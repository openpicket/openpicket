// Package enforcer applies the decisions the manager distributes to the
// node's nftables ban sets (docs/ARCHITECTURE.md §4.3, §4.4).
//
// The enforcer makes the final local checks: values in the allowlist or the
// node's own networks are refused, so are absurdly wide ranges, and the
// number of elements is capped. Each decision is kept with an absolute
// deadline: element timeouts are always the remaining time, so applying
// the same snapshot again, re-creating the table or restoring after a
// reboot never extends a block.
package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/openpicket/openpicket/agent/dataplane"
	"github.com/openpicket/openpicket/agent/nft"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/direction"
)

// Minimum prefix lengths accepted for ranges: a manager sending 0.0.0.0/1
// must not take the node off the internet.
const (
	MinBits4 = 8
	MinBits6 = 16
)

// tolerance below which an element's remaining time is not rewritten.
const tolerance = 30 * time.Second

// untrustedRestoreCap bounds restored blocks when the clock cannot be
// trusted (router without RTC before NTP).
const untrustedRestoreCap = time.Hour

// Entry is one applied decision.
type Entry struct {
	Value    string    `json:"v"`
	Range    bool      `json:"r,omitempty"`
	Both     bool      `json:"b,omitempty"`
	Deadline time.Time `json:"d"`
	Origin   string    `json:"o,omitempty"`
	Scenario string    `json:"s,omitempty"`
}

func (e Entry) set() string {
	return nft.SetName(e.Both, !isV4(e.Value), e.Range)
}

func isV4(v string) bool {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Addr().Is4()
	}
	a, err := netip.ParseAddr(v)
	return err == nil && a.Is4()
}

// Config configures an Enforcer.
type Config struct {
	Host  *nft.Host
	Table nft.BanConfig
	// Allow returns the allowlist (configured networks and the controller
	// addresses); it is re-read on every Ensure.
	Allow func() []netip.Prefix
	// Nets returns the node's inside networks: decisions on them are
	// refused.
	Nets        func() *direction.Nets
	MaxElements int
	// StateFile persists the applied decisions for restore after a reboot.
	StateFile string
	Logger    *slog.Logger
	Now       func() time.Time
}

// Enforcer implements dataplane.DecisionSink.
type Enforcer struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	version  uint64
	entries  map[string]Entry
	rejected uint64
	lastErr  string
	allow    []netip.Prefix
	dirty    bool
	present  bool
}

var _ dataplane.DecisionSink = (*Enforcer)(nil)

// New creates an enforcer; call Restore, then Run.
func New(cfg Config) *Enforcer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Allow == nil {
		cfg.Allow = func() []netip.Prefix { return nil }
	}
	if cfg.Nets == nil {
		cfg.Nets = func() *direction.Nets { return nil }
	}
	if cfg.MaxElements <= 0 {
		cfg.MaxElements = 100000
	}
	return &Enforcer{cfg: cfg, log: cfg.Logger.With("component", "enforcer"), entries: map[string]Entry{}}
}

// Version implements dataplane.DecisionSink.
func (e *Enforcer) Version() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.version
}

// Status returns the enforcer state for status reports.
func (e *Enforcer) Status() *dataplanev1.EnforcerStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := &dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: e.version, Rejected: e.rejected, LastError: e.lastErr}
	now := e.cfg.Now()
	for _, en := range e.entries {
		if !en.Deadline.After(now) {
			continue
		}
		switch v4 := isV4(en.Value); {
		case en.Both && v4:
			st.BanBothV4++
		case en.Both:
			st.BanBothV6++
		case v4:
			st.BanInV4++
		default:
			st.BanInV6++
		}
	}
	return st
}

var originRank = map[string]int{"cscli": 0, "manual": 0, "misp": 1, "crowdsec": 2, "ai": 3}

func rank(origin string) int {
	if r, ok := originRank[origin]; ok {
		return r
	}
	return 2
}

// accept validates one decision against local policy.
func (e *Enforcer) accept(d *dataplanev1.Decision, now time.Time, nets *direction.Nets, allow []netip.Prefix) (Entry, error) {
	var p netip.Prefix
	isRange := d.Scope == dataplanev1.Scope_SCOPE_RANGE
	if isRange {
		pp, err := netip.ParsePrefix(d.Value)
		if err != nil {
			return Entry{}, fmt.Errorf("invalid range %q", d.Value)
		}
		p = pp.Masked()
		if (p.Addr().Is4() && p.Bits() < MinBits4) || (p.Addr().Is6() && p.Bits() < MinBits6) {
			return Entry{}, fmt.Errorf("range %s is too wide", p)
		}
	} else {
		a, err := netip.ParseAddr(d.Value)
		if err != nil {
			return Entry{}, fmt.Errorf("invalid address %q", d.Value)
		}
		a = a.Unmap()
		p = netip.PrefixFrom(a, a.BitLen())
	}
	for _, al := range allow {
		if al.Overlaps(p) {
			return Entry{}, fmt.Errorf("%s overlaps the allowlist (%s)", p, al)
		}
	}
	for _, ln := range nets.Prefixes() {
		if ln.Overlaps(p) {
			return Entry{}, fmt.Errorf("%s overlaps a local network (%s)", p, ln)
		}
	}
	if d.TtlMs <= 0 {
		return Entry{}, errors.New("expired")
	}
	v := p.Addr().String()
	if isRange {
		v = p.String()
	}
	return Entry{Value: v, Range: isRange, Both: d.Direction == dataplanev1.Direction_DIRECTION_BOTH,
		Deadline: now.Add(time.Duration(d.TtlMs) * time.Millisecond), Origin: d.Origin, Scenario: d.Scenario}, nil
}

// ApplySnapshot implements dataplane.DecisionSink.
func (e *Enforcer) ApplySnapshot(ctx context.Context, s *dataplanev1.DecisionSnapshot) (uint32, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Now()
	want := map[string]Entry{}
	e.merge(want, s.Decisions, now)
	if err := e.sync(ctx, want, now); err != nil {
		return uint32(len(e.entries)), err
	}
	e.version, e.dirty = s.Version, true
	return uint32(len(e.entries)), nil
}

// ApplyDelta implements dataplane.DecisionSink.
func (e *Enforcer) ApplyDelta(ctx context.Context, d *dataplanev1.DecisionDelta) (uint32, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if d.FromVersion != e.version {
		return uint32(len(e.entries)), dataplane.ErrVersionMismatch
	}
	now := e.cfg.Now()
	want := make(map[string]Entry, len(e.entries))
	for k, v := range e.entries {
		want[k] = v
	}
	for _, v := range d.Deletes {
		delete(want, canonical(v))
	}
	e.merge(want, d.Upserts, now)
	if err := e.sync(ctx, want, now); err != nil {
		return uint32(len(e.entries)), err
	}
	e.version, e.dirty = d.ToVersion, true
	return uint32(len(e.entries)), nil
}

func canonical(v string) string {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.Unmap().String()
	}
	return v
}

// merge validates decisions into want. Callers hold mu.
func (e *Enforcer) merge(want map[string]Entry, ds []*dataplanev1.Decision, now time.Time) {
	nets, allow := e.cfg.Nets(), e.allow
	for _, d := range ds {
		en, err := e.accept(d, now, nets, allow)
		if err != nil {
			e.rejected++
			e.log.Debug("decision refused", "value", d.Value, "err", err)
			delete(want, canonical(d.Value))
			continue
		}
		want[en.Value] = en
	}
	dropContainedRanges(want)
	if len(want) > e.cfg.MaxElements {
		e.cap(want)
	}
}

// dropContainedRanges removes ranges inside another range of the same set
// (interval sets reject overlapping elements).
func dropContainedRanges(want map[string]Entry) {
	var ranges []Entry
	for _, en := range want {
		if en.Range {
			ranges = append(ranges, en)
		}
	}
	if len(ranges) < 2 {
		return
	}
	sort.Slice(ranges, func(i, j int) bool {
		pi, pj := netip.MustParsePrefix(ranges[i].Value), netip.MustParsePrefix(ranges[j].Value)
		return pi.Bits() < pj.Bits()
	})
	for i, outer := range ranges {
		po := netip.MustParsePrefix(outer.Value)
		for _, inner := range ranges[i+1:] {
			pi := netip.MustParsePrefix(inner.Value)
			if inner.set() == outer.set() && po.Overlaps(pi) && pi.Bits() >= po.Bits() {
				delete(want, inner.Value)
			}
		}
	}
}

// cap keeps MaxElements entries: manual first, then MISP, CrowdSec, AI,
// longest deadline first.
func (e *Enforcer) cap(want map[string]Entry) {
	list := make([]Entry, 0, len(want))
	for _, en := range want {
		list = append(list, en)
	}
	sort.Slice(list, func(i, j int) bool {
		if ri, rj := rank(list[i].Origin), rank(list[j].Origin); ri != rj {
			return ri < rj
		}
		return list[i].Deadline.After(list[j].Deadline)
	})
	for _, en := range list[e.cfg.MaxElements:] {
		delete(want, en.Value)
		e.rejected++
	}
	e.log.Warn("decision set capped", "max_elements", e.cfg.MaxElements, "dropped", len(list)-e.cfg.MaxElements)
}

// sync makes the kernel sets match want. On failure (an element expired
// on its own, the table vanished) it reads the sets back and retries once.
// Callers hold mu.
func (e *Enforcer) sync(ctx context.Context, want map[string]Entry, now time.Time) error {
	if !e.present {
		if err := e.recreate(ctx, want, now); err != nil {
			e.lastErr = err.Error()
			return err
		}
		e.entries, e.lastErr = want, ""
		return nil
	}
	script := diffScript(e.entries, want, now)
	err := e.apply(ctx, script)
	if err != nil {
		e.log.Warn("ban sets out of sync; reading them back", "err", err)
		actual, lerr := e.listed(ctx, now)
		if lerr != nil {
			// The table itself is gone or unreadable: rebuild it.
			err = e.recreate(ctx, want, now)
		} else {
			err = e.apply(ctx, diffScript(actual, want, now))
		}
	}
	if err != nil {
		e.lastErr = err.Error()
		return err
	}
	e.entries, e.lastErr = want, ""
	return nil
}

func (e *Enforcer) apply(ctx context.Context, script string) error {
	if script == "" {
		return nil
	}
	return e.cfg.Host.Apply(ctx, script)
}

// diffScript turns have into want: removed values are deleted, new ones
// added, and values whose set or remaining time changed are replaced.
func diffScript(have, want map[string]Entry, now time.Time) string {
	var dels, adds []nft.Element
	for v, h := range have {
		w, ok := want[v]
		if !ok || w.set() != h.set() || absDur(w.Deadline.Sub(h.Deadline)) > tolerance {
			if h.Deadline.After(now) {
				dels = append(dels, nft.Element{Set: h.set(), Value: v})
			}
		}
	}
	for v, w := range want {
		h, ok := have[v]
		if ok && w.set() == h.set() && absDur(w.Deadline.Sub(h.Deadline)) <= tolerance && h.Deadline.After(now) {
			continue
		}
		if rem := w.Deadline.Sub(now); rem > 0 {
			adds = append(adds, nft.Element{Set: w.set(), Value: v, Timeout: rem})
		}
	}
	return nft.ElementsScript(dels, adds)
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// listed reads the kernel sets back as entries (deadline = now + expires).
func (e *Enforcer) listed(ctx context.Context, now time.Time) (map[string]Entry, error) {
	out := map[string]Entry{}
	for _, set := range nft.BanSets() {
		els, err := e.cfg.Host.ListElements(ctx, set)
		if err != nil {
			return nil, err
		}
		both, isRange := set[:2] == "bo", set[len(set)-1] == 'r'
		for v, exp := range els {
			out[canonical(v)] = Entry{Value: canonical(v), Range: isRange, Both: both, Deadline: now.Add(exp)}
		}
	}
	return out, nil
}

// recreate builds the table from scratch with want's remaining times.
// Callers hold mu.
func (e *Enforcer) recreate(ctx context.Context, want map[string]Entry, now time.Time) error {
	e.allow = e.cfg.Allow()
	script := e.cfg.Table.Script(e.allow) + diffScript(nil, want, now)
	if err := e.cfg.Host.Apply(ctx, script); err != nil {
		e.present = false
		return err
	}
	e.present = true
	return nil
}

// Ensure checks that the table exists (fw4 or a user may have flushed the
// ruleset) and that the allowlist is current; it rebuilds as needed.
func (e *Enforcer) Ensure(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Now()
	for v, en := range e.entries {
		if !en.Deadline.After(now) {
			delete(e.entries, v)
		}
	}
	if !e.present || !e.cfg.Host.BanTablePresent(ctx) {
		if e.present {
			e.log.Warn("ban table disappeared; recreating it")
		}
		if err := e.recreate(ctx, e.entries, now); err != nil {
			e.lastErr = err.Error()
			return err
		}
		return nil
	}
	if allow := e.cfg.Allow(); !slices.Equal(allow, e.allow) {
		if err := e.cfg.Host.Apply(ctx, nft.AllowScript(allow)); err != nil {
			return err
		}
		e.allow = allow
		// Values now in the allowlist must not stay blocked.
		want := map[string]Entry{}
		for v, en := range e.entries {
			want[v] = en
		}
		for v, en := range want {
			p := prefixOf(en)
			for _, al := range allow {
				if al.Overlaps(p) {
					delete(want, v)
				}
			}
		}
		return e.sync(ctx, want, now)
	}
	return nil
}

func prefixOf(en Entry) netip.Prefix {
	if en.Range {
		return netip.MustParsePrefix(en.Value)
	}
	a := netip.MustParseAddr(en.Value)
	return netip.PrefixFrom(a, a.BitLen())
}

type stateFile struct {
	Version uint64    `json:"version"`
	SavedAt time.Time `json:"saved_at"`
	Entries []Entry   `json:"entries"`
}

// Save writes the applied decisions if they changed.
func (e *Enforcer) Save() error {
	e.mu.Lock()
	if !e.dirty || e.cfg.StateFile == "" {
		e.mu.Unlock()
		return nil
	}
	st := stateFile{Version: e.version, SavedAt: e.cfg.Now()}
	for _, en := range e.entries {
		st.Entries = append(st.Entries, en)
	}
	e.dirty = false
	e.mu.Unlock()
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.cfg.StateFile), 0o750); err != nil {
		return err
	}
	tmp := e.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.cfg.StateFile)
}

// Restore re-applies the saved decisions before the manager is reachable.
// With a trustworthy clock the saved deadlines are used; otherwise (the
// clock is behind the save time or far ahead) each block gets at most the
// remaining time it had when saved, capped at one hour, and the version is
// dropped so the manager sends a snapshot.
func (e *Enforcer) Restore(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Now()
	want := map[string]Entry{}
	var version uint64
	if b, err := os.ReadFile(e.cfg.StateFile); err == nil {
		var st stateFile
		if err := json.Unmarshal(b, &st); err != nil {
			e.log.Warn("ignoring unreadable decision state", "err", err)
		} else {
			trusted := !now.Before(st.SavedAt) && now.Sub(st.SavedAt) < 30*24*time.Hour
			for _, en := range st.Entries {
				if !trusted {
					rem := min(en.Deadline.Sub(st.SavedAt), untrustedRestoreCap)
					en.Deadline = now.Add(rem)
				}
				if en.Deadline.After(now) {
					want[en.Value] = en
				}
			}
			if trusted {
				version = st.Version
			} else {
				e.log.Warn("clock not trusted: restored blocks are capped", "saved_at", st.SavedAt, "now", now, "cap", untrustedRestoreCap)
			}
		}
	}
	if err := e.recreate(ctx, want, now); err != nil {
		e.lastErr = err.Error()
		return err
	}
	e.entries, e.version = want, version
	e.log.Info("ban table ready", "restored", len(want), "version", version)
	return nil
}

// Run keeps the table in place and saves the state until ctx ends.
func (e *Enforcer) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := e.Save(); err != nil {
				e.log.Warn("save decision state", "err", err)
			}
			return
		case <-t.C:
		}
		if err := e.Ensure(ctx); err != nil && ctx.Err() == nil {
			e.log.Warn("ensure ban table", "err", err)
		}
		if err := e.Save(); err != nil {
			e.log.Warn("save decision state", "err", err)
		}
	}
}

// Remove deletes the ban table (agent uninstall).
func (e *Enforcer) Remove(ctx context.Context) error {
	return e.cfg.Host.Apply(ctx, fmt.Sprintf("table inet %[1]s\ndelete table inet %[1]s\n", nft.BanTable))
}
