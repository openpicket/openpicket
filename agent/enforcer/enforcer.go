// Package enforcer applies the decisions the manager distributes to the
// node's nftables ban sets (docs/ARCHITECTURE.md §4.3, §4.4).
//
// The enforcer keeps two views. The decisions are what the manager sent:
// every well-formed decision with an absolute deadline, persisted for
// restore after a reboot. The applied elements are computed from them
// every time something changes (decisions, allowlist, local networks,
// restore, periodic check): values in the allowlist or the node's own
// networks are left out, the number of decisions is capped, and nested
// ranges are decomposed into disjoint prefixes (Decompose). Local checks
// never delete a decision, so a value that stops being local, or a range
// whose outer range expires, is blocked again.
//
// Element timeouts are always the remaining time of a deadline, so
// applying the same snapshot again, re-creating the table or restoring
// after a reboot never extends a block.
package enforcer

import (
	"cmp"
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
	"strings"
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

// maxRefusedReported bounds the refused decisions in status reports.
const maxRefusedReported = 100

const reasonLimit = "over the element limit"

// Entry is one decision, or one applied element.
type Entry struct {
	Value    string    `json:"v"`
	Range    bool      `json:"r,omitempty"`
	Both     bool      `json:"b,omitempty"`
	Deadline time.Time `json:"d"`
	Origin   string    `json:"o,omitempty"`
	Scenario string    `json:"s,omitempty"`

	// Cached by withCache (large sets are recomputed often).
	pfx  netip.Prefix
	setN string
}

func (e Entry) set() string {
	if e.setN != "" {
		return e.setN
	}
	return nft.SetName(e.Both, !isV4(e.Value), e.Range)
}

func (e Entry) prefix() netip.Prefix {
	if e.pfx.IsValid() {
		return e.pfx
	}
	if e.Range {
		return netip.MustParsePrefix(e.Value)
	}
	a := netip.MustParseAddr(e.Value)
	return netip.PrefixFrom(a, a.BitLen())
}

// withCache fills the cached prefix and set name.
func withCache(e Entry) Entry {
	e.pfx, e.setN = e.prefix(), e.set()
	return e
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
	// Nets returns the node's inside networks: decisions on them are not
	// applied.
	Nets func() *direction.Nets
	// MaxElements caps the decisions applied.
	MaxElements int
	// StateFile persists the decisions for restore after a reboot.
	StateFile string
	Logger    *slog.Logger
	Now       func() time.Time
}

// Enforcer implements dataplane.DecisionSink.
type Enforcer struct {
	cfg Config
	log *slog.Logger

	mu      sync.Mutex
	version uint64
	// decisions as sent by the manager (valid ones), keyed by value.
	decisions map[string]Entry
	// invalid decisions of the current version, value -> reason.
	invalid map[string]string
	// refused decisions (local policy, cap), value -> reason; recomputed.
	refused map[string]string
	// applied are the kernel elements, keyed by elemKey (set, value).
	applied map[string]Entry
	// capped is set when the last full computation hit MaxElements: deltas
	// then take the full path.
	capped  bool
	lastErr string
	allow   []netip.Prefix
	// local networks of the last full computation.
	local []netip.Prefix
	// wan is the content of the table's wan set.
	wan     []string
	dirty   bool
	present bool
	// stale: the last change failed to apply, so applied may not match
	// the decisions; the next change or check recomputes everything.
	stale bool
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
	return &Enforcer{cfg: cfg, log: cfg.Logger.With("component", "enforcer"),
		decisions: map[string]Entry{}, invalid: map[string]string{}, refused: map[string]string{}, applied: map[string]Entry{}}
}

// Version implements dataplane.DecisionSink.
func (e *Enforcer) Version() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.version
}

// Status returns the enforcer state for status reports: active decisions
// applied per set kind, and the ones not applied with the reason.
func (e *Enforcer) Status() *dataplanev1.EnforcerStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := &dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: e.version, LastError: e.lastErr,
		Rejected: uint64(len(e.refused) + len(e.invalid))}
	now := e.cfg.Now()
	for v, en := range e.decisions {
		if !en.Deadline.After(now) || e.refused[v] != "" {
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
	refused := make([]*dataplanev1.RefusedDecision, 0, len(e.refused)+len(e.invalid))
	for v, r := range e.refused {
		refused = append(refused, &dataplanev1.RefusedDecision{Value: v, Reason: r})
	}
	for v, r := range e.invalid {
		refused = append(refused, &dataplanev1.RefusedDecision{Value: v, Reason: r})
	}
	// The local reasons first: they are few and explain why a ban the
	// manager sent is not in force here; the element limit can refuse
	// thousands.
	slices.SortFunc(refused, func(a, b *dataplanev1.RefusedDecision) int {
		if c := cmp.Compare(refusalRank(a.Reason), refusalRank(b.Reason)); c != 0 {
			return c
		}
		return strings.Compare(a.Value, b.Value)
	})
	st.Refused = refused[:min(len(refused), maxRefusedReported)]
	return st
}

func refusalRank(reason string) int {
	switch {
	case strings.HasPrefix(reason, reasonLimit):
		return 2
	case strings.HasPrefix(reason, "overlaps "):
		return 0
	default:
		return 1
	}
}

var originRank = map[string]int{"cscli": 0, "manual": 0, "misp": 1, "crowdsec": 2, "ai": 3}

func rank(origin string) int {
	if r, ok := originRank[origin]; ok {
		return r
	}
	return 2
}

// parse validates the form of a decision (not the local policy, which
// changes over time).
func parse(d *dataplanev1.Decision, now time.Time) (Entry, error) {
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
	if d.TtlMs <= 0 {
		return Entry{}, errors.New("expired")
	}
	v := p.Addr().String()
	if isRange {
		v = p.String()
	}
	return withCache(Entry{Value: v, Range: isRange, Both: d.Direction == dataplanev1.Direction_DIRECTION_BOTH,
		Deadline: now.Add(time.Duration(d.TtlMs) * time.Millisecond), Origin: d.Origin, Scenario: d.Scenario}), nil
}

// localReason reports why a decision must not be applied on this node.
func localReason(p netip.Prefix, allow, local []netip.Prefix) string {
	for _, al := range allow {
		if al.Overlaps(p) {
			return fmt.Sprintf("overlaps the allowlist (%s)", al)
		}
	}
	for _, ln := range local {
		if ln.Overlaps(p) {
			return fmt.Sprintf("overlaps a local network (%s)", ln)
		}
	}
	return ""
}

// ApplySnapshot implements dataplane.DecisionSink.
func (e *Enforcer) ApplySnapshot(ctx context.Context, s *dataplanev1.DecisionSnapshot) (uint32, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Now()
	decisions, invalid := map[string]Entry{}, map[string]string{}
	e.merge(decisions, invalid, s.Decisions, now)
	if err := e.update(ctx, decisions, invalid, now); err != nil {
		return uint32(len(e.applied)), err
	}
	e.version = s.Version
	return uint32(len(e.applied)), nil
}

// ApplyDelta implements dataplane.DecisionSink.
func (e *Enforcer) ApplyDelta(ctx context.Context, d *dataplanev1.DecisionDelta) (uint32, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if d.FromVersion != e.version {
		return uint32(len(e.applied)), dataplane.ErrVersionMismatch
	}
	now := e.cfg.Now()
	// The decisions change in place: if nft fails the version stays and
	// the manager sends the delta again (applying it twice is harmless).
	touched := map[string]bool{}
	for _, v := range d.Deletes {
		c := canonical(v)
		delete(e.decisions, c)
		delete(e.invalid, v)
		touched[c] = true
	}
	for _, dd := range d.Upserts {
		touched[canonical(dd.Value)] = true
	}
	e.merge(e.decisions, e.invalid, d.Upserts, now)
	e.dirty = true
	if err := e.syncTouched(ctx, touched, now); err != nil {
		return uint32(len(e.applied)), err
	}
	e.version = d.ToVersion
	return uint32(len(e.applied)), nil
}

// syncTouched applies a change of a few values without recomputing
// everything: addresses one by one, ranges by recomputing only the sets
// they belong to. Callers hold mu.
func (e *Enforcer) syncTouched(ctx context.Context, touched map[string]bool, now time.Time) error {
	if e.stale || e.capped || len(e.decisions) > e.cfg.MaxElements {
		return e.syncPlan(ctx, e.compute(e.decisions, now), now)
	}
	local := e.cfg.Nets().Prefixes()
	have, want := map[string]Entry{}, map[string]Entry{}
	rangeSets := map[string]bool{}
	for v := range touched {
		delete(e.refused, v)
		if p, err := netip.ParsePrefix(v); err == nil {
			// A range (deleted, changed or new): its family's range sets.
			v6 := p.Addr().Is6()
			rangeSets[nft.SetName(false, v6, true)], rangeSets[nft.SetName(true, v6, true)] = true, true
			continue
		}
		// The address may move between its inbound and two-way sets.
		v6 := !isV4(v)
		for _, set := range []string{nft.SetName(false, v6, false), nft.SetName(true, v6, false)} {
			if old, ok := e.applied[elemKey(set, v)]; ok {
				have[elemKey(set, v)] = old
			}
		}
		en, ok := e.decisions[v]
		if !ok || !en.Deadline.After(now) {
			continue
		}
		if r := localReason(en.prefix(), e.allow, local); r != "" {
			e.refused[v] = r
			continue
		}
		want[en.key()] = en
	}
	if len(rangeSets) > 0 {
		for k, el := range e.applied {
			if el.Range && rangeSets[el.set()] {
				have[k] = el
			}
		}
		bySet := map[string][]Entry{}
		for v, en := range e.decisions {
			if !en.Range || !rangeSets[en.set()] {
				continue
			}
			delete(e.refused, v)
			if !en.Deadline.After(now) {
				continue
			}
			if r := localReason(en.prefix(), e.allow, local); r != "" {
				e.refused[v] = r
				continue
			}
			bySet[en.set()] = append(bySet[en.set()], en)
		}
		for _, rs := range bySet {
			addPieces(want, rs)
		}
	}
	if err := e.apply(ctx, diffScript(have, want, now)); err != nil {
		// Out of sync: the full path reads the sets back.
		e.log.Warn("incremental ban update failed; resyncing", "err", err)
		return e.syncPlan(ctx, e.compute(e.decisions, now), now)
	}
	for k := range have {
		delete(e.applied, k)
	}
	for k, v := range want {
		e.applied[k] = v
	}
	e.lastErr = ""
	return nil
}

// addPieces adds the decomposed ranges of one set to want.
func addPieces(want map[string]Entry, rs []Entry) {
	for _, p := range Decompose(rs) {
		src := rs[p.From]
		v := p.Prefix.String()
		want[elemKey(src.set(), v)] = Entry{Value: v, Range: true, Both: src.Both, Deadline: p.Deadline, Origin: src.Origin, Scenario: src.Scenario,
			pfx: p.Prefix, setN: src.set()}
	}
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

// merge validates decisions into decisions/invalid. Callers hold mu.
func (e *Enforcer) merge(decisions map[string]Entry, invalid map[string]string, ds []*dataplanev1.Decision, now time.Time) {
	for _, d := range ds {
		en, err := parse(d, now)
		if err != nil {
			e.log.Debug("invalid decision", "value", d.Value, "err", err)
			delete(decisions, canonical(d.Value))
			invalid[d.Value] = err.Error()
			continue
		}
		delete(invalid, d.Value)
		decisions[en.Value] = en
	}
}

// update replaces the decisions and applies them. Callers hold mu.
func (e *Enforcer) update(ctx context.Context, decisions map[string]Entry, invalid map[string]string, now time.Time) error {
	if err := e.syncPlan(ctx, e.compute(decisions, now), now); err != nil {
		return err
	}
	e.decisions, e.invalid, e.dirty = decisions, invalid, true
	return nil
}

// plan is a full computation of the kernel elements.
type plan struct {
	// want is keyed by elemKey: the same prefix can be in several sets
	// (an inbound range and a two-way one decompose into equal pieces).
	want    map[string]Entry
	refused map[string]string
	capped  bool
	// local is the local networks it was computed with.
	local []netip.Prefix
}

// elemKey identifies a kernel element: its set and value.
func elemKey(set, value string) string { return set + " " + value }

func (e Entry) key() string { return elemKey(e.set(), e.Value) }

// syncPlan applies a full computation. What Ensure compares against (local
// networks, refusals, cap) changes only once the kernel has it: after a
// failure the next check computes again. Callers hold mu.
func (e *Enforcer) syncPlan(ctx context.Context, p plan, now time.Time) error {
	if err := e.sync(ctx, p.want, now); err != nil {
		e.stale = true
		return err
	}
	e.refused, e.capped, e.local, e.stale = p.refused, p.capped, p.local, false
	return nil
}

// compute derives the kernel elements from the decisions with the current
// allowlist and local networks. Callers hold mu.
func (e *Enforcer) compute(decisions map[string]Entry, now time.Time) plan {
	local := e.cfg.Nets().Prefixes()
	refused := map[string]string{}
	keep := make([]Entry, 0, len(decisions))
	for v, en := range decisions {
		if !en.Deadline.After(now) {
			continue
		}
		if r := localReason(en.prefix(), e.allow, local); r != "" {
			refused[v] = r
			continue
		}
		keep = append(keep, en)
	}
	capped := len(keep) > e.cfg.MaxElements
	if capped {
		// Manual first, then MISP, CrowdSec, AI; longest deadline first.
		sort.Slice(keep, func(i, j int) bool {
			if ri, rj := rank(keep[i].Origin), rank(keep[j].Origin); ri != rj {
				return ri < rj
			}
			if !keep[i].Deadline.Equal(keep[j].Deadline) {
				return keep[i].Deadline.After(keep[j].Deadline)
			}
			return keep[i].Value < keep[j].Value
		})
		for _, en := range keep[e.cfg.MaxElements:] {
			refused[en.Value] = fmt.Sprintf("%s (%d)", reasonLimit, e.cfg.MaxElements)
		}
		e.log.Warn("decisions capped", "max_elements", e.cfg.MaxElements, "dropped", len(keep)-e.cfg.MaxElements)
		keep = keep[:e.cfg.MaxElements]
	}
	want := make(map[string]Entry, len(keep))
	ranges := map[string][]Entry{}
	for _, en := range keep {
		if en.Range {
			ranges[en.set()] = append(ranges[en.set()], en)
			continue
		}
		want[en.key()] = en
	}
	// Interval sets reject overlapping elements: nested ranges become
	// disjoint pieces with the latest deadline covering them.
	for _, rs := range ranges {
		addPieces(want, rs)
	}
	return plan{want: want, refused: refused, capped: capped, local: local}
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
		e.applied, e.lastErr = want, ""
		return nil
	}
	script := diffScript(e.applied, want, now)
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
	e.applied, e.lastErr = want, ""
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
	for k, h := range have {
		w, ok := want[k]
		if !ok || absDur(w.Deadline.Sub(h.Deadline)) > tolerance {
			if h.Deadline.After(now) {
				dels = append(dels, nft.Element{Set: h.set(), Value: h.Value})
			}
		}
	}
	for k, w := range want {
		h, ok := have[k]
		if ok && absDur(w.Deadline.Sub(h.Deadline)) <= tolerance && h.Deadline.After(now) {
			continue
		}
		if rem := w.Deadline.Sub(now); rem > 0 {
			adds = append(adds, nft.Element{Set: w.set(), Value: w.Value, Timeout: rem})
		}
	}
	// Deletions first in the transaction: a split range is removed before
	// its pieces are added.
	return nft.ElementsScript(dels, adds)
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// listed reads the kernel sets back as elements (deadline = now +
// expires).
func (e *Enforcer) listed(ctx context.Context, now time.Time) (map[string]Entry, error) {
	out := map[string]Entry{}
	for _, set := range nft.BanSets() {
		els, err := e.cfg.Host.ListElements(ctx, set)
		if err != nil {
			return nil, err
		}
		both, isRange := set[:2] == "bo", set[len(set)-1] == 'r'
		for v, exp := range els {
			v = canonical(v)
			if isRange {
				// nft prints a single-address interval without its length.
				if a, err := netip.ParseAddr(v); err == nil {
					v = netip.PrefixFrom(a, a.BitLen()).String()
				}
			}
			out[elemKey(set, v)] = withCache(Entry{Value: v, Range: isRange, Both: both, Deadline: now.Add(exp)})
		}
	}
	return out, nil
}

// recreate builds the table from scratch with want's remaining times.
// Callers hold mu.
func (e *Enforcer) recreate(ctx context.Context, want map[string]Entry, now time.Time) error {
	// Read first: a change while rendering is caught by the next Ensure.
	e.wan = e.cfg.Table.WAN.Get()
	script := e.cfg.Table.Script(e.allow) + diffScript(nil, want, now)
	if err := e.cfg.Host.Apply(ctx, script); err != nil {
		e.present = false
		return err
	}
	e.present = true
	return nil
}

// Ensure checks that the table exists (fw4 or a user may have flushed the
// ruleset), follows WAN changes and, when the allowlist or the local
// networks changed, applies
// the decisions again: a value that became local is unblocked, one that
// is no longer local is blocked again. Call it when the local networks
// change; it also runs every minute. Expiry needs no recomputation: every
// element (pieces of split ranges included) carries its own timeout.
func (e *Enforcer) Ensure(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Now()
	for v, en := range e.decisions {
		if !en.Deadline.After(now) {
			delete(e.decisions, v)
			delete(e.refused, v)
			e.dirty = true
		}
	}
	for v, en := range e.applied {
		if !en.Deadline.After(now) {
			delete(e.applied, v)
		}
	}
	allow := e.cfg.Allow()
	present := e.present && e.cfg.Host.BanTablePresent(ctx)
	if wan := e.cfg.Table.WAN.Get(); present && !slices.Equal(wan, e.wan) {
		// The WAN changed (fw4 zone devices): only the wan set changes,
		// the bans and their timeouts stay.
		if err := e.cfg.Host.Apply(ctx, nft.WANScript(wan)); err != nil {
			e.lastErr = err.Error()
			return err
		}
		e.wan = wan
	}
	// Capped: expired decisions free room for others.
	if present && !e.capped && !e.stale && slices.Equal(allow, e.allow) && slices.Equal(e.cfg.Nets().Prefixes(), e.local) {
		return nil
	}
	if !present {
		if e.present {
			e.log.Warn("ban table disappeared; recreating it")
		}
		e.present, e.allow = false, allow
	} else if !slices.Equal(allow, e.allow) {
		if err := e.cfg.Host.Apply(ctx, nft.AllowScript(allow)); err != nil {
			e.lastErr = err.Error()
			return err
		}
		e.allow = allow
	}
	return e.syncPlan(ctx, e.compute(e.decisions, now), now)
}

type stateFile struct {
	Version uint64    `json:"version"`
	SavedAt time.Time `json:"saved_at"`
	Entries []Entry   `json:"entries"`
}

// Save writes the decisions if they changed.
func (e *Enforcer) Save() error {
	e.mu.Lock()
	if !e.dirty || e.cfg.StateFile == "" {
		e.mu.Unlock()
		return nil
	}
	st := stateFile{Version: e.version, SavedAt: e.cfg.Now()}
	for _, en := range e.decisions {
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

// Restore re-applies the saved decisions before the manager is reachable,
// through the same local checks as live decisions (the local networks
// known at boot; Ensure re-checks when they change). With a trustworthy
// clock the saved deadlines are used; otherwise (the clock is behind the
// save time or far ahead) each block gets at most the remaining time it
// had when saved, capped at one hour, and the version is dropped so the
// manager sends a snapshot.
func (e *Enforcer) Restore(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Now()
	decisions := map[string]Entry{}
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
				if !en.Deadline.After(now) {
					continue
				}
				// Saved state is re-validated like a decision from the
				// manager.
				if _, err := netip.ParsePrefix(en.Value); en.Range && err != nil {
					continue
				}
				if _, err := netip.ParseAddr(en.Value); !en.Range && err != nil {
					continue
				}
				decisions[en.Value] = withCache(en)
			}
			if trusted {
				version = st.Version
			} else {
				e.log.Warn("clock not trusted: restored blocks are capped", "saved_at", st.SavedAt, "now", now, "cap", untrustedRestoreCap)
			}
		}
	}
	// Kept even if nft fails now: Ensure retries.
	e.decisions, e.version = decisions, version
	e.allow, e.present = e.cfg.Allow(), false
	p := e.compute(decisions, now)
	if err := e.syncPlan(ctx, p, now); err != nil {
		return err
	}
	e.log.Info("ban table ready", "restored", len(decisions), "applied", len(p.want), "refused", len(p.refused), "version", version)
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
