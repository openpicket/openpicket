package misp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/manager/lapi"
)

// Scenarios of the MISP decisions: ip-src blocks inbound, ip-dst both ways
// (the relay's both-way rules match the -ip-dst suffix).
const (
	ScenarioSrc = "openpicket/misp-ip-src"
	ScenarioDst = "openpicket/misp-ip-dst"
	// Origin of the decisions (the agents rank it after manual ones).
	Origin = "misp"
)

// Config configures the service.
type Config struct {
	DB     *pgxpool.Pool
	Client *Client
	// LAPI receives the decisions (the primary LAPI).
	LAPI *lapi.Watcher
	// Interval between syncs (default 5m).
	Interval time.Duration
	// Renew: decisions last twice this and are renewed when less than this
	// remains (default 6h). A revoked attribute loses its decision at the
	// next sync; an unreachable MISP lets decisions run out within 2×Renew.
	Renew time.Duration
	// DefaultTTL of approvals without an openpicket:ttl tag (default 30d).
	DefaultTTL string
	// ProposeMinAlerts proposes sources with at least this many alerts in
	// ProposeWindow (0 disables automatic proposals).
	ProposeMinAlerts int
	ProposeWindow    time.Duration
	Logger           *slog.Logger
	Now              func() time.Time
}

// Service syncs MISP and changes approval states.
type Service struct {
	cfg  Config
	log  *slog.Logger
	poke chan struct{}

	mu     sync.Mutex
	events map[string]string // event info -> id
}

// New creates the service.
func New(cfg Config) *Service {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.Renew <= 0 {
		cfg.Renew = 6 * time.Hour
	}
	if cfg.DefaultTTL == "" {
		cfg.DefaultTTL = "30d"
	}
	if cfg.ProposeWindow <= 0 {
		cfg.ProposeWindow = 7 * 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{cfg: cfg, log: cfg.Logger.With("component", "misp"), poke: make(chan struct{}, 1), events: map[string]string{}}
}

// Client returns the MISP client.
func (s *Service) Client() *Client { return s.cfg.Client }

// Poke asks for a sync now.
func (s *Service) Poke() {
	select {
	case s.poke <- struct{}{}:
	default:
	}
}

// Fencer runs fn while leader.
type Fencer interface {
	Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error
}

// Run syncs while leader.
func (s *Service) Run(ctx context.Context, l Fencer) {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		if err := s.Sync(ctx, l); err != nil && ctx.Err() == nil {
			s.log.Warn("misp sync", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.poke:
		}
	}
}

// ParseTTL parses "30d", "12h", "2w".
func ParseTTL(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if n, err := strconv.Atoi(v[:len(v)-1]); err == nil && n > 0 {
			switch v[len(v)-1] {
			case 'd':
				return time.Duration(n) * 24 * time.Hour, nil
			case 'w':
				return time.Duration(n) * 7 * 24 * time.Hour, nil
			}
		}
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid ttl %q (e.g. 7d, 30d, 12h)", v)
	}
	return d, nil
}

// target returns the decision scope, value and scenario of an attribute.
func target(typ, value string) (scope, v, scenario string, ok bool) {
	addr, _, _ := strings.Cut(value, "|")
	switch {
	case strings.HasPrefix(typ, "ip-src"):
		scenario = ScenarioSrc
	case strings.HasPrefix(typ, "ip-dst"):
		scenario = ScenarioDst
	default:
		return "", "", "", false
	}
	if p, err := netip.ParsePrefix(addr); err == nil {
		if p.IsSingleIP() {
			return "Ip", p.Addr().Unmap().String(), scenario, true
		}
		return "Range", p.Masked().String(), scenario, true
	}
	if a, err := netip.ParseAddr(addr); err == nil {
		return "Ip", a.Unmap().String(), scenario, true
	}
	return "", "", "", false
}

func (s *Service) recordError(ctx context.Context, err error) {
	_, _ = s.cfg.DB.Exec(ctx, `UPDATE openpicket.misp_sync SET last_error = $1, error_at = now() WHERE id = 1`, err.Error())
}

// Sync reads the OpenPicket attributes of MISP into the copy, reconciles
// the LAPI decisions and proposes repeated attackers.
func (s *Service) Sync(ctx context.Context, l Fencer) error {
	attrs, err := s.cfg.Client.SearchOpenPicket(ctx)
	if err != nil {
		// Decisions are left alone: they run out on their own.
		s.recordError(ctx, err)
		return err
	}
	now := s.cfg.Now()
	if err := l.Fenced(ctx, func(tx pgx.Tx) error {
		seen := make([]string, 0, len(attrs))
		for _, a := range attrs {
			state := a.Machine("state")
			if state == "" {
				state = StateProposed
			}
			tags := make([]string, 0, len(a.Tags))
			for _, t := range a.Tags {
				tags = append(tags, t.Name)
			}
			if a.Deleted {
				// A deleted attribute is a revocation.
				state = StateRevoked
			}
			info := ""
			if a.Event != nil {
				info = a.Event.Info
			}
			seen = append(seen, a.UUID)
			if _, err := tx.Exec(ctx, `INSERT INTO openpicket.misp_iocs (uuid, attribute_id, event_id, event_info, type, value, to_ids, state, ttl,
				comment, tags, modified_at, approved_at, synced_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, CASE WHEN $8 = 'approved' THEN $13::timestamptz END, $13)
				ON CONFLICT (uuid) DO UPDATE SET attribute_id=excluded.attribute_id, event_id=excluded.event_id,
				event_info=CASE WHEN excluded.event_info = '' THEN misp_iocs.event_info ELSE excluded.event_info END, type=excluded.type,
				value=excluded.value, to_ids=excluded.to_ids, state=excluded.state, ttl=excluded.ttl, comment=excluded.comment, tags=excluded.tags,
				modified_at=excluded.modified_at,
				approved_at=CASE WHEN excluded.state = 'approved' THEN COALESCE(misp_iocs.approved_at, excluded.approved_at) END,
				synced_at=excluded.synced_at`,
				a.UUID, a.ID, a.EventID, info, a.Type, a.Value, a.ToIDS && !a.Deleted, state, a.Machine("ttl"), a.Comment, tags, a.Modified(), now); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `DELETE FROM openpicket.misp_iocs WHERE NOT (uuid = ANY($1))`, seen)
		return err
	}); err != nil {
		return err
	}
	active, err := s.reconcile(ctx)
	if err != nil {
		s.recordError(ctx, err)
		return err
	}
	if _, err := s.cfg.DB.Exec(ctx, `UPDATE openpicket.misp_sync SET last_sync_at = $1, last_error = '', active = $2 WHERE id = 1`, now, active); err != nil {
		return err
	}
	if s.cfg.ProposeMinAlerts > 0 {
		if err := s.proposeRepeated(ctx); err != nil {
			s.log.Warn("misp proposals", "err", err)
		}
	}
	return nil
}

type desired struct {
	scope, value, scenario, ref string
	// end of the approval (approved_at + ttl)
	end time.Time
}

// reconcile makes the LAPI decisions of the MISP scenarios match the
// approved attributes; it returns how many are active.
func (s *Service) reconcile(ctx context.Context) (int, error) {
	now := s.cfg.Now()
	rows, err := s.cfg.DB.Query(ctx, `SELECT uuid, type, value, ttl, approved_at, event_info FROM openpicket.misp_iocs
		WHERE state = 'approved' AND to_ids AND approved_at IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	want := map[string]desired{}
	for rows.Next() {
		var (
			uuid, typ, value, ttl, info string
			approved                    time.Time
		)
		if err := rows.Scan(&uuid, &typ, &value, &ttl, &approved, &info); err != nil {
			rows.Close()
			return 0, err
		}
		if ttl == "" {
			ttl = s.cfg.DefaultTTL
		}
		d, err := ParseTTL(ttl)
		if err != nil {
			s.log.Warn("misp attribute with an invalid ttl", "uuid", uuid, "ttl", ttl)
			continue
		}
		scope, v, scenario, ok := target(typ, value)
		if !ok || !approved.Add(d).After(now) {
			continue
		}
		key := scenario + "|" + v
		if cur, dup := want[key]; !dup || approved.Add(d).After(cur.end) {
			want[key] = desired{scope: scope, value: v, scenario: scenario, ref: fmt.Sprintf("%s (%s)", uuid, info), end: approved.Add(d)}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	type have struct {
		ids   []int64
		until time.Time
	}
	current := map[string]*have{}
	for _, scenario := range []string{ScenarioSrc, ScenarioDst} {
		alerts, err := s.cfg.LAPI.Alerts(ctx, url.Values{"scenario": {scenario}, "has_active_decision": {"true"}, "limit": {"0"}})
		if err != nil {
			return 0, err
		}
		for _, a := range alerts {
			for _, d := range a.Decisions {
				if d.Scenario == nil || *d.Scenario != scenario || d.Value == nil {
					continue
				}
				until, err := time.Parse(time.RFC3339, d.Until)
				if err != nil || !until.After(now) {
					continue
				}
				key := scenario + "|" + *d.Value
				h := current[key]
				if h == nil {
					h = &have{}
					current[key] = h
				}
				h.ids = append(h.ids, d.ID)
				if until.After(h.until) {
					h.until = until
				}
			}
		}
	}
	var errs []error
	for key, d := range want {
		h := current[key]
		if h != nil && h.until.Sub(now) >= s.cfg.Renew {
			continue
		}
		dur := min(2*s.cfg.Renew, d.end.Sub(now)).Round(time.Second)
		if dur < time.Minute {
			continue
		}
		msg := "MISP " + d.ref
		if _, err := s.cfg.LAPI.PushAlerts(ctx, []*lapi.Alert{lapi.DecisionAlert(d.scope, d.value, "ban", dur.String(), d.scenario, Origin, msg, now)}); err != nil {
			errs = append(errs, fmt.Errorf("decision on %s: %w", d.value, err))
		}
	}
	for key, h := range current {
		if _, ok := want[key]; ok {
			continue
		}
		for _, id := range h.ids {
			if _, err := s.cfg.LAPI.DeleteDecision(ctx, id); err != nil && !errors.Is(err, lapi.ErrNotFound) {
				errs = append(errs, fmt.Errorf("delete decision %d: %w", id, err))
			}
		}
	}
	return len(want), errors.Join(errs...)
}

// eventFor returns the monthly sightings event, created when missing.
func (s *Service) eventFor(ctx context.Context) (string, error) {
	info := "OpenPicket sightings " + s.cfg.Now().UTC().Format("2006-01")
	s.mu.Lock()
	id, ok := s.events[info]
	s.mu.Unlock()
	if ok {
		return id, nil
	}
	ev, err := s.cfg.Client.FindEvent(ctx, info)
	if err != nil {
		return "", err
	}
	if ev == nil {
		if ev, err = s.cfg.Client.AddEvent(ctx, info); err != nil {
			return "", err
		}
	}
	s.mu.Lock()
	s.events[info] = ev.ID
	s.mu.Unlock()
	return ev.ID, nil
}

// ErrExists is returned when the value is already in MISP for OpenPicket.
var ErrExists = errors.New("misp: already proposed")

// Propose adds an attribute in the proposed state (to_ids off).
func (s *Service) Propose(ctx context.Context, value, typ, comment string) (*Attribute, error) {
	if typ == "" {
		typ = "ip-src"
	}
	if _, v, _, ok := target(typ, value); !ok {
		return nil, fmt.Errorf("misp: %q is not an IP address or range", value)
	} else {
		value = v
	}
	var n int
	if err := s.cfg.DB.QueryRow(ctx, `SELECT count(*) FROM openpicket.misp_iocs WHERE value = $1 AND type = $2 AND state <> 'revoked'`, value, typ).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, ErrExists
	}
	eventID, err := s.eventFor(ctx)
	if err != nil {
		return nil, err
	}
	a, err := s.cfg.Client.AddAttribute(ctx, eventID, Attribute{Type: typ, Value: value, Comment: comment})
	if err != nil {
		return nil, err
	}
	if err := s.cfg.Client.AttachTag(ctx, a.UUID, StateTag(StateProposed)); err != nil {
		return nil, err
	}
	s.Poke()
	return a, nil
}

// row reads the cached attribute.
func (s *Service) row(ctx context.Context, uuid string) (id string, tags []string, err error) {
	err = s.cfg.DB.QueryRow(ctx, `SELECT attribute_id, tags FROM openpicket.misp_iocs WHERE uuid = $1`, uuid).Scan(&id, &tags)
	if errors.Is(err, pgx.ErrNoRows) {
		err = fmt.Errorf("misp: attribute %s is unknown (not synced yet?)", uuid)
	}
	return id, tags, err
}

// SetState moves attributes to a state: approved (with a TTL) turns on
// to_ids, the others turn it off. The copy is updated at once.
func (s *Service) SetState(ctx context.Context, uuids []string, state, ttl string) error {
	if !slices.Contains([]string{StateApproved, StateRejected, StateRevoked, StateProposed}, state) {
		return fmt.Errorf("misp: unknown state %q", state)
	}
	if state == StateApproved {
		if ttl == "" {
			ttl = s.cfg.DefaultTTL
		}
		if _, err := ParseTTL(ttl); err != nil {
			return err
		}
	}
	var errs []error
	for _, uuid := range uuids {
		if err := s.setState(ctx, uuid, state, ttl); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", uuid, err))
		}
	}
	s.Poke()
	return errors.Join(errs...)
}

func (s *Service) setState(ctx context.Context, uuid, state, ttl string) error {
	id, tags, err := s.row(ctx, uuid)
	if err != nil {
		return err
	}
	for _, t := range tags {
		stale := strings.HasPrefix(t, TagNamespace+":state=") && t != StateTag(state)
		stale = stale || (state == StateApproved && strings.HasPrefix(t, TagNamespace+":ttl=") && t != TTLTag(ttl))
		if stale {
			if err := s.cfg.Client.RemoveTag(ctx, uuid, t); err != nil {
				return err
			}
		}
	}
	if !slices.Contains(tags, StateTag(state)) {
		if err := s.cfg.Client.AttachTag(ctx, uuid, StateTag(state)); err != nil {
			return err
		}
	}
	if state == StateApproved && !slices.Contains(tags, TTLTag(ttl)) {
		if err := s.cfg.Client.AttachTag(ctx, uuid, TTLTag(ttl)); err != nil {
			return err
		}
	}
	if err := s.cfg.Client.SetToIDS(ctx, id, state == StateApproved); err != nil {
		return err
	}
	_, err = s.cfg.DB.Exec(ctx, `UPDATE openpicket.misp_iocs SET state = $2, to_ids = $3,
		ttl = CASE WHEN $2 = 'approved' THEN $4 ELSE ttl END,
		approved_at = CASE WHEN $2 = 'approved' THEN COALESCE(approved_at, now()) END WHERE uuid = $1`,
		uuid, state, state == StateApproved, ttl)
	return err
}

// proposeRepeated proposes sources with many recent alerts.
func (s *Service) proposeRepeated(ctx context.Context) error {
	rows, err := s.cfg.DB.Query(ctx, `SELECT a.source_value, count(*), string_agg(DISTINCT a.scenario, ', '), string_agg(DISTINCT a.node_id, ', ')
		FROM openpicket.alerts a WHERE a.source_scope = 'Ip' AND NOT a.simulated AND a.created_at > $1
		AND a.scenario NOT LIKE 'openpicket/misp-%' AND a.scenario NOT LIKE 'openpicket/manual%'
		AND NOT EXISTS (SELECT 1 FROM openpicket.misp_iocs m WHERE m.value = a.source_value)
		GROUP BY 1 HAVING count(*) >= $2 ORDER BY 2 DESC LIMIT 50`, s.cfg.Now().Add(-s.cfg.ProposeWindow), s.cfg.ProposeMinAlerts)
	if err != nil {
		return err
	}
	type cand struct {
		value, scenarios, nodes string
		n                       int64
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.value, &c.n, &c.scenarios, &c.nodes); err != nil {
			rows.Close()
			return err
		}
		cands = append(cands, c)
	}
	rows.Close()
	var errs []error
	for _, c := range cands {
		comment := fmt.Sprintf("OpenPicket: %d alerts in %s; scenarios: %s; nodes: %s", c.n, s.cfg.ProposeWindow, c.scenarios, c.nodes)
		if _, err := s.Propose(ctx, c.value, "ip-src", comment); err != nil && !errors.Is(err, ErrExists) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
