// Package relay distributes CrowdSec decisions to the nodes
// (docs/ARCHITECTURE.md §4.3).
//
// The leader replica pulls the primary LAPI's decision stream and keeps the
// edge view in PostgreSQL (openpicket.edge_decisions: one row per value,
// versioned). Every replica then streams snapshots and deltas of that view
// to the nodes connected to it (Distributor).
package relay

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/openpicket/openpicket/manager/allowlist"
	"github.com/openpicket/openpicket/manager/db"
	"github.com/openpicket/openpicket/manager/lapi"
)

// Directions stored in edge_decisions.
const (
	DirInbound = "inbound"
	DirBoth    = "both"
)

// Rules decide which LAPI decisions reach the edge and how they block
// (§5.9 D). LAPI decisions carry no direction, so it is derived from the
// scenario name.
type Rules struct {
	// Types that apply at the edge (default ban).
	Types []string
	// Scopes that apply at the edge (default Ip, Range).
	Scopes []string
	// ExcludeOrigins and ExcludeScenarios (path.Match globs) keep decisions
	// for L7 bouncers only.
	ExcludeOrigins   []string
	ExcludeScenarios []string
	// BothScenarios (globs) block both ways.
	BothScenarios []string
}

// DefaultRules returns the default edge rules.
func DefaultRules() Rules {
	return Rules{
		Types:         []string{"ban"},
		Scopes:        []string{"Ip", "Range"},
		BothScenarios: []string{"openpicket/suricata-outbound-*", "openpicket/misp-ip-dst", "openpicket/manual-both"},
	}
}

func globAny(globs []string, s string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, s); ok {
			return true
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(v string) bool { return strings.EqualFold(v, s) })
}

// Normalize returns the canonical value and edge scope ("ip" or "range"),
// or false for a value the edge cannot block.
func Normalize(scope, value string) (string, string, bool) {
	switch strings.ToLower(scope) {
	case "ip":
		a, err := netip.ParseAddr(value)
		if err != nil || a.Zone() != "" {
			return "", "", false
		}
		return a.Unmap().String(), "ip", true
	case "range":
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return "", "", false
		}
		p = p.Masked()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.String(), "range", true
	}
	return "", "", false
}

// Eligible reports whether d applies at the edge.
func (r Rules) Eligible(d *lapi.Decision) bool {
	if !containsFold(r.Types, d.Type) || !containsFold(r.Scopes, d.Scope) {
		return false
	}
	if containsFold(r.ExcludeOrigins, d.Origin) || globAny(r.ExcludeScenarios, d.Scenario) {
		return false
	}
	_, _, ok := Normalize(d.Scope, d.Value)
	return ok
}

// Both reports whether d blocks both ways.
func (r Rules) Both(d *lapi.Decision) bool { return globAny(r.BothScenarios, d.Scenario) }

// Config configures the relay.
type Config struct {
	LAPI  *lapi.Client
	Rules Rules
	// PullInterval between stream pulls (default 10s).
	PullInterval time.Duration
	// FullResyncInterval forces a startup pull periodically (default 15m).
	FullResyncInterval time.Duration
	// TombstoneRetention before deleted rows are pruned (default 24h).
	TombstoneRetention time.Duration
	Logger             *slog.Logger
	Registerer         prometheus.Registerer
	Now                func() time.Time
}

// Relay is the leader task feeding edge_decisions.
type Relay struct {
	cfg      Config
	log      *slog.Logger
	version  prometheus.Gauge
	pulls    *prometheus.CounterVec
	resyncs  prometheus.Counter
	lastPull prometheus.Gauge
	// poke wakes Run after an allowlist change.
	poke chan struct{}
}

// New creates a relay.
func New(cfg Config) *Relay {
	if cfg.PullInterval <= 0 {
		cfg.PullInterval = 10 * time.Second
	}
	if cfg.FullResyncInterval <= 0 {
		cfg.FullResyncInterval = 15 * time.Minute
	}
	if cfg.TombstoneRetention <= 0 {
		cfg.TombstoneRetention = 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	r := &Relay{
		cfg:      cfg,
		log:      cfg.Logger.With("component", "relay"),
		version:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "openpicket_relay_version", Help: "Current version of the edge decision view."}),
		pulls:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openpicket_relay_pulls_total", Help: "LAPI stream pulls."}, []string{"result"}),
		resyncs:  prometheus.NewCounter(prometheus.CounterOpts{Name: "openpicket_relay_full_resyncs_total", Help: "Startup (full) pulls."}),
		lastPull: prometheus.NewGauge(prometheus.GaugeOpts{Name: "openpicket_relay_last_pull_timestamp_seconds", Help: "Time of the last successful pull."}),
		poke:     make(chan struct{}, 1),
	}
	if cfg.Registerer != nil {
		for _, c := range []prometheus.Collector{r.version, r.pulls, r.resyncs, r.lastPull} {
			_ = cfg.Registerer.Register(c)
		}
	}
	return r
}

// Fencer runs a transaction that commits only while this replica still
// leads (db.Leadership).
type Fencer interface {
	Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error
}

// Notified reports an allowlist change (openpicket_allowlist).
func (r *Relay) Notified(string) {
	select {
	case r.poke <- struct{}{}:
	default:
	}
}

// Run pulls until ctx ends (leadership lost or shutdown). Leadership
// starts with a full resync: the previous leader may have received a
// delta it never committed (§4.3). The allowlist is reconciled at the
// start, after a change, when an entry runs out and every
// FullResyncInterval.
func (r *Relay) Run(ctx context.Context, l Fencer) {
	needResync := true
	lastFull := time.Time{}
	allowDue := time.Time{}
	for ctx.Err() == nil {
		full := needResync || r.cfg.Now().Sub(lastFull) >= r.cfg.FullResyncInterval
		changed, err := r.pull(ctx, l, full)
		switch {
		case errors.Is(err, db.ErrNotLeader):
			r.log.Warn("relay stopped: no longer the leader")
			return
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			// The LAPI may have advanced our cursor (sent a delta we did
			// not commit): only a full pull is safe now.
			needResync = true
			r.pulls.WithLabelValues("error").Inc()
			r.log.Warn("relay pull failed; next pull is a full resync", "err", err)
		default:
			needResync = false
			if full {
				lastFull = r.cfg.Now()
				r.resyncs.Inc()
			}
			r.pulls.WithLabelValues("ok").Inc()
			r.lastPull.Set(float64(r.cfg.Now().Unix()))
			if changed > 0 {
				r.log.Info("edge decisions updated", "changes", changed, "full", full)
			}
		}
		if err := r.expire(ctx, l); err != nil && !errors.Is(err, context.Canceled) {
			r.log.Warn("expire edge decisions", "err", err)
		}
		if !r.cfg.Now().Before(allowDue) {
			next, err := r.Reconcile(ctx, l)
			switch {
			case errors.Is(err, db.ErrNotLeader):
				r.log.Warn("relay stopped: no longer the leader")
				return
			case err != nil:
				if ctx.Err() != nil {
					return
				}
				r.log.Warn("apply the allowlist to edge decisions; retrying at the next pull", "err", err)
			default:
				allowDue = next
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-r.poke:
			allowDue = time.Time{}
		case <-time.After(r.cfg.PullInterval):
		}
	}
}

func (r *Relay) pull(ctx context.Context, l Fencer, full bool) (int, error) {
	s, err := r.cfg.LAPI.Stream(ctx, full)
	if err != nil {
		return 0, err
	}
	var changed int
	err = l.Fenced(ctx, func(tx pgx.Tx) error {
		var err error
		changed, err = r.Apply(ctx, tx, s, full)
		return err
	})
	return changed, err
}

// Apply writes a stream response into lapi_decisions and updates the edge
// view of every affected value. A full response replaces the whole copy.
// It returns the number of edge rows changed.
func (r *Relay) Apply(ctx context.Context, tx pgx.Tx, s *lapi.Stream, full bool) (int, error) {
	affected := map[string]bool{}
	if full {
		keep := make([]int64, 0, len(s.New))
		for _, d := range s.New {
			keep = append(keep, d.ID)
		}
		rows, err := tx.Query(ctx, `DELETE FROM openpicket.lapi_decisions WHERE NOT (id = ANY($1)) RETURNING value`, keep)
		if err != nil {
			return 0, err
		}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err == nil {
				affected[v] = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, err
		}
	} else {
		ids := make([]int64, 0, len(s.Deleted))
		for _, d := range s.Deleted {
			ids = append(ids, d.ID)
		}
		if len(ids) > 0 {
			rows, err := tx.Query(ctx, `DELETE FROM openpicket.lapi_decisions WHERE id = ANY($1) RETURNING value`, ids)
			if err != nil {
				return 0, err
			}
			for rows.Next() {
				var v string
				if err := rows.Scan(&v); err == nil {
					affected[v] = true
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return 0, err
			}
		}
	}
	if len(s.New) > 0 {
		var (
			ids                                   []int64
			values, scopes, types, origins, scens []string
			untils                                []time.Time
			eligible, both                        []bool
		)
		for _, d := range s.New {
			rem, err := d.Remaining()
			if err != nil {
				r.log.Warn("skip decision with bad duration", "id", d.ID, "duration", d.Duration)
				continue
			}
			value := d.Value
			if v, _, ok := Normalize(d.Scope, d.Value); ok {
				value = v
			}
			ids, values, scopes, types = append(ids, d.ID), append(values, value), append(scopes, d.Scope), append(types, d.Type)
			origins, scens = append(origins, d.Origin), append(scens, d.Scenario)
			untils = append(untils, s.ReceivedAt.Add(rem))
			eligible, both = append(eligible, r.cfg.Rules.Eligible(d)), append(both, r.cfg.Rules.Both(d))
			affected[value] = true
		}
		// A decision keeps its until across pulls unless the LAPI moved it
		// by more than a pull's rounding, so a full resync does not
		// reshuffle versions.
		if _, err := tx.Exec(ctx, `INSERT INTO openpicket.lapi_decisions (id, value, scope, type, origin, scenario, until, eligible, both_ways, received_at)
			SELECT u.id, u.value, u.scope, u.type, u.origin, u.scenario, u.until, u.eligible, u.both_ways, $10
			FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[], $8::bool[], $9::bool[])
				AS u(id, value, scope, type, origin, scenario, until, eligible, both_ways)
			ON CONFLICT (id) DO UPDATE SET value = excluded.value, scope = excluded.scope, type = excluded.type, origin = excluded.origin,
				scenario = excluded.scenario, eligible = excluded.eligible, both_ways = excluded.both_ways,
				until = CASE WHEN abs(extract(epoch FROM excluded.until - openpicket.lapi_decisions.until)) > 30
					THEN excluded.until ELSE openpicket.lapi_decisions.until END`,
			ids, values, scopes, types, origins, scens, untils, eligible, both, s.ReceivedAt); err != nil {
			return 0, err
		}
	}
	if len(affected) == 0 {
		return 0, nil
	}
	vals := make([]string, 0, len(affected))
	for v := range affected {
		vals = append(vals, v)
	}
	return r.recompute(ctx, tx, vals)
}

type edgeRow struct {
	scope, direction, origin, scenario string
	until                              time.Time
}

// recompute rebuilds the edge rows of the given values and versions the
// ones that changed.
func (r *Relay) recompute(ctx context.Context, tx pgx.Tx, values []string) (int, error) {
	now := r.cfg.Now()
	want := map[string]edgeRow{}
	// Eligible values are canonical addresses or ranges (Normalize); the
	// CASE keeps the cast off the others whatever the plan.
	rows, err := tx.Query(ctx, `SELECT value, scope, origin, scenario, until, both_ways FROM openpicket.lapi_decisions
		WHERE value = ANY($1) AND eligible AND until > $2
			AND NOT `+allowlist.Covered("CASE WHEN eligible THEN value::inet END", "$2")+`
		ORDER BY value, until DESC`, values, now)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var (
			value, scope, origin, scenario string
			until                          time.Time
			both                           bool
		)
		if err := rows.Scan(&value, &scope, &origin, &scenario, &until, &both); err != nil {
			rows.Close()
			return 0, err
		}
		_, edgeScope, _ := Normalize(scope, value)
		cur, ok := want[value]
		if !ok {
			// First row is the longest until.
			cur = edgeRow{scope: edgeScope, direction: DirInbound, origin: origin, scenario: scenario, until: until}
		}
		if both {
			cur.direction = DirBoth
		}
		want[value] = cur
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	have := map[string]edgeRow{}
	deleted := map[string]bool{}
	rows, err = tx.Query(ctx, `SELECT value, scope, direction, origin, scenario, until, deleted FROM openpicket.edge_decisions WHERE value = ANY($1)`, values)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var (
			value string
			e     edgeRow
			del   bool
		)
		if err := rows.Scan(&value, &e.scope, &e.direction, &e.origin, &e.scenario, &e.until, &del); err != nil {
			rows.Close()
			return 0, err
		}
		if del {
			deleted[value] = true
		} else {
			have[value] = e
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	changed := 0
	for _, v := range values {
		w, wok := want[v]
		h, hok := have[v]
		switch {
		case wok && hok && w.scope == h.scope && w.direction == h.direction && absDur(w.until.Sub(h.until)) <= 30*time.Second:
			continue
		case wok:
			if _, err := tx.Exec(ctx, `INSERT INTO openpicket.edge_decisions (value, scope, direction, until, origin, scenario, version, deleted, updated_at)
				VALUES ($1,$2,$3,$4,$5,$6, nextval('openpicket.edge_version'), false, $7)
				ON CONFLICT (value) DO UPDATE SET scope=excluded.scope, direction=excluded.direction, until=excluded.until, origin=excluded.origin,
					scenario=excluded.scenario, version=excluded.version, deleted=false, updated_at=excluded.updated_at`,
				v, w.scope, w.direction, w.until, w.origin, w.scenario, now); err != nil {
				return 0, err
			}
		case hok:
			// updated_at uses the relay clock, the one pruning compares with.
			if _, err := tx.Exec(ctx, `UPDATE openpicket.edge_decisions SET deleted = true, version = nextval('openpicket.edge_version'), updated_at = $2
				WHERE value = $1`, v, now); err != nil {
				return 0, err
			}
		default:
			continue
		}
		changed++
	}
	if changed > 0 {
		var version int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version), 0) FROM openpicket.edge_decisions`).Scan(&version); err != nil {
			return 0, err
		}
		r.version.Set(float64(version))
		if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, db.ChannelDecisions, strconv.FormatInt(version, 10)); err != nil {
			return 0, err
		}
	}
	return changed, nil
}

// Reconcile recomputes the values whose edge rows disagree with the
// allowlist in force: blocked although an entry covers them, or left out
// although none does any more. It returns when to reconcile next: when the
// next entry runs out, or after FullResyncInterval at the latest.
func (r *Relay) Reconcile(ctx context.Context, l Fencer) (time.Time, error) {
	var next time.Time
	err := l.Fenced(ctx, func(tx pgx.Tx) error {
		now := r.cfg.Now()
		rows, err := tx.Query(ctx, `SELECT DISTINCT d.value FROM openpicket.lapi_decisions d
			LEFT JOIN openpicket.edge_decisions e ON e.value = d.value AND NOT e.deleted
			WHERE d.eligible AND d.until > $1
				AND (e.value IS NOT NULL) = `+allowlist.Covered("CASE WHEN d.eligible THEN d.value::inet END", "$1"), now)
		if err != nil {
			return err
		}
		vals, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		if len(vals) > 0 {
			changed, err := r.recompute(ctx, tx, vals)
			if err != nil {
				return err
			}
			r.log.Info("allowlist applied to edge decisions", "changes", changed)
		}
		var exp *time.Time
		if err := tx.QueryRow(ctx, `SELECT min(expires_at) FROM openpicket.allowlist WHERE expires_at > $1`, now).Scan(&exp); err != nil {
			return err
		}
		next = now.Add(r.cfg.FullResyncInterval)
		if exp != nil && exp.Before(next) {
			next = *exp
		}
		return nil
	})
	return next, err
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// expire tombstones edge rows whose decisions all ran out (the LAPI also
// reports them as deleted, but nodes should not wait for the next pull) and
// prunes old tombstones.
func (r *Relay) expire(ctx context.Context, l Fencer) error {
	return l.Fenced(ctx, func(tx pgx.Tx) error {
		now := r.cfg.Now()
		rows, err := tx.Query(ctx, `SELECT value FROM openpicket.edge_decisions WHERE NOT deleted AND until <= $1`, now)
		if err != nil {
			return err
		}
		var vals []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err == nil {
				vals = append(vals, v)
			}
		}
		rows.Close()
		if len(vals) > 0 {
			if _, err := r.recompute(ctx, tx, vals); err != nil {
				return err
			}
		}
		var pruned *int64
		if err := tx.QueryRow(ctx, `WITH d AS (DELETE FROM openpicket.edge_decisions WHERE deleted AND updated_at < $1 RETURNING version)
			SELECT max(version) FROM d`, now.Add(-r.cfg.TombstoneRetention)).Scan(&pruned); err != nil {
			return err
		}
		if pruned != nil {
			if _, err := tx.Exec(ctx, `UPDATE openpicket.edge_meta SET horizon = GREATEST(horizon, $1) WHERE id = 1`, *pruned); err != nil {
				return err
			}
		}
		return nil
	})
}
