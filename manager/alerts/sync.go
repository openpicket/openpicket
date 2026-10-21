// Package alerts keeps a PostgreSQL copy of the alerts and decisions of
// the CrowdSec LAPI instances, and searches it (docs/ARCHITECTURE.md
// §5.7). The copy is written by one replica (leader "alerts") and read by
// all.
//
// LAPI has no "created after" filter, so new alerts are found by listing
// the newest ones (sort DESC) with a growing limit until the list overlaps
// what is stored (alert ids grow with creation). Decisions change without
// a new alert (deleted, or expired): the alerts with active decisions are
// re-read periodically, and a full pass over the retention window removes
// what the LAPI no longer has.
package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/openpicket/openpicket/manager/lapi"
)

// Instance is one LAPI.
type Instance struct {
	Name    string
	URL     string
	Watcher *lapi.Watcher
}

// Config configures the syncer.
type Config struct {
	DB        *pgxpool.Pool
	Instances []Instance
	// PollInterval for new alerts (default 10s).
	PollInterval time.Duration
	// ActiveInterval for re-reading alerts with active decisions (60s).
	ActiveInterval time.Duration
	// FullInterval for the reconciliation pass (1h).
	FullInterval time.Duration
	// Retention of the copy (default 30d); also the reconciliation window.
	Retention  time.Duration
	Logger     *slog.Logger
	Registerer prometheus.Registerer
	Now        func() time.Time
}

// Fencer runs fn in a transaction that commits only while leader.
type Fencer interface {
	Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error
}

// Syncer copies alerts.
type Syncer struct {
	cfg       Config
	log       *slog.Logger
	poke      chan string
	forceFull atomic.Bool

	synced *prometheus.CounterVec
	errs   *prometheus.CounterVec
}

// NewSyncer creates a syncer.
func NewSyncer(cfg Config) *Syncer {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 10 * time.Second
	}
	if cfg.ActiveInterval <= 0 {
		cfg.ActiveInterval = time.Minute
	}
	if cfg.FullInterval <= 0 {
		cfg.FullInterval = time.Hour
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 30 * 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Syncer{cfg: cfg, log: cfg.Logger.With("component", "alerts"), poke: make(chan string, 16),
		synced: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openpicket_alerts_synced_total", Help: "Alerts copied from the LAPI."}, []string{"instance"}),
		errs:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openpicket_alerts_sync_errors_total", Help: "Failed LAPI alert syncs."}, []string{"instance"}),
	}
	if cfg.Registerer != nil {
		cfg.Registerer.MustRegister(s.synced, s.errs)
	}
	return s
}

// Poke asks for an immediate sync of an instance (after a change made
// through the API); "" pokes all.
func (s *Syncer) Poke(instance string) {
	select {
	case s.poke <- instance:
	default:
	}
}

// Resync asks for a full pass over every instance.
func (s *Syncer) Resync() {
	s.forceFull.Store(true)
	s.Poke("")
}

// Run syncs while leader.
func (s *Syncer) Run(ctx context.Context, l Fencer) {
	type state struct{ lastActive, lastFull time.Time }
	states := make([]state, len(s.cfg.Instances))
	t := time.NewTicker(s.cfg.PollInterval)
	defer t.Stop()
	for {
		now := s.cfg.Now()
		forced := s.forceFull.Swap(false)
		for i, inst := range s.cfg.Instances {
			st := &states[i]
			full := forced || now.Sub(st.lastFull) >= s.cfg.FullInterval
			active := full || now.Sub(st.lastActive) >= s.cfg.ActiveInterval
			if err := s.syncInstance(ctx, l, inst, active, full); err != nil {
				if ctx.Err() != nil {
					return
				}
				s.errs.WithLabelValues(inst.Name).Inc()
				s.log.Warn("alert sync", "instance", inst.Name, "err", err)
				s.recordError(ctx, inst, err)
				continue
			}
			if active {
				st.lastActive = now
			}
			if full {
				st.lastFull = now
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.poke:
		}
	}
}

func (s *Syncer) recordError(ctx context.Context, inst Instance, err error) {
	_, _ = s.cfg.DB.Exec(ctx, `INSERT INTO openpicket.alert_sync (instance, url, last_error, error_at) VALUES ($1,$2,$3,now())
		ON CONFLICT (instance) DO UPDATE SET url=excluded.url, last_error=excluded.last_error, error_at=excluded.error_at`, inst.Name, inst.URL, err.Error())
}

// SyncOnce runs one pass (tests).
func (s *Syncer) SyncOnce(ctx context.Context, l Fencer, active, full bool) error {
	var errs []error
	for _, inst := range s.cfg.Instances {
		errs = append(errs, s.syncInstance(ctx, l, inst, active, full))
	}
	return errors.Join(errs...)
}

const (
	firstLimit = 200
	maxLimit   = 50000
)

func (s *Syncer) syncInstance(ctx context.Context, l Fencer, inst Instance, active, full bool) error {
	var maxID int64
	if err := s.cfg.DB.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM openpicket.alerts WHERE instance = $1`, inst.Name).Scan(&maxID); err != nil {
		return err
	}
	var batches [][]*lapi.Alert
	if full {
		window := fmt.Sprintf("%dh", int(s.cfg.Retention.Hours()))
		all, err := inst.Watcher.Alerts(ctx, url.Values{"since": {window}, "limit": {"0"}, "include_capi": {"false"}})
		if err != nil {
			return err
		}
		batches = append(batches, all)
	} else {
		// Newest first, growing the limit until the oldest returned alert
		// is one already stored.
		for limit := firstLimit; ; limit *= 4 {
			got, err := inst.Watcher.Alerts(ctx, url.Values{"sort": {"DESC"}, "limit": {strconv.Itoa(limit)}, "include_capi": {"false"}})
			if err != nil {
				return err
			}
			batches = append(batches, got)
			if len(got) < limit || maxID == 0 || got[len(got)-1].ID <= maxID || limit >= maxLimit {
				break
			}
		}
		if active {
			act, err := inst.Watcher.Alerts(ctx, url.Values{"has_active_decision": {"true"}, "limit": {"0"}, "include_capi": {"false"}})
			if err != nil {
				return err
			}
			batches = append(batches, act)
		}
	}
	now := s.cfg.Now()
	return l.Fenced(ctx, func(tx pgx.Tx) error {
		seen := map[int64]bool{}
		withActive := map[int64]bool{}
		n := 0
		for bi, batch := range batches {
			for _, a := range batch {
				if a.ID == 0 {
					continue
				}
				if active && !full && bi == len(batches)-1 {
					withActive[a.ID] = true
				}
				if seen[a.ID] {
					continue
				}
				seen[a.ID] = true
				// Unchanged old alerts are skipped (decisions are refreshed
				// by the active and full passes).
				if a.ID <= maxID && !full && !(active && bi == len(batches)-1) {
					continue
				}
				if err := upsert(ctx, tx, inst.Name, a); err != nil {
					return fmt.Errorf("alert %d: %w", a.ID, err)
				}
				n++
			}
		}
		if active && !full {
			// Active decisions whose alert no longer lists them active were
			// deleted in the LAPI.
			ids := make([]int64, 0, len(withActive))
			for id := range withActive {
				ids = append(ids, id)
			}
			// LAPI soft-deletes (until = now): keep them as expired.
			if _, err := tx.Exec(ctx, `UPDATE openpicket.alert_decisions SET until = $2 WHERE instance = $1 AND until > $2 AND NOT (alert_id = ANY($3))`,
				inst.Name, now, ids); err != nil {
				return err
			}
		}
		if full {
			ids := make([]int64, 0, len(seen))
			for id := range seen {
				ids = append(ids, id)
			}
			// Alerts in the window the LAPI no longer has were deleted
			// (cscli alerts delete, or the LAPI flush).
			if _, err := tx.Exec(ctx, `DELETE FROM openpicket.alerts WHERE instance = $1 AND start_at >= $2 AND NOT (id = ANY($3))`,
				inst.Name, now.Add(-s.cfg.Retention), ids); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM openpicket.alerts WHERE instance = $1 AND created_at < $2`, inst.Name, now.Add(-s.cfg.Retention)); err != nil {
				return err
			}
		}
		s.synced.WithLabelValues(inst.Name).Add(float64(n))
		_, err := tx.Exec(ctx, `INSERT INTO openpicket.alert_sync (instance, url, last_poll_at, last_full_at, last_error) VALUES ($1,$2,$3,$4,'')
			ON CONFLICT (instance) DO UPDATE SET url=excluded.url, last_poll_at=excluded.last_poll_at,
			last_full_at=COALESCE(excluded.last_full_at, alert_sync.last_full_at), last_error=''`,
			inst.Name, inst.URL, now, nullIf(full, now))
		return err
	})
}

func nullIf(ok bool, t time.Time) *time.Time {
	if !ok {
		return nil
	}
	return &t
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05 -0700 MST"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// metaMap decodes alert context values (JSON arrays as strings).
func metaMap(meta []*lapi.Meta) map[string][]string {
	out := map[string][]string{}
	for _, m := range meta {
		var vals []string
		if err := json.Unmarshal([]byte(m.Value), &vals); err != nil {
			vals = []string{m.Value}
		}
		out[m.Key] = append(out[m.Key], vals...)
	}
	return out
}

func first(m map[string][]string, key string) string {
	if v := m[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func upsert(ctx context.Context, tx pgx.Tx, instance string, a *lapi.Alert) error {
	meta := metaMap(a.Meta)
	metaJSON, _ := json.Marshal(meta)
	events := a.Events
	if events == nil {
		events = []*lapi.Event{}
	}
	eventsJSON, _ := json.Marshal(events)
	created := parseTime(a.CreatedAt)
	if created == nil {
		created = parseTime(str(a.StartAt))
	}
	if created == nil {
		now := time.Now()
		created = &now
	}
	src := a.Source
	if src == nil {
		src = &lapi.Source{}
	}
	var events32 int32
	if a.EventsCount != nil {
		events32 = *a.EventsCount
	}
	simulated := a.Simulated != nil && *a.Simulated
	if _, err := tx.Exec(ctx, `INSERT INTO openpicket.alerts (instance, id, uuid, scenario, message, source_scope, source_value, source_ip, source_range,
		country, as_number, as_name, latitude, longitude, events_count, simulated, remediation, machine_id, start_at, stop_at, created_at,
		meta, node_id, direction, events, synced_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,now())
		ON CONFLICT (instance, id) DO UPDATE SET uuid=excluded.uuid, scenario=excluded.scenario, message=excluded.message,
		source_scope=excluded.source_scope, source_value=excluded.source_value, source_ip=excluded.source_ip, source_range=excluded.source_range,
		country=excluded.country, as_number=excluded.as_number, as_name=excluded.as_name, latitude=excluded.latitude, longitude=excluded.longitude,
		events_count=excluded.events_count, simulated=excluded.simulated, remediation=excluded.remediation, machine_id=excluded.machine_id,
		start_at=excluded.start_at, stop_at=excluded.stop_at, created_at=excluded.created_at, meta=excluded.meta, node_id=excluded.node_id,
		direction=excluded.direction, events=CASE WHEN excluded.events = '[]'::jsonb THEN alerts.events ELSE excluded.events END, synced_at=now()`,
		instance, a.ID, a.UUID, str(a.Scenario), str(a.Message), str(src.Scope), str(src.Value), src.IP, src.Range,
		src.Country, src.ASNumber, src.ASName, src.Latitude, src.Longitude, events32, simulated, a.Remediation, a.MachineID,
		parseTime(str(a.StartAt)), parseTime(str(a.StopAt)), *created, metaJSON, first(meta, "node_id"), first(meta, "direction"), eventsJSON); err != nil {
		return err
	}
	ids := make([]int64, 0, len(a.Decisions))
	for _, d := range a.Decisions {
		until := parseTime(d.Until)
		if until == nil {
			// Older LAPIs: until from the remaining duration.
			dur, err := time.ParseDuration(str(d.Duration))
			if err != nil {
				continue
			}
			t := time.Now().Add(dur)
			until = &t
		}
		ids = append(ids, d.ID)
		if _, err := tx.Exec(ctx, `INSERT INTO openpicket.alert_decisions (instance, id, alert_id, type, scope, value, origin, scenario, until, simulated)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (instance, id) DO UPDATE SET type=excluded.type, scope=excluded.scope, value=excluded.value, origin=excluded.origin,
			scenario=excluded.scenario, until=excluded.until, simulated=excluded.simulated`,
			instance, d.ID, a.ID, str(d.Type), str(d.Scope), str(d.Value), str(d.Origin), str(d.Scenario), *until, d.Simulated != nil && *d.Simulated); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `DELETE FROM openpicket.alert_decisions WHERE instance = $1 AND alert_id = $2 AND NOT (id = ANY($3))`, instance, a.ID, ids)
	return err
}

// Store applies the result of API changes to the copy immediately (the
// next sync confirms them).
type Store struct {
	DB *pgxpool.Pool
}

// ForgetAlerts removes alerts from the copy.
func (s *Store) ForgetAlerts(ctx context.Context, instance string, ids []int64) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM openpicket.alerts WHERE instance = $1 AND id = ANY($2)`, instance, ids)
	return err
}

// ExpireDecisions marks decisions deleted through the API as expired, as
// LAPI does (until = now), so the list with expired decisions keeps them.
func (s *Store) ExpireDecisions(ctx context.Context, instance string, ids []int64) error {
	_, err := s.DB.Exec(ctx, `UPDATE openpicket.alert_decisions SET until = now() WHERE instance = $1 AND id = ANY($2) AND until > now()`, instance, ids)
	return err
}

// ForgetValue expires the decisions of a value and optionally deletes its
// alerts (with their decisions).
func (s *Store) ForgetValue(ctx context.Context, instance, value string, alerts bool) error {
	if _, err := s.DB.Exec(ctx, `UPDATE openpicket.alert_decisions SET until = now() WHERE ($1 = '' OR instance = $1) AND value = $2 AND until > now()`, instance, value); err != nil {
		return err
	}
	if alerts {
		_, err := s.DB.Exec(ctx, `DELETE FROM openpicket.alerts WHERE ($1 = '' OR instance = $1) AND source_value = $2`, instance, value)
		return err
	}
	return nil
}
