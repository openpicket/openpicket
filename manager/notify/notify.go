// Package notify evaluates notification rules and delivers notifications
// to destinations (docs/ARCHITECTURE.md §5.7). Evaluation and delivery run
// on one replica (leader "notify"); every notification is also kept for
// the in-app notification center.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/manager/alerts"
	"github.com/openpicket/openpicket/manager/search"
)

// Rule types.
const (
	NewAlert        = "new_alert"
	NewDecision     = "new_decision"
	IPBan           = "ip_ban"
	CompromisedHost = "compromised_host"
	AlertThreshold  = "alert_threshold"
	AlertSpike      = "alert_spike"
	LAPIDown        = "lapi_down"
	NodeOffline     = "node_offline"
	PolicyError     = "policy_error"
	SinkDown        = "sink_down"
)

var defaultSeverity = map[string]string{
	NewAlert: "info", NewDecision: "info", IPBan: "warning", CompromisedHost: "critical", AlertThreshold: "warning",
	AlertSpike: "warning", LAPIDown: "critical", NodeOffline: "warning", PolicyError: "warning", SinkDown: "critical",
}

// Rule is a notification rule.
type Rule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Enabled          bool      `json:"enabled"`
	Type             string    `json:"type"`
	Severity         string    `json:"severity"`
	Query            string    `json:"query,omitempty"`
	Threshold        int       `json:"threshold,omitempty"`
	WindowSeconds    int       `json:"window_seconds,omitempty"`
	SpikeFactor      float64   `json:"spike_factor,omitempty"`
	CooldownSeconds  int       `json:"cooldown_seconds,omitempty"`
	Destinations     []string  `json:"destinations,omitempty"`
	IPFilters        []string  `json:"ip_filters,omitempty"`
	IncludeSimulated bool      `json:"include_simulated,omitempty"`
	LastFiredAt      time.Time `json:"-"`
}

var idRe = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// Validate checks and completes a rule.
func (r *Rule) Validate() error {
	if !idRe.MatchString(r.ID) {
		return fmt.Errorf("id %q must match %s", r.ID, idRe)
	}
	if r.Name == "" || len(r.Name) > 100 {
		return errors.New("a name of 1-100 characters is required")
	}
	if _, ok := defaultSeverity[r.Type]; !ok {
		return fmt.Errorf("unknown rule type %q", r.Type)
	}
	if r.Severity == "" {
		r.Severity = defaultSeverity[r.Type]
	}
	if !slices.Contains([]string{"info", "warning", "critical"}, r.Severity) {
		return fmt.Errorf("unknown severity %q", r.Severity)
	}
	if n, err := search.Parse(r.Query); err != nil {
		return err
	} else if _, err := alerts.AlertSchema.SQL(n, &search.Builder{}); err != nil {
		return err
	}
	for _, f := range r.IPFilters {
		if _, err := parsePrefix(f); err != nil {
			return fmt.Errorf("ip filter %q: %v", f, err)
		}
	}
	switch r.Type {
	case AlertThreshold, AlertSpike:
		if r.Threshold <= 0 {
			return errors.New("threshold must be positive")
		}
		if r.WindowSeconds < 60 {
			r.WindowSeconds = 300
		}
		if r.Type == AlertSpike && r.SpikeFactor <= 1 {
			r.SpikeFactor = 3
		}
	case NodeOffline:
		if r.WindowSeconds < 60 {
			r.WindowSeconds = 300
		}
	}
	if r.CooldownSeconds <= 0 {
		r.CooldownSeconds = 600
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Store keeps rules, destinations and notifications.
type Store struct {
	DB *pgxpool.Pool
}

// ErrNotFound is returned for unknown rules or destinations.
var ErrNotFound = errors.New("notify: not found")

// Rules lists the rules.
func (s *Store) Rules(ctx context.Context) ([]*Rule, error) {
	rows, err := s.DB.Query(ctx, `SELECT r.spec, r.enabled, (SELECT max(time) FROM openpicket.notifications n WHERE n.rule_id = r.id)
		FROM openpicket.notify_rules r ORDER BY r.name, r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Rule
	for rows.Next() {
		var (
			raw     []byte
			enabled bool
			last    *time.Time
			r       Rule
		)
		if err := rows.Scan(&raw, &enabled, &last); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		r.Enabled = enabled
		if last != nil {
			r.LastFiredAt = *last
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// PutRule creates or replaces a rule. A changed rule starts again from the
// current alerts (no notification for the past).
func (s *Store) PutRule(ctx context.Context, r *Rule, by string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	raw, _ := json.Marshal(r)
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO openpicket.notify_rules (id, name, enabled, spec, updated_at, updated_by) VALUES ($1,$2,$3,$4,now(),$5)
			ON CONFLICT (id) DO UPDATE SET name=excluded.name, enabled=excluded.enabled, spec=excluded.spec, updated_at=now(), updated_by=excluded.updated_by`,
			r.ID, r.Name, r.Enabled, raw, by); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM openpicket.notify_state WHERE rule_id = $1 AND key LIKE 'wm:%'`, r.ID)
		return err
	})
}

// DeleteRule removes a rule.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM openpicket.notify_rules WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// Destinations lists destinations (with secrets; callers must strip them).
func (s *Store) Destinations(ctx context.Context) ([]*Destination, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, name, type, enabled, config, secrets, severities FROM openpicket.notify_destinations ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Destination
	for rows.Next() {
		var (
			d               Destination
			config, secrets []byte
		)
		if err := rows.Scan(&d.ID, &d.Name, &d.Type, &d.Enabled, &config, &secrets, &d.Severities); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(config, &d.Config)
		_ = json.Unmarshal(secrets, &d.Secrets)
		out = append(out, &d)
	}
	return out, rows.Err()
}

// Destination returns one destination.
func (s *Store) Destination(ctx context.Context, id string) (*Destination, error) {
	all, err := s.Destinations(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range all {
		if d.ID == id {
			return d, nil
		}
	}
	return nil, ErrNotFound
}

// MergeSecrets fills empty secrets of d from the stored destination.
func (s *Store) MergeSecrets(ctx context.Context, d *Destination) error {
	old, err := s.Destination(ctx, d.ID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if d.Secrets == nil {
		d.Secrets = map[string]string{}
	}
	for k, v := range old.Secrets {
		if cur, ok := d.Secrets[k]; !ok || cur == "" {
			d.Secrets[k] = v
		}
	}
	return nil
}

// PutDestination creates or replaces a destination; empty secrets keep
// the stored values.
func (s *Store) PutDestination(ctx context.Context, d *Destination, by string) error {
	if !idRe.MatchString(d.ID) {
		return fmt.Errorf("id %q must match %s", d.ID, idRe)
	}
	if err := s.MergeSecrets(ctx, d); err != nil {
		return err
	}
	for k, v := range d.Secrets {
		if v == "" {
			delete(d.Secrets, k)
		}
	}
	if err := d.Validate(); err != nil {
		return err
	}
	config, _ := json.Marshal(nonNil(d.Config))
	secrets, _ := json.Marshal(nonNil(d.Secrets))
	if d.Severities == nil {
		d.Severities = []string{}
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO openpicket.notify_destinations (id, name, type, enabled, config, secrets, severities, updated_at, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,now(),$8) ON CONFLICT (id) DO UPDATE SET name=excluded.name, type=excluded.type, enabled=excluded.enabled,
		config=excluded.config, secrets=excluded.secrets, severities=excluded.severities, updated_at=now(), updated_by=excluded.updated_by`,
		d.ID, d.Name, d.Type, d.Enabled, config, secrets, d.Severities, by)
	return err
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// DeleteDestination removes a destination.
func (s *Store) DeleteDestination(ctx context.Context, id string) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM openpicket.notify_destinations WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// Config configures the engine.
type Config struct {
	DB     *pgxpool.Pool
	Sender *Sender
	// PublicURL makes links absolute (https://openpicket.example.com).
	PublicURL string
	// Health reports components that are down on the leader (sink_down).
	Health   func() map[string]string
	Interval time.Duration
	Logger   *slog.Logger
	Now      func() time.Time
}

// Engine evaluates rules and delivers.
type Engine struct {
	cfg   Config
	store *Store
	log   *slog.Logger
	q     *alerts.Querier
}

// NewEngine creates an engine.
func NewEngine(cfg Config) *Engine {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sender == nil {
		cfg.Sender = &Sender{}
	}
	return &Engine{cfg: cfg, store: &Store{DB: cfg.DB}, log: cfg.Logger.With("component", "notify"), q: &alerts.Querier{DB: cfg.DB, Now: cfg.Now}}
}

// Fencer runs fn while leader.
type Fencer interface {
	Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error
}

// Run evaluates and delivers while leader.
func (e *Engine) Run(ctx context.Context, l Fencer) {
	t := time.NewTicker(e.cfg.Interval)
	defer t.Stop()
	for {
		if err := e.Evaluate(ctx, l); err != nil && ctx.Err() == nil {
			e.log.Warn("evaluate rules", "err", err)
		}
		if err := e.Deliver(ctx); err != nil && ctx.Err() == nil {
			e.log.Warn("deliver notifications", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type fired struct {
	subject, title, body, link string
}

// Evaluate runs every enabled rule once.
func (e *Engine) Evaluate(ctx context.Context, l Fencer) error {
	rules, err := e.store.Rules(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if err := l.Fenced(ctx, func(tx pgx.Tx) error { return e.evaluate(ctx, tx, r) }); err != nil {
			errs = append(errs, fmt.Errorf("rule %s: %w", r.ID, err))
		}
	}
	return errors.Join(errs...)
}

func getState(ctx context.Context, tx pgx.Tx, rule, key string, v any) (bool, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT value FROM openpicket.notify_state WHERE rule_id = $1 AND key = $2`, rule, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, v)
}

func setState(ctx context.Context, tx pgx.Tx, rule, key string, v any) error {
	raw, _ := json.Marshal(v)
	_, err := tx.Exec(ctx, `INSERT INTO openpicket.notify_state (rule_id, key, value) VALUES ($1,$2,$3)
		ON CONFLICT (rule_id, key) DO UPDATE SET value = excluded.value`, rule, key, raw)
	return err
}

func delState(ctx context.Context, tx pgx.Tx, rule, key string) error {
	_, err := tx.Exec(ctx, `DELETE FROM openpicket.notify_state WHERE rule_id = $1 AND key = $2`, rule, key)
	return err
}

const maxPerPass = 20

func (e *Engine) evaluate(ctx context.Context, tx pgx.Tx, r *Rule) error {
	var out []fired
	var err error
	switch r.Type {
	case NewAlert, CompromisedHost:
		out, err = e.newAlerts(ctx, tx, r)
	case NewDecision, IPBan:
		out, err = e.newDecisions(ctx, tx, r)
	case AlertThreshold, AlertSpike:
		out, err = e.counts(ctx, tx, r)
	case LAPIDown:
		out, err = e.lapiDown(ctx, tx)
	case NodeOffline:
		out, err = e.nodesOffline(ctx, tx, r)
	case PolicyError:
		out, err = e.policyErrors(ctx, tx)
	case SinkDown:
		if e.cfg.Health != nil {
			for name, detail := range e.cfg.Health() {
				out = append(out, fired{subject: name, title: name + " is down", body: detail, link: "/system"})
			}
		}
	}
	if err != nil {
		return err
	}
	if len(out) > maxPerPass {
		extra := len(out) - maxPerPass
		out = append(out[:maxPerPass], fired{subject: "*", title: fmt.Sprintf("%s: %d more", r.Name, extra),
			body: fmt.Sprintf("%d more events matched %q in this pass.", extra, r.Name)})
	}
	now := e.cfg.Now()
	for _, f := range out {
		var last time.Time
		key := "fired:" + f.subject
		if ok, err := getState(ctx, tx, r.ID, key, &last); err != nil {
			return err
		} else if ok && now.Sub(last) < time.Duration(r.CooldownSeconds)*time.Second {
			continue
		}
		if err := setState(ctx, tx, r.ID, key, now); err != nil {
			return err
		}
		if err := e.create(ctx, tx, r, f, now); err != nil {
			return err
		}
	}
	// Old cooldown entries.
	_, err = tx.Exec(ctx, `DELETE FROM openpicket.notify_state WHERE rule_id = $1 AND key LIKE 'fired:%' AND (value #>> '{}')::timestamptz < $2`,
		r.ID, now.Add(-time.Duration(r.CooldownSeconds)*time.Second))
	return err
}

func (e *Engine) create(ctx context.Context, tx pgx.Tx, r *Rule, f fired, now time.Time) error {
	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO openpicket.notifications (time, rule_id, rule_name, severity, title, body, subject, link)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, now, r.ID, r.Name, r.Severity, f.title, f.body, f.subject, f.link).Scan(&id); err != nil {
		return err
	}
	dests, err := e.store.Destinations(ctx)
	if err != nil {
		return err
	}
	for _, d := range dests {
		if !d.Enabled || !slices.Contains(r.Destinations, d.ID) || (len(d.Severities) > 0 && !slices.Contains(d.Severities, r.Severity)) {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO openpicket.notify_deliveries (notification_id, destination_id) VALUES ($1,$2)`, id, d.ID); err != nil {
			return err
		}
	}
	return nil
}

// watermark returns the last id seen per instance, initializing it to the
// current maximum (a new rule does not notify about the past).
func watermark(ctx context.Context, tx pgx.Tx, rule, key, maxSQL string) (map[string]int64, bool, error) {
	wm := map[string]int64{}
	ok, err := getState(ctx, tx, rule, key, &wm)
	if err != nil || ok {
		return wm, ok, err
	}
	rows, err := tx.Query(ctx, maxSQL)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			inst string
			id   int64
		)
		if err := rows.Scan(&inst, &id); err != nil {
			return nil, false, err
		}
		wm[inst] = id
	}
	return wm, false, rows.Err()
}

func (e *Engine) alertWhere(r *Rule, b *search.Builder) (string, error) {
	n, err := search.Parse(r.Query)
	if err != nil {
		return "", err
	}
	cond, err := alerts.AlertSchema.SQL(n, b)
	if err != nil {
		return "", err
	}
	if !r.IncludeSimulated {
		cond = "(" + cond + ") AND NOT a.simulated"
	}
	if r.Type == CompromisedHost {
		cond = "(" + cond + ") AND a.source_scope = 'openpicket_host'"
	}
	return cond, nil
}

func (e *Engine) newAlerts(ctx context.Context, tx pgx.Tx, r *Rule) ([]fired, error) {
	wm, ok, err := watermark(ctx, tx, r.ID, "wm:alerts", `SELECT instance, max(id) FROM openpicket.alerts GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, setState(ctx, tx, r.ID, "wm:alerts", wm)
	}
	b := &search.Builder{Now: e.cfg.Now}
	cond, err := e.alertWhere(r, b)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(wm)
	b.Args = append(b.Args, raw)
	rows, err := tx.Query(ctx, `SELECT a.instance, a.id, a.scenario, a.source_value, a.country, a.as_name, a.node_id, a.message, a.events_count
		FROM openpicket.alerts a WHERE a.id > COALESCE(($`+strconv.Itoa(len(b.Args))+`::jsonb ->> a.instance)::bigint, 0) AND `+cond+` ORDER BY a.id LIMIT 500`, b.Args...)
	if err != nil {
		return nil, err
	}
	var out []fired
	for rows.Next() {
		var (
			inst, scenario, value, cc, as, node, msg string
			id                                       int64
			events                                   int32
		)
		if err := rows.Scan(&inst, &id, &scenario, &value, &cc, &as, &node, &msg, &events); err != nil {
			rows.Close()
			return nil, err
		}
		wm[inst] = max(wm[inst], id)
		title := scenario + " from " + value
		if r.Type == CompromisedHost {
			title = "Compromised host " + value
		}
		body := fmt.Sprintf("%s\nScenario: %s\nSource: %s (%s, %s)\nNode: %s\nEvents: %d", msg, scenario, value, orDash(cc), orDash(as), orDash(node), events)
		out = append(out, fired{subject: value + "|" + scenario, title: title, body: body, link: "/alerts/" + inst + "/" + strconv.FormatInt(id, 10)})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, setState(ctx, tx, r.ID, "wm:alerts", wm)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (e *Engine) newDecisions(ctx context.Context, tx pgx.Tx, r *Rule) ([]fired, error) {
	wm, ok, err := watermark(ctx, tx, r.ID, "wm:decisions", `SELECT instance, max(id) FROM openpicket.alert_decisions GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, setState(ctx, tx, r.ID, "wm:decisions", wm)
	}
	b := &search.Builder{Now: e.cfg.Now}
	cond, err := e.alertWhere(r, b)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(wm)
	b.Args = append(b.Args, raw, e.cfg.Now())
	rows, err := tx.Query(ctx, `SELECT d.instance, d.id, d.type, d.value, d.scenario, d.origin, d.until, a.country, a.as_name, a.node_id
		FROM openpicket.alert_decisions d JOIN openpicket.alerts a ON a.instance = d.instance AND a.id = d.alert_id
		WHERE d.id > COALESCE(($`+strconv.Itoa(len(b.Args)-1)+`::jsonb ->> d.instance)::bigint, 0) AND d.until > $`+strconv.Itoa(len(b.Args))+`
		AND `+cond+` ORDER BY d.id LIMIT 500`, b.Args...)
	if err != nil {
		return nil, err
	}
	var filters []netip.Prefix
	for _, f := range r.IPFilters {
		p, _ := parsePrefix(f)
		filters = append(filters, p)
	}
	var out []fired
	for rows.Next() {
		var (
			inst, typ, value, scenario, origin, cc, as, node string
			id                                               int64
			until                                            time.Time
		)
		if err := rows.Scan(&inst, &id, &typ, &value, &scenario, &origin, &until, &cc, &as, &node); err != nil {
			rows.Close()
			return nil, err
		}
		wm[inst] = max(wm[inst], id)
		if r.Type == IPBan {
			if typ != "ban" || !matchesFilters(value, filters) {
				continue
			}
		}
		title := fmt.Sprintf("%s %s", strings.ToUpper(typ[:1])+typ[1:], value)
		body := fmt.Sprintf("Scenario: %s\nOrigin: %s\nUntil: %s\nSource: %s, %s\nNode: %s", scenario, origin, until.UTC().Format(time.RFC3339), orDash(cc), orDash(as), orDash(node))
		out = append(out, fired{subject: value, title: title, body: body, link: "/ip/" + value})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, setState(ctx, tx, r.ID, "wm:decisions", wm)
}

func matchesFilters(value string, filters []netip.Prefix) bool {
	if len(filters) == 0 {
		return true
	}
	p, err := parsePrefix(value)
	if err != nil {
		return false
	}
	for _, f := range filters {
		if f.Overlaps(p) && f.Bits() <= p.Bits() {
			return true
		}
	}
	return false
}

func (e *Engine) counts(ctx context.Context, tx pgx.Tx, r *Rule) ([]fired, error) {
	b := &search.Builder{Now: e.cfg.Now}
	cond, err := e.alertWhere(r, b)
	if err != nil {
		return nil, err
	}
	now := e.cfg.Now()
	window := time.Duration(r.WindowSeconds) * time.Second
	count := func(from, to time.Time) (int64, error) {
		args := append(append([]any{}, b.Args...), from, to)
		var n int64
		err := tx.QueryRow(ctx, `SELECT count(*) FROM openpicket.alerts a WHERE `+cond+` AND a.created_at >= $`+strconv.Itoa(len(args)-1)+
			` AND a.created_at <= $`+strconv.Itoa(len(args)), args...).Scan(&n)
		return n, err
	}
	cur, err := count(now.Add(-window), now)
	if err != nil {
		return nil, err
	}
	q := r.Query
	if q == "" {
		q = "all alerts"
	}
	link := "/alerts?q=" + urlQuery(r.Query)
	switch r.Type {
	case AlertThreshold:
		if cur >= int64(r.Threshold) {
			return []fired{{subject: "threshold", title: fmt.Sprintf("%d alerts in %s", cur, window),
				body: fmt.Sprintf("%d alerts matching %q in the last %s (threshold %d).", cur, q, window, r.Threshold), link: link}}, nil
		}
	case AlertSpike:
		const baselineWindows = 6
		prev, err := count(now.Add(-window*(baselineWindows+1)), now.Add(-window))
		if err != nil {
			return nil, err
		}
		avg := float64(prev) / baselineWindows
		if cur >= int64(r.Threshold) && float64(cur) >= r.SpikeFactor*avg {
			return []fired{{subject: "spike", title: fmt.Sprintf("Alert spike: %d in %s", cur, window),
				body: fmt.Sprintf("%d alerts matching %q in the last %s, against %.1f on average before.", cur, q, window, avg), link: link}}, nil
		}
	}
	return nil, nil
}

func urlQuery(s string) string {
	r := strings.NewReplacer("%", "%25", "&", "%26", "#", "%23", " ", "%20", "+", "%2B", "?", "%3F")
	return r.Replace(s)
}

func (e *Engine) lapiDown(ctx context.Context, tx pgx.Tx) ([]fired, error) {
	rows, err := tx.Query(ctx, `SELECT instance, url, last_error, last_poll_at FROM openpicket.alert_sync`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fired
	now := e.cfg.Now()
	for rows.Next() {
		var (
			inst, u, lastErr string
			poll             *time.Time
		)
		if err := rows.Scan(&inst, &u, &lastErr, &poll); err != nil {
			return nil, err
		}
		switch {
		case lastErr != "":
			out = append(out, fired{subject: inst, title: "LAPI " + inst + " is unavailable", body: u + ": " + lastErr, link: "/system"})
		case poll == nil || now.Sub(*poll) > 5*time.Minute:
			out = append(out, fired{subject: inst, title: "LAPI " + inst + " is not synced", body: u + ": no successful sync for 5 minutes", link: "/system"})
		}
	}
	return out, rows.Err()
}

func (e *Engine) nodesOffline(ctx context.Context, tx pgx.Tx, r *Rule) ([]fired, error) {
	now := e.cfg.Now()
	rows, err := tx.Query(ctx, `SELECT n.id, n.dp_last_seen_at, s.heartbeat_at FROM openpicket.nodes n
		LEFT JOIN openpicket.node_sessions s ON s.node_id = n.id WHERE n.enabled AND n.dp_last_seen_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	type st struct {
		id      string
		seen    time.Time
		offline bool
	}
	var nodes []st
	for rows.Next() {
		var (
			id   string
			seen time.Time
			hb   *time.Time
		)
		if err := rows.Scan(&id, &seen, &hb); err != nil {
			rows.Close()
			return nil, err
		}
		last := seen
		if hb != nil && hb.After(last) {
			last = *hb
		}
		nodes = append(nodes, st{id: id, seen: last, offline: now.Sub(last) > time.Duration(r.WindowSeconds)*time.Second})
	}
	rows.Close()
	var out []fired
	for _, n := range nodes {
		key := "offline:" + n.id
		var was bool
		if _, err := getState(ctx, tx, r.ID, key, &was); err != nil {
			return nil, err
		}
		switch {
		case n.offline && !was:
			if err := setState(ctx, tx, r.ID, key, true); err != nil {
				return nil, err
			}
			out = append(out, fired{subject: n.id, title: "Node " + n.id + " is offline",
				body: "No data plane contact since " + n.seen.UTC().Format(time.RFC3339) + ".", link: "/nodes/" + n.id})
		case !n.offline && was:
			if err := delState(ctx, tx, r.ID, key); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func (e *Engine) policyErrors(ctx context.Context, tx pgx.Tx) ([]fired, error) {
	rows, err := tx.Query(ctx, `SELECT node_id, 'decisions', error FROM openpicket.node_decision_state WHERE error <> ''
		UNION ALL SELECT node_id, 'port policies', error FROM openpicket.node_policy_state WHERE error <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fired
	for rows.Next() {
		var node, what, msg string
		if err := rows.Scan(&node, &what, &msg); err != nil {
			return nil, err
		}
		out = append(out, fired{subject: node + "|" + what, title: "Node " + node + " could not apply " + what, body: msg, link: "/nodes/" + node})
	}
	return out, rows.Err()
}

// MaxAttempts of a delivery.
const MaxAttempts = 5

// Deliver sends pending deliveries.
func (e *Engine) Deliver(ctx context.Context) error {
	dests, err := e.store.Destinations(ctx)
	if err != nil {
		return err
	}
	byID := map[string]*Destination{}
	for _, d := range dests {
		byID[d.ID] = d
	}
	rows, err := e.cfg.DB.Query(ctx, `SELECT d.notification_id, d.destination_id, d.attempts, n.time, n.rule_name, n.severity, n.title, n.body, n.subject, n.link
		FROM openpicket.notify_deliveries d JOIN openpicket.notifications n ON n.id = d.notification_id
		WHERE d.status = 'pending' AND d.next_at <= $1 ORDER BY d.next_at LIMIT 50`, e.cfg.Now())
	if err != nil {
		return err
	}
	type job struct {
		dest     string
		attempts int
		msg      Message
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.msg.ID, &j.dest, &j.attempts, &j.msg.Time, &j.msg.Rule, &j.msg.Severity, &j.msg.Title, &j.msg.Body, &j.msg.Subject, &j.msg.Link); err != nil {
			rows.Close()
			return err
		}
		if j.msg.Link != "" && e.cfg.PublicURL != "" {
			j.msg.Link = strings.TrimRight(e.cfg.PublicURL, "/") + j.msg.Link
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	for _, j := range jobs {
		d := byID[j.dest]
		var sendErr error
		if d == nil || !d.Enabled {
			sendErr = errors.New("destination removed or disabled")
			j.attempts = MaxAttempts - 1
		} else {
			sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			sendErr = e.cfg.Sender.Send(sctx, d, &j.msg)
			cancel()
		}
		attempts := j.attempts + 1
		status, msg, next := "sent", "", e.cfg.Now()
		if sendErr != nil {
			msg = sendErr.Error()
			status = "pending"
			next = e.cfg.Now().Add(time.Duration(30<<j.attempts) * time.Second)
			if attempts >= MaxAttempts {
				status = "failed"
			}
			e.log.Warn("notification delivery", "destination", j.dest, "attempt", attempts, "err", sendErr)
		}
		if _, err := e.cfg.DB.Exec(ctx, `UPDATE openpicket.notify_deliveries SET status = $3, attempts = $4, error = $5, next_at = $6, updated_at = now()
			WHERE notification_id = $1 AND destination_id = $2`, j.msg.ID, j.dest, status, attempts, msg, next); err != nil {
			return err
		}
	}
	// Keep 90 days of notifications.
	_, err = e.cfg.DB.Exec(ctx, `DELETE FROM openpicket.notifications WHERE time < $1`, e.cfg.Now().Add(-90*24*time.Hour))
	return err
}

// Test sends a test message to d.
func (e *Engine) Test(ctx context.Context, d *Destination) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	link := ""
	if e.cfg.PublicURL != "" {
		link = strings.TrimRight(e.cfg.PublicURL, "/") + "/notifications"
	}
	return e.cfg.Sender.Send(ctx, d, &Message{Time: e.cfg.Now(), Rule: "test", Severity: "info", Title: "OpenPicket test notification",
		Body: "This destination works.", Subject: "test", Link: link})
}
