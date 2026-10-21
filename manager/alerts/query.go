package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/manager/search"
)

const decisionExists = "EXISTS (SELECT 1 FROM openpicket.alert_decisions d WHERE d.instance = a.instance AND d.alert_id = a.id AND %s)"

// AlertSchema is the search schema of alerts (table alias a).
var AlertSchema = &search.Schema{
	Fields: map[string]search.Field{
		"value":       {SQL: "a.source_value"},
		"ip":          {SQL: "a.source_value"},
		"source":      {SQL: "a.source_value"},
		"scope":       {SQL: "a.source_scope", NoFreeText: true},
		"scenario":    {SQL: "a.scenario"},
		"message":     {SQL: "a.message"},
		"country":     {SQL: "a.country"},
		"cn":          {SQL: "a.country"},
		"as":          {SQL: "a.as_name"},
		"as_name":     {SQL: "a.as_name"},
		"asn":         {SQL: "a.as_number"},
		"node":        {SQL: "a.node_id"},
		"direction":   {SQL: "a.direction", NoFreeText: true},
		"machine":     {SQL: "a.machine_id", NoFreeText: true},
		"instance":    {SQL: "a.instance", NoFreeText: true},
		"target":      {SQL: "(a.meta->'dst_ip'->>0)"},
		"dst_ip":      {SQL: "(a.meta->'dst_ip'->>0)"},
		"port":        {SQL: "(a.meta->'dst_port'->>0)", NoFreeText: true},
		"signature":   {SQL: "(a.meta->'alert_signature'->>0)"},
		"events":      {SQL: "a.events_count", Kind: search.Number},
		"id":          {SQL: "a.id", Kind: search.Number},
		"created":     {SQL: "a.created_at", Kind: search.Time},
		"date":        {SQL: "a.created_at", Kind: search.Time},
		"start":       {SQL: "a.start_at", Kind: search.Time},
		"stop":        {SQL: "a.stop_at", Kind: search.Time},
		"simulated":   {SQL: "a.simulated", Kind: search.Bool},
		"remediation": {SQL: "a.remediation", Kind: search.Bool},
		"origin":      {SQL: "d.origin", Exists: decisionExists},
		"type":        {SQL: "d.type", Exists: decisionExists},
		"decision":    {SQL: "d.value", Exists: decisionExists},
		"active":      {SQL: "(d.until > now())", Kind: search.Bool, Exists: decisionExists},
	},
	Prefixes: map[string]string{"meta.": "a.meta"},
}

// DecisionSchema is the search schema of decisions (d joined with its
// alert a).
var DecisionSchema = &search.Schema{
	Fields: map[string]search.Field{
		"value":     {SQL: "d.value"},
		"ip":        {SQL: "d.value"},
		"scope":     {SQL: "d.scope", NoFreeText: true},
		"type":      {SQL: "d.type", NoFreeText: true},
		"action":    {SQL: "d.type", NoFreeText: true},
		"status":    {SQL: "(CASE WHEN d.until > now() THEN 'active' ELSE 'expired' END)", NoFreeText: true},
		"origin":    {SQL: "d.origin"},
		"scenario":  {SQL: "d.scenario"},
		"until":     {SQL: "d.until", Kind: search.Time},
		"instance":  {SQL: "d.instance", NoFreeText: true},
		"alert":     {SQL: "d.alert_id", Kind: search.Number},
		"id":        {SQL: "d.id", Kind: search.Number},
		"country":   {SQL: "a.country"},
		"as":        {SQL: "a.as_name"},
		"node":      {SQL: "a.node_id"},
		"simulated": {SQL: "d.simulated", Kind: search.Bool},
		"active":    {SQL: "(d.until > now())", Kind: search.Bool},
	},
}

// Querier reads the copy.
type Querier struct {
	DB  *pgxpool.Pool
	Now func() time.Time
}

func (q *Querier) now() time.Time {
	if q.Now != nil {
		return q.Now()
	}
	return time.Now()
}

// ErrQuery wraps search errors (invalid argument).
var ErrQuery = errors.New("invalid query")

// Filter is the common part of alert queries.
type Filter struct {
	Query            string
	From, To         time.Time
	Instance         string
	IncludeSimulated bool
}

// where compiles a filter; skip drops the query clauses on a field (facets).
func (q *Querier) where(f Filter, skip string, b *search.Builder) (string, error) {
	n, err := search.Parse(f.Query)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrQuery, err)
	}
	if skip != "" {
		n = search.WithoutField(n, skip)
	}
	cond, err := AlertSchema.SQL(n, b)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrQuery, err)
	}
	parts := []string{"(" + cond + ")"}
	if !f.From.IsZero() {
		b.Args = append(b.Args, f.From)
		parts = append(parts, "a.created_at >= $"+strconv.Itoa(len(b.Args)))
	}
	if !f.To.IsZero() {
		b.Args = append(b.Args, f.To)
		parts = append(parts, "a.created_at < $"+strconv.Itoa(len(b.Args)))
	}
	if f.Instance != "" {
		b.Args = append(b.Args, f.Instance)
		parts = append(parts, "a.instance = $"+strconv.Itoa(len(b.Args)))
	}
	if !f.IncludeSimulated && !mentions(n, "simulated") {
		parts = append(parts, "NOT a.simulated")
	}
	return strings.Join(parts, " AND "), nil
}

func mentions(n search.Node, field string) bool {
	for _, f := range search.Fields(n) {
		if f == field {
			return true
		}
	}
	return false
}

const alertColumns = `a.instance, a.id, a.uuid, a.scenario, a.message, a.source_scope, a.source_value, a.source_ip, a.source_range, a.country,
	a.as_number, a.as_name, a.latitude, a.longitude, a.events_count, a.simulated, a.remediation, a.machine_id, a.start_at, a.stop_at,
	a.created_at, a.meta, a.node_id, a.direction,
	COALESCE((SELECT jsonb_agg(jsonb_build_object('id', d.id, 'type', d.type, 'scope', d.scope, 'value', d.value, 'origin', d.origin,
		'scenario', d.scenario, 'until', d.until) ORDER BY d.id) FROM openpicket.alert_decisions d WHERE d.instance = a.instance AND d.alert_id = a.id), '[]')`

func (q *Querier) scanAlert(row pgx.Row) (*apiv1.Alert, error) {
	var (
		a                  apiv1.Alert
		src                apiv1.Source
		start, stop        *time.Time
		created            time.Time
		meta, decisions    []byte
		simulated, remedia bool
	)
	if err := row.Scan(&a.Instance, &a.Id, &a.Uuid, &a.Scenario, &a.Message, &src.Scope, &src.Value, &src.Ip, &src.Range, &src.Country,
		&src.AsNumber, &src.AsName, &src.Latitude, &src.Longitude, &a.EventsCount, &simulated, &remedia, &a.MachineId, &start, &stop,
		&created, &meta, &a.NodeId, &a.Direction, &decisions); err != nil {
		return nil, err
	}
	a.Source, a.Simulated, a.Remediation = &src, simulated, remedia
	a.StartAt, a.StopAt, a.CreatedAt = ts(start), ts(stop), timestamppb.New(created)
	var m map[string][]string
	_ = json.Unmarshal(meta, &m)
	for _, k := range sortedKeys(m) {
		a.Meta = append(a.Meta, &apiv1.MetaValue{Key: k, Values: m[k]})
	}
	var ds []struct {
		ID       int64     `json:"id"`
		Type     string    `json:"type"`
		Scope    string    `json:"scope"`
		Value    string    `json:"value"`
		Origin   string    `json:"origin"`
		Scenario string    `json:"scenario"`
		Until    time.Time `json:"until"`
	}
	_ = json.Unmarshal(decisions, &ds)
	now := q.now()
	for _, d := range ds {
		a.Decisions = append(a.Decisions, &apiv1.AlertDecision{Id: d.ID, Type: d.Type, Scope: d.Scope, Value: d.Value, Origin: d.Origin,
			Scenario: d.Scenario, Until: timestamppb.New(d.Until), Active: d.Until.After(now)})
	}
	return &a, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func clampLimit(n int32, def, max int) int {
	if n <= 0 {
		return def
	}
	if int(n) > max {
		return max
	}
	return int(n)
}

// Search lists alerts.
func (q *Querier) Search(ctx context.Context, f Filter, limit, offset int32, orderBy string, asc bool) ([]*apiv1.Alert, int64, error) {
	b := &search.Builder{Now: q.now}
	where, err := q.where(f, "", b)
	if err != nil {
		return nil, 0, err
	}
	order := map[string]string{"": "a.created_at", "created_at": "a.created_at", "events_count": "a.events_count", "scenario": "a.scenario"}[orderBy]
	if order == "" {
		return nil, 0, fmt.Errorf("%w: cannot order by %q", ErrQuery, orderBy)
	}
	dir := " DESC"
	if asc {
		dir = " ASC"
	}
	var total int64
	if err := q.DB.QueryRow(ctx, `SELECT count(*) FROM openpicket.alerts a WHERE `+where, b.Args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args := append(b.Args, clampLimit(limit, 100, 1000), max(offset, 0))
	rows, err := q.DB.Query(ctx, fmt.Sprintf(`SELECT %s FROM openpicket.alerts a WHERE %s ORDER BY %s%s, a.id%s LIMIT $%d OFFSET $%d`,
		alertColumns, where, order, dir, dir, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*apiv1.Alert
	for rows.Next() {
		a, err := q.scanAlert(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// Get returns one alert and its events (JSON).
func (q *Querier) Get(ctx context.Context, instance string, id int64) (*apiv1.Alert, string, error) {
	row := q.DB.QueryRow(ctx, `SELECT `+alertColumns+`, a.events FROM openpicket.alerts a WHERE a.instance = $1 AND a.id = $2`, instance, id)
	var events []byte
	a, err := q.scanAlert(rowWithExtra{row, &events})
	if err != nil {
		return nil, "", err
	}
	return a, string(events), nil
}

// rowWithExtra appends destinations to a Scan.
type rowWithExtra struct {
	row   pgx.Row
	extra any
}

func (r rowWithExtra) Scan(dest ...any) error { return r.row.Scan(append(dest, r.extra)...) }

// facetColumns are the facet fields.
var facetColumns = map[string]string{
	"scenario":  "a.scenario",
	"country":   "a.country",
	"as_name":   "a.as_name",
	"node":      "a.node_id",
	"direction": "a.direction",
	"machine":   "a.machine_id",
	"value":     "a.source_value",
	"target":    "(a.meta->'dst_ip'->>0)",
	"instance":  "a.instance",
}

// facetSkip maps a facet to the query fields it ignores.
var facetSkip = map[string]string{"as_name": "as", "value": "value", "node": "node"}

// Facets counts alerts per value of each field.
func (q *Querier) Facets(ctx context.Context, f Filter, fields []string, prefix string, limit int32) ([]*apiv1.Facet, error) {
	if len(fields) == 0 {
		fields = []string{"scenario", "country", "as_name", "node", "direction", "origin"}
	}
	var out []*apiv1.Facet
	for _, field := range fields {
		skip := field
		if s, ok := facetSkip[field]; ok {
			skip = s
		}
		b := &search.Builder{Now: q.now}
		where, err := q.where(f, skip, b)
		if err != nil {
			return nil, err
		}
		var sql string
		if field == "origin" {
			sql = `SELECT d.origin AS v, count(DISTINCT (a.instance, a.id)) FROM openpicket.alerts a
				JOIN openpicket.alert_decisions d ON d.instance = a.instance AND d.alert_id = a.id WHERE ` + where
		} else {
			col, ok := facetColumns[field]
			if !ok {
				return nil, fmt.Errorf("%w: no facet %q", ErrQuery, field)
			}
			sql = `SELECT COALESCE(` + col + `, '') AS v, count(*) FROM openpicket.alerts a WHERE ` + where
		}
		if prefix != "" {
			b.Args = append(b.Args, prefix+"%")
			sql = `SELECT * FROM (` + sql + ` GROUP BY 1) f WHERE v ILIKE $` + strconv.Itoa(len(b.Args))
		} else {
			sql += ` GROUP BY 1`
		}
		b.Args = append(b.Args, clampLimit(limit, 10, 200))
		sql += ` ORDER BY 2 DESC, 1 LIMIT $` + strconv.Itoa(len(b.Args))
		vals, err := q.counts(ctx, sql, b.Args...)
		if err != nil {
			return nil, err
		}
		out = append(out, &apiv1.Facet{Field: field, Values: vals})
	}
	return out, nil
}

func (q *Querier) counts(ctx context.Context, sql string, args ...any) ([]*apiv1.FacetValue, error) {
	rows, err := q.DB.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*apiv1.FacetValue
	for rows.Next() {
		var v apiv1.FacetValue
		if err := rows.Scan(&v.Value, &v.Count); err != nil {
			return nil, err
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

// DecisionFilter selects decisions.
type DecisionFilter struct {
	Query          string
	IncludeExpired bool
	HideDuplicates bool
	Instance       string
}

// Decisions lists decisions, active first by until.
func (q *Querier) Decisions(ctx context.Context, f DecisionFilter, limit, offset int32) ([]*apiv1.Decision, int64, error) {
	n, err := search.Parse(f.Query)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrQuery, err)
	}
	b := &search.Builder{Now: q.now}
	cond, err := DecisionSchema.SQL(n, b)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrQuery, err)
	}
	parts := []string{"(" + cond + ")"}
	if !f.IncludeExpired {
		b.Args = append(b.Args, q.now())
		parts = append(parts, "d.until > $"+strconv.Itoa(len(b.Args)))
	}
	if f.Instance != "" {
		b.Args = append(b.Args, f.Instance)
		parts = append(parts, "d.instance = $"+strconv.Itoa(len(b.Args)))
	}
	where := strings.Join(parts, " AND ")
	inner := `SELECT d.instance, d.id, d.type, d.scope, d.value, d.origin, d.scenario, d.until, d.alert_id, a.country, a.as_name,
		COALESCE(e.direction, '') AS edge_direction
		FROM openpicket.alert_decisions d JOIN openpicket.alerts a ON a.instance = d.instance AND a.id = d.alert_id
		LEFT JOIN openpicket.edge_decisions e ON e.value = d.value AND NOT e.deleted WHERE ` + where
	if f.HideDuplicates {
		inner = `SELECT DISTINCT ON (value) * FROM (` + inner + `) x ORDER BY value, until DESC, id DESC`
	}
	var total int64
	if err := q.DB.QueryRow(ctx, `SELECT count(*) FROM (`+inner+`) c`, b.Args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args := append(b.Args, clampLimit(limit, 100, 1000), max(offset, 0))
	rows, err := q.DB.Query(ctx, fmt.Sprintf(`SELECT * FROM (%s) r ORDER BY until DESC, id DESC LIMIT $%d OFFSET $%d`, inner, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	now := q.now()
	var out []*apiv1.Decision
	for rows.Next() {
		var (
			d     apiv1.Decision
			until time.Time
		)
		if err := rows.Scan(&d.Instance, &d.Id, &d.Type, &d.Scope, &d.Value, &d.Origin, &d.Scenario, &until, &d.AlertId, &d.Country, &d.AsName, &d.EdgeDirection); err != nil {
			return nil, 0, err
		}
		d.Until, d.Active = timestamppb.New(until), until.After(now)
		out = append(out, &d)
	}
	return out, total, rows.Err()
}

// ActiveDecisionIDs returns the ids of active decisions of a value per
// instance.
func (q *Querier) ActiveDecisionIDs(ctx context.Context, instance, value string) (map[string][]int64, error) {
	rows, err := q.DB.Query(ctx, `SELECT instance, id FROM openpicket.alert_decisions WHERE ($1 = '' OR instance = $1) AND value = $2 AND until > $3`,
		instance, value, q.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]int64{}
	for rows.Next() {
		var (
			inst string
			id   int64
		)
		if err := rows.Scan(&inst, &id); err != nil {
			return nil, err
		}
		out[inst] = append(out[inst], id)
	}
	return out, rows.Err()
}

// Summary computes the dashboard.
func (q *Querier) Summary(ctx context.Context, f Filter) (*apiv1.GetSummaryResponse, error) {
	if f.To.IsZero() {
		f.To = q.now()
	}
	if f.From.IsZero() {
		f.From = f.To.Add(-24 * time.Hour)
	}
	b := &search.Builder{Now: q.now}
	where, err := q.where(f, "", b)
	if err != nil {
		return nil, err
	}
	res := &apiv1.GetSummaryResponse{}
	args := b.Args
	if err := q.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE a.simulated),
		count(DISTINCT a.source_value) FILTER (WHERE a.source_scope = 'openpicket_host') FROM openpicket.alerts a WHERE `+where, args...).
		Scan(&res.Alerts, &res.SimulatedAlerts, &res.CompromisedHosts); err != nil {
		return nil, err
	}
	if err := q.DB.QueryRow(ctx, `SELECT count(DISTINCT value) FROM openpicket.alert_decisions WHERE until > $1 AND NOT simulated`, q.now()).
		Scan(&res.ActiveDecisions); err != nil {
		return nil, err
	}
	bucket := "hour"
	if f.To.Sub(f.From) > 3*24*time.Hour {
		bucket = "day"
	}
	rows, err := q.DB.Query(ctx, `SELECT date_trunc('`+bucket+`', a.created_at) AS t, count(*),
		count(*) FILTER (WHERE EXISTS (SELECT 1 FROM openpicket.alert_decisions d WHERE d.instance = a.instance AND d.alert_id = a.id))
		FROM openpicket.alerts a WHERE `+where+` GROUP BY 1 ORDER BY 1`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var (
			t  time.Time
			tb apiv1.TimeBucket
		)
		if err := rows.Scan(&t, &tb.Alerts, &tb.Decisions); err != nil {
			rows.Close()
			return nil, err
		}
		tb.Start = timestamppb.New(t)
		res.Series = append(res.Series, &tb)
	}
	rows.Close()
	top := func(col string, n int) ([]*apiv1.FacetValue, error) {
		return q.counts(ctx, `SELECT `+col+`, count(*) FROM openpicket.alerts a WHERE `+where+` AND `+col+` <> '' GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT `+strconv.Itoa(n), args...)
	}
	for _, t := range []struct {
		col string
		n   int
		dst *[]*apiv1.FacetValue
	}{
		{"a.country", 10, &res.TopCountries}, {"a.scenario", 10, &res.TopScenarios}, {"a.as_name", 10, &res.TopAs},
		{"a.node_id", 10, &res.TopNodes}, {"a.source_value", 10, &res.TopSources},
	} {
		if *t.dst, err = top(t.col, t.n); err != nil {
			return nil, err
		}
	}
	countries, err := top("a.country", 250)
	if err != nil {
		return nil, err
	}
	for _, c := range countries {
		res.Map = append(res.Map, &apiv1.MapPoint{Country: c.Value, Count: c.Count})
	}
	if err := q.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE s.heartbeat_at > $1) FROM openpicket.nodes n
		LEFT JOIN openpicket.node_sessions s ON s.node_id = n.id`, q.now().Add(-90*time.Second)).Scan(&res.NodesTotal, &res.NodesOnline); err != nil {
		return nil, err
	}
	return res, nil
}

// Propagation reports how the edge decision of a value reached the nodes
// and whether each node has it in force.
func (q *Querier) Propagation(ctx context.Context, value string) (*apiv1.GetPropagationResponse, error) {
	res := &apiv1.GetPropagationResponse{}
	var (
		version int64
		until   time.Time
	)
	// The value itself, or a range containing it: the one blocking the
	// longest is what holds the value in the kernel.
	err := q.DB.QueryRow(ctx, `SELECT value, direction, version, until FROM openpicket.edge_decisions
		WHERE value = ANY($1) AND NOT deleted ORDER BY until DESC, direction = 'both' DESC, value LIMIT 1`, covering(value)).
		Scan(&res.EdgeValue, &res.Direction, &version, &until)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return nil, err
	default:
		res.AtEdge, res.Version, res.Until = true, uint64(version), timestamppb.New(until)
	}
	rows, err := q.DB.Query(ctx, `SELECT n.id, COALESCE(st.version, 0), COALESCE(st.error, ''), st.acked_at, s.heartbeat_at, s.status FROM openpicket.nodes n
		LEFT JOIN openpicket.node_decision_state st ON st.node_id = n.id LEFT JOIN openpicket.node_sessions s ON s.node_id = n.id ORDER BY n.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			np        apiv1.NodePropagation
			v         int64
			acked, hb *time.Time
			status    []byte
		)
		if err := rows.Scan(&np.NodeId, &v, &np.Error, &acked, &hb, &status); err != nil {
			return nil, err
		}
		np.AckedVersion, np.AckedAt = uint64(v), ts(acked)
		np.Connected = hb != nil && q.now().Sub(*hb) < 90*time.Second
		received := version > 0 && v >= version && np.Error == ""
		if received {
			np.Refused, np.MaybeRefused = refusal(status, res.EdgeValue)
		}
		np.Applied = received && np.Refused == ""
		res.Nodes = append(res.Nodes, &np)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	query := `value="` + strings.ReplaceAll(value, `"`, ``) + `"`
	if res.EdgeValue != "" && res.EdgeValue != value {
		query += ` OR value="` + res.EdgeValue + `"`
	}
	ds, _, err := q.Decisions(ctx, DecisionFilter{Query: query, IncludeExpired: true}, 50, 0)
	if err != nil {
		return nil, err
	}
	res.Decisions = ds
	return res, nil
}

// covering returns the edge values that block value: itself and every
// range containing it, in their canonical forms (relay.Normalize).
func covering(value string) []string {
	out := []string{value}
	var p netip.Prefix
	if a, err := netip.ParseAddr(value); err == nil {
		a = a.Unmap()
		out[0] = a.String()
		p = netip.PrefixFrom(a, a.BitLen())
	} else if pp, err := netip.ParsePrefix(value); err == nil {
		p = pp.Masked()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
		}
		out[0] = p.String()
	} else {
		return out
	}
	for bits := p.Bits(); bits >= 0; bits-- {
		r, _ := p.Addr().Prefix(bits)
		out = append(out, r.String())
	}
	return out
}

// refusal reads a node's status report for why it does not apply value.
func refusal(status []byte, value string) (string, bool) {
	st := &dataplanev1.Status{}
	if len(status) == 0 || proto.Unmarshal(status, st) != nil {
		return "", false
	}
	enf := st.GetEnforcer()
	if !enf.GetEnabled() {
		return "ban enforcer disabled on this node", false
	}
	for _, r := range enf.GetRefused() {
		if r.GetValue() == value {
			return r.GetReason(), false
		}
	}
	return "", enf.GetRejected() > uint64(len(enf.GetRefused()))
}
