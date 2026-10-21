package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/auth"
	"github.com/openpicket/openpicket/manager/settings"
)

type systemService struct{ s *Server }

func (y *systemService) GetLogPolicy(ctx context.Context, _ *connect.Request[apiv1.GetLogPolicyRequest]) (*connect.Response[apiv1.GetLogPolicyResponse], error) {
	p := &agentv1.LogCollectionPolicy{}
	ok, err := y.s.cfg.Settings.Get(ctx, settings.KeyLogPolicy, p)
	if err != nil {
		return nil, toConnectError(err)
	}
	if !ok {
		p = settings.DefaultLogPolicy()
	}
	return connect.NewResponse(&apiv1.GetLogPolicyResponse{Policy: p, IsDefault: !ok}), nil
}

func (y *systemService) SetLogPolicy(ctx context.Context, req *connect.Request[apiv1.SetLogPolicyRequest]) (*connect.Response[apiv1.SetLogPolicyResponse], error) {
	var err error
	switch {
	case req.Msg.GetReset_():
		err = y.s.cfg.Settings.Delete(ctx, settings.KeyLogPolicy)
	case req.Msg.GetPolicy() == nil:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("policy is required"))
	default:
		err = y.s.cfg.Settings.Put(ctx, settings.KeyLogPolicy, req.Msg.GetPolicy())
	}
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.SetLogPolicyResponse{}), nil
}

func (y *systemService) ListAudit(ctx context.Context, req *connect.Request[apiv1.ListAuditRequest]) (*connect.Response[apiv1.ListAuditResponse], error) {
	m := req.Msg
	limit := m.GetLimit()
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := y.s.cfg.DB.Query(ctx, `SELECT id, time, source, principal, action, target, detail FROM openpicket.audit
		WHERE ($1 = 0 OR id < $1) AND ($2 = '' OR principal = $2) AND ($3 = '' OR action LIKE $3 || '%') AND ($4 = '' OR target = $4)
		ORDER BY id DESC LIMIT $5`, m.GetBeforeId(), m.GetPrincipal(), m.GetActionPrefix(), m.GetTarget(), limit)
	if err != nil {
		return nil, toConnectError(err)
	}
	defer rows.Close()
	res := &apiv1.ListAuditResponse{}
	for rows.Next() {
		var (
			e apiv1.AuditEntry
			t time.Time
		)
		if err := rows.Scan(&e.Id, &t, &e.Source, &e.Principal, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, toConnectError(err)
		}
		e.Time = timestamppb.New(t)
		res.Entries = append(res.Entries, &e)
	}
	return connect.NewResponse(res), toConnectError(rows.Err())
}

var savedFilterPages = map[string]bool{"alerts": true, "decisions": true, "logs": true, "nodes": true}

func (y *systemService) ListSavedFilters(ctx context.Context, req *connect.Request[apiv1.ListSavedFiltersRequest]) (*connect.Response[apiv1.ListSavedFiltersResponse], error) {
	rows, err := y.s.cfg.DB.Query(ctx, `SELECT id, page, name, query, state, shared, owner, created_at FROM openpicket.saved_filters
		WHERE ($1 = '' OR page = $1) AND (owner = $2 OR shared) ORDER BY name, id`, req.Msg.GetPage(), by(ctx))
	if err != nil {
		return nil, toConnectError(err)
	}
	defer rows.Close()
	res := &apiv1.ListSavedFiltersResponse{}
	for rows.Next() {
		var (
			f     apiv1.SavedFilter
			state []byte
			t     time.Time
		)
		if err := rows.Scan(&f.Id, &f.Page, &f.Name, &f.Query, &state, &f.Shared, &f.Owner, &t); err != nil {
			return nil, toConnectError(err)
		}
		f.StateJson, f.CreatedAt = string(state), timestamppb.New(t)
		res.Filters = append(res.Filters, &f)
	}
	return connect.NewResponse(res), toConnectError(rows.Err())
}

func (y *systemService) SaveFilter(ctx context.Context, req *connect.Request[apiv1.SaveFilterRequest]) (*connect.Response[apiv1.SaveFilterResponse], error) {
	f := req.Msg.GetFilter()
	switch {
	case f == nil || f.GetName() == "" || len(f.GetName()) > 100:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a name of 1-100 characters is required"))
	case !savedFilterPages[f.GetPage()]:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unknown page %q", f.GetPage()))
	case len(f.GetQuery()) > 4096 || len(f.GetStateJson()) > 16<<10:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("filter too large"))
	}
	p := auth.FromContext(ctx)
	if f.GetShared() && !p.Has(auth.RoleOperator) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("sharing filters requires the operator role"))
	}
	state := []byte(f.GetStateJson())
	if len(state) == 0 {
		state = []byte("{}")
	}
	if !json.Valid(state) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("state_json is not valid JSON"))
	}
	owner := by(ctx)
	id := f.GetId()
	if id == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		id = hex.EncodeToString(b)
	}
	var t time.Time
	// Only the owner replaces a filter.
	err := y.s.cfg.DB.QueryRow(ctx, `INSERT INTO openpicket.saved_filters (id, owner, page, name, query, state, shared) VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (id) DO UPDATE SET page=excluded.page, name=excluded.name, query=excluded.query, state=excluded.state, shared=excluded.shared
		WHERE saved_filters.owner = excluded.owner RETURNING created_at`,
		id, owner, f.GetPage(), f.GetName(), f.GetQuery(), state, f.GetShared()).Scan(&t)
	if err != nil {
		return nil, toConnectError(fmt.Errorf("%w: filter belongs to another user", errNotFound))
	}
	out := &apiv1.SavedFilter{Id: id, Page: f.GetPage(), Name: f.GetName(), Query: f.GetQuery(), StateJson: string(state), Shared: f.GetShared(),
		Owner: owner, CreatedAt: timestamppb.New(t)}
	return connect.NewResponse(&apiv1.SaveFilterResponse{Filter: out}), nil
}

func (y *systemService) DeleteSavedFilter(ctx context.Context, req *connect.Request[apiv1.DeleteSavedFilterRequest]) (*connect.Response[apiv1.DeleteSavedFilterResponse], error) {
	// Admins may remove shared filters of others.
	tag, err := y.s.cfg.DB.Exec(ctx, `DELETE FROM openpicket.saved_filters WHERE id = $1 AND (owner = $2 OR (shared AND $3))`,
		req.Msg.GetId(), by(ctx), auth.FromContext(ctx).Has(auth.RoleAdmin))
	if err != nil {
		return nil, toConnectError(err)
	}
	if tag.RowsAffected() == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("filter not found"))
	}
	return connect.NewResponse(&apiv1.DeleteSavedFilterResponse{}), nil
}

func (y *systemService) GetStatus(ctx context.Context, _ *connect.Request[apiv1.GetStatusRequest]) (*connect.Response[apiv1.GetStatusResponse], error) {
	res := &apiv1.GetStatusResponse{Version: y.s.cfg.Version, Replica: y.s.cfg.Replica}
	if y.s.cfg.Status != nil {
		res.Components = y.s.cfg.Status(ctx)
	}
	rows, err := y.s.cfg.DB.Query(ctx, `SELECT DISTINCT replica FROM openpicket.node_sessions WHERE heartbeat_at > now() - $1::interval
		UNION SELECT holder FROM openpicket.leader_epochs ORDER BY 1`, fmt.Sprintf("%d seconds", int(sessionTimeout.Seconds())))
	if err == nil {
		for rows.Next() {
			var r string
			if rows.Scan(&r) == nil {
				res.Replicas = append(res.Replicas, r)
			}
		}
		rows.Close()
	}
	return connect.NewResponse(res), nil
}

const maxRecent = 5

func (y *systemService) ListRecentQueries(ctx context.Context, req *connect.Request[apiv1.ListRecentQueriesRequest]) (*connect.Response[apiv1.ListRecentQueriesResponse], error) {
	rows, err := y.s.cfg.DB.Query(ctx, `SELECT query FROM openpicket.recent_queries WHERE owner = $1 AND page = $2 ORDER BY used_at DESC LIMIT $3`,
		by(ctx), req.Msg.GetPage(), maxRecent)
	if err != nil {
		return nil, toConnectError(err)
	}
	defer rows.Close()
	res := &apiv1.ListRecentQueriesResponse{}
	for rows.Next() {
		var q string
		if err := rows.Scan(&q); err != nil {
			return nil, toConnectError(err)
		}
		res.Queries = append(res.Queries, q)
	}
	return connect.NewResponse(res), toConnectError(rows.Err())
}

func (y *systemService) AddRecentQuery(ctx context.Context, req *connect.Request[apiv1.AddRecentQueryRequest]) (*connect.Response[apiv1.AddRecentQueryResponse], error) {
	m := req.Msg
	if !savedFilterPages[m.GetPage()] || m.GetQuery() == "" || len(m.GetQuery()) > 4096 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a page and a query of at most 4096 bytes are required"))
	}
	owner := by(ctx)
	if _, err := y.s.cfg.DB.Exec(ctx, `INSERT INTO openpicket.recent_queries (owner, page, query) VALUES ($1,$2,$3)
		ON CONFLICT (owner, page, query) DO UPDATE SET used_at = now()`, owner, m.GetPage(), m.GetQuery()); err != nil {
		return nil, toConnectError(err)
	}
	if _, err := y.s.cfg.DB.Exec(ctx, `DELETE FROM openpicket.recent_queries WHERE owner = $1 AND page = $2 AND query NOT IN
		(SELECT query FROM openpicket.recent_queries WHERE owner = $1 AND page = $2 ORDER BY used_at DESC LIMIT $3)`, owner, m.GetPage(), maxRecent); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.AddRecentQueryResponse{}), nil
}

// KeyUISettings stores apiv1.UISettings (protojson).
const KeyUISettings = "ui.settings"

// DefaultManualScenarios are offered in the Add Decision form.
var DefaultManualScenarios = []string{"openpicket/manual", "openpicket/manual-both", "manual/web-ui"}

func (y *systemService) GetUISettings(ctx context.Context, _ *connect.Request[apiv1.GetUISettingsRequest]) (*connect.Response[apiv1.GetUISettingsResponse], error) {
	var raw json.RawMessage
	st := &apiv1.UISettings{}
	ok, err := y.s.cfg.Settings.Get(ctx, KeyUISettings, &raw)
	if err != nil {
		return nil, toConnectError(err)
	}
	if ok {
		_ = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(raw, st)
	}
	if len(st.ManualScenarios) == 0 {
		st.ManualScenarios = DefaultManualScenarios
	}
	return connect.NewResponse(&apiv1.GetUISettingsResponse{Settings: st}), nil
}

func (y *systemService) SetUISettings(ctx context.Context, req *connect.Request[apiv1.SetUISettingsRequest]) (*connect.Response[apiv1.SetUISettingsResponse], error) {
	st := req.Msg.GetSettings()
	if st == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("settings are required"))
	}
	if len(st.ManualScenarios) > 50 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("at most 50 manual decision scenarios"))
	}
	for _, s := range st.ManualScenarios {
		if !scenarioRe.MatchString(s) {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid scenario %q", s))
		}
	}
	if st.TimeZone != "" {
		if _, err := time.LoadLocation(st.TimeZone); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unknown time zone %q", st.TimeZone))
		}
	}
	raw, _ := protojson.Marshal(st)
	if err := y.s.cfg.Settings.Put(ctx, KeyUISettings, json.RawMessage(raw)); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.SetUISettingsResponse{}), nil
}

func (y *systemService) ResyncAlerts(ctx context.Context, _ *connect.Request[apiv1.ResyncAlertsRequest]) (*connect.Response[apiv1.ResyncAlertsResponse], error) {
	if y.s.cfg.Resync == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no CrowdSec LAPI is configured"))
	}
	y.s.cfg.Resync()
	return connect.NewResponse(&apiv1.ResyncAlertsResponse{}), nil
}
