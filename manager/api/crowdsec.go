package api

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/alerts"
	"github.com/openpicket/openpicket/manager/auth"
	"github.com/openpicket/openpicket/manager/lapi"
)

// LAPI is one CrowdSec LAPI the API changes alerts and decisions on.
type LAPI struct {
	Name    string
	Watcher *lapi.Watcher
}

func (s *Server) lapis(instance string) ([]LAPI, error) {
	if len(s.cfg.LAPIs) == 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no CrowdSec LAPI is configured"))
	}
	if instance == "" {
		return s.cfg.LAPIs, nil
	}
	for _, l := range s.cfg.LAPIs {
		if l.Name == instance {
			return []LAPI{l}, nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("unknown LAPI instance %q", instance))
}

func (s *Server) querier() (*alerts.Querier, error) {
	if s.cfg.Alerts == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no CrowdSec LAPI is configured"))
	}
	return s.cfg.Alerts, nil
}

func (s *Server) changed(instance string) {
	if s.cfg.Poke != nil {
		s.cfg.Poke(instance)
	}
}

func queryError(err error) error {
	if errors.Is(err, alerts.ErrQuery) {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return toConnectError(err)
}

func timeOf(t interface{ AsTime() time.Time }, valid bool) time.Time {
	if !valid {
		return time.Time{}
	}
	return t.AsTime()
}

type alertService struct{ s *Server }

func (a *alertService) SearchAlerts(ctx context.Context, req *connect.Request[apiv1.SearchAlertsRequest]) (*connect.Response[apiv1.SearchAlertsResponse], error) {
	q, err := a.s.querier()
	if err != nil {
		return nil, err
	}
	m := req.Msg
	f := alerts.Filter{Query: m.GetQuery(), From: timeOf(m.GetFrom(), m.From != nil), To: timeOf(m.GetTo(), m.To != nil), Instance: m.GetInstance(),
		IncludeSimulated: m.GetIncludeSimulated()}
	list, total, err := q.Search(ctx, f, m.GetLimit(), m.GetOffset(), m.GetOrderBy(), m.GetAscending())
	if err != nil {
		return nil, queryError(err)
	}
	return connect.NewResponse(&apiv1.SearchAlertsResponse{Alerts: list, Total: total}), nil
}

func (a *alertService) GetAlert(ctx context.Context, req *connect.Request[apiv1.GetAlertRequest]) (*connect.Response[apiv1.GetAlertResponse], error) {
	q, err := a.s.querier()
	if err != nil {
		return nil, err
	}
	al, events, err := q.Get(ctx, req.Msg.GetInstance(), req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.GetAlertResponse{Alert: al, EventsJson: events}), nil
}

func (a *alertService) Facets(ctx context.Context, req *connect.Request[apiv1.FacetsRequest]) (*connect.Response[apiv1.FacetsResponse], error) {
	q, err := a.s.querier()
	if err != nil {
		return nil, err
	}
	m := req.Msg
	f := alerts.Filter{Query: m.GetQuery(), From: timeOf(m.GetFrom(), m.From != nil), To: timeOf(m.GetTo(), m.To != nil), Instance: m.GetInstance(),
		IncludeSimulated: m.GetIncludeSimulated()}
	facets, err := q.Facets(ctx, f, m.GetFields(), m.GetValuePrefix(), m.GetLimit())
	if err != nil {
		return nil, queryError(err)
	}
	return connect.NewResponse(&apiv1.FacetsResponse{Facets: facets}), nil
}

func (a *alertService) DeleteAlerts(ctx context.Context, req *connect.Request[apiv1.DeleteAlertsRequest]) (*connect.Response[apiv1.DeleteAlertsResponse], error) {
	ls, err := a.s.lapis(req.Msg.GetInstance())
	if err != nil {
		return nil, err
	}
	if req.Msg.GetInstance() == "" || len(ls) != 1 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("instance is required"))
	}
	res := &apiv1.DeleteAlertsResponse{}
	var done []int64
	for _, id := range req.Msg.GetIds() {
		if err := ls[0].Watcher.DeleteAlert(ctx, id); err != nil && !errors.Is(err, lapi.ErrNotFound) {
			res.Errors = append(res.Errors, &apiv1.InstanceError{Instance: ls[0].Name, Error: fmt.Sprintf("alert %d: %v", id, err)})
			continue
		}
		done = append(done, id)
	}
	res.Deleted = int64(len(done))
	if err := a.s.cfg.AlertStore.ForgetAlerts(ctx, ls[0].Name, done); err != nil {
		a.s.log.Warn("forget alerts", "err", err)
	}
	a.s.changed(ls[0].Name)
	return connect.NewResponse(res), nil
}

type decisionService struct{ s *Server }

func (d *decisionService) SearchDecisions(ctx context.Context, req *connect.Request[apiv1.SearchDecisionsRequest]) (*connect.Response[apiv1.SearchDecisionsResponse], error) {
	q, err := d.s.querier()
	if err != nil {
		return nil, err
	}
	m := req.Msg
	list, total, err := q.Decisions(ctx, alerts.DecisionFilter{Query: m.GetQuery(), IncludeExpired: m.GetIncludeExpired(), HideDuplicates: m.GetHideDuplicates(),
		Instance: m.GetInstance()}, m.GetLimit(), m.GetOffset())
	if err != nil {
		return nil, queryError(err)
	}
	return connect.NewResponse(&apiv1.SearchDecisionsResponse{Decisions: list, Total: total}), nil
}

var (
	durationRe = regexp.MustCompile(`^(\d+)(d|h|m|s)$`)
	scenarioRe = regexp.MustCompile(`^[A-Za-z0-9_.\-/ ]{1,128}$`)
)

// lapiDuration converts "30d" (not understood by LAPI) to hours.
func lapiDuration(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = "4h"
	}
	if m := durationRe.FindStringSubmatch(s); m != nil && m[2] == "d" {
		n, _ := strconv.Atoi(m[1])
		s = strconv.Itoa(n*24) + "h"
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < time.Minute || d > 10*365*24*time.Hour {
		return "", fmt.Errorf("%w: duration %q (1m to 10 years, e.g. 4h or 30d)", errInvalid, s)
	}
	return s, nil
}

func normalizeTarget(scope, value string) (string, string, error) {
	value = strings.TrimSpace(value)
	switch strings.ToLower(scope) {
	case "", "ip":
		a, err := netip.ParseAddr(value)
		if err != nil {
			return "", "", fmt.Errorf("%w: %q is not an IP address", errInvalid, value)
		}
		return "Ip", a.Unmap().String(), nil
	case "range":
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return "", "", fmt.Errorf("%w: %q is not a CIDR range", errInvalid, value)
		}
		if p.Bits() < 8 && p.Addr().Is4() || p.Bits() < 16 && p.Addr().Is6() {
			return "", "", fmt.Errorf("%w: range %s is too large", errInvalid, p)
		}
		return "Range", p.Masked().String(), nil
	case "country":
		if len(value) != 2 {
			return "", "", fmt.Errorf("%w: country must be an ISO code", errInvalid)
		}
		return "Country", strings.ToUpper(value), nil
	case "as":
		if _, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(value), "AS"), 10, 32); err != nil {
			return "", "", fmt.Errorf("%w: AS must be a number", errInvalid)
		}
		return "AS", strings.TrimPrefix(strings.ToUpper(value), "AS"), nil
	}
	return "", "", fmt.Errorf("%w: unknown scope %q", errInvalid, scope)
}

func (d *decisionService) AddDecision(ctx context.Context, req *connect.Request[apiv1.AddDecisionRequest]) (*connect.Response[apiv1.AddDecisionResponse], error) {
	m := req.Msg
	ls, err := d.s.lapis(m.GetInstance())
	if err != nil {
		return nil, err
	}
	scope, value, err := normalizeTarget(m.GetScope(), m.GetValue())
	if err != nil {
		return nil, toConnectError(err)
	}
	dur, err := lapiDuration(m.GetDuration())
	if err != nil {
		return nil, toConnectError(err)
	}
	typ := m.GetType()
	if typ == "" {
		typ = "ban"
	}
	if typ != "ban" && typ != "captcha" && typ != "throttle" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unknown decision type %q", typ))
	}
	scenario := m.GetScenario()
	if scenario == "" {
		scenario = "openpicket/manual"
	}
	if !scenarioRe.MatchString(scenario) || len(m.GetReason()) > 512 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid scenario or reason"))
	}
	who := auth.FromContext(ctx).Display()
	res := &apiv1.AddDecisionResponse{}
	for _, l := range ls {
		alert := lapi.ManualDecision(scope, value, typ, dur, scenario, m.GetReason(), who, d.s.cfg.Now())
		if _, err := l.Watcher.PushAlerts(ctx, []*lapi.Alert{alert}); err != nil {
			res.Errors = append(res.Errors, &apiv1.InstanceError{Instance: l.Name, Error: err.Error()})
		}
		d.s.changed(l.Name)
	}
	if len(res.Errors) == len(ls) {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New(res.Errors[0].Error))
	}
	return connect.NewResponse(res), nil
}

func (d *decisionService) DeleteDecisions(ctx context.Context, req *connect.Request[apiv1.DeleteDecisionsRequest]) (*connect.Response[apiv1.DeleteDecisionsResponse], error) {
	ls, err := d.s.lapis(req.Msg.GetInstance())
	if err != nil {
		return nil, err
	}
	if req.Msg.GetInstance() == "" || len(ls) != 1 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("instance is required"))
	}
	res := &apiv1.DeleteDecisionsResponse{}
	var done []int64
	for _, id := range req.Msg.GetIds() {
		n, err := ls[0].Watcher.DeleteDecision(ctx, id)
		if err != nil && !errors.Is(err, lapi.ErrNotFound) {
			res.Errors = append(res.Errors, &apiv1.InstanceError{Instance: ls[0].Name, Error: fmt.Sprintf("decision %d: %v", id, err)})
			continue
		}
		res.Deleted += n
		done = append(done, id)
	}
	if err := d.s.cfg.AlertStore.ForgetDecisions(ctx, ls[0].Name, done); err != nil {
		d.s.log.Warn("forget decisions", "err", err)
	}
	d.s.changed(ls[0].Name)
	return connect.NewResponse(res), nil
}

func (d *decisionService) CleanupIP(ctx context.Context, req *connect.Request[apiv1.CleanupIPRequest]) (*connect.Response[apiv1.CleanupIPResponse], error) {
	ls, err := d.s.lapis(req.Msg.GetInstance())
	if err != nil {
		return nil, err
	}
	_, ip, err := normalizeTarget("ip", req.Msg.GetIp())
	if err != nil {
		return nil, toConnectError(err)
	}
	res := &apiv1.CleanupIPResponse{}
	for _, l := range ls {
		n, err := l.Watcher.DeleteDecisions(ctx, url.Values{"ip": {ip}})
		if err != nil {
			res.Errors = append(res.Errors, &apiv1.InstanceError{Instance: l.Name, Error: "decisions: " + err.Error()})
			continue
		}
		res.DecisionsDeleted += n
		if req.Msg.GetDeleteAlerts() {
			n, err := l.Watcher.DeleteAlerts(ctx, url.Values{"ip": {ip}})
			if err != nil {
				res.Errors = append(res.Errors, &apiv1.InstanceError{Instance: l.Name, Error: "alerts: " + err.Error()})
			}
			res.AlertsDeleted += n
		}
		if err := d.s.cfg.AlertStore.ForgetValue(ctx, l.Name, ip, req.Msg.GetDeleteAlerts()); err != nil {
			d.s.log.Warn("forget value", "err", err)
		}
		d.s.changed(l.Name)
	}
	return connect.NewResponse(res), nil
}

func (d *decisionService) GetPropagation(ctx context.Context, req *connect.Request[apiv1.GetPropagationRequest]) (*connect.Response[apiv1.GetPropagationResponse], error) {
	q, err := d.s.querier()
	if err != nil {
		return nil, err
	}
	res, err := q.Propagation(ctx, strings.TrimSpace(req.Msg.GetValue()))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(res), nil
}

type dashboardService struct{ s *Server }

func (d *dashboardService) GetSummary(ctx context.Context, req *connect.Request[apiv1.GetSummaryRequest]) (*connect.Response[apiv1.GetSummaryResponse], error) {
	q, err := d.s.querier()
	if err != nil {
		return nil, err
	}
	m := req.Msg
	res, err := q.Summary(ctx, alerts.Filter{Query: m.GetQuery(), From: timeOf(m.GetFrom(), m.From != nil), To: timeOf(m.GetTo(), m.To != nil),
		Instance: m.GetInstance(), IncludeSimulated: m.GetIncludeSimulated()})
	if err != nil {
		return nil, queryError(err)
	}
	return connect.NewResponse(res), nil
}
