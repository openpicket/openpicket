package api

import (
	"context"
	"errors"
	"sort"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/notify"
)

type notificationService struct{ s *Server }

func (n *notificationService) store() *notify.Store { return &notify.Store{DB: n.s.cfg.DB} }

func toDestinationMsg(d *notify.Destination) *apiv1.Destination {
	out := &apiv1.Destination{Id: d.ID, Name: d.Name, Type: d.Type, Enabled: d.Enabled, Config: d.Config, MinSeverity: d.Severities}
	for k := range d.Secrets {
		out.SecretKeys = append(out.SecretKeys, k)
	}
	sort.Strings(out.SecretKeys)
	return out
}

func fromDestinationMsg(m *apiv1.Destination) *notify.Destination {
	return &notify.Destination{ID: m.GetId(), Name: m.GetName(), Type: m.GetType(), Enabled: m.GetEnabled(), Config: m.GetConfig(),
		Secrets: m.GetSecrets(), Severities: m.GetMinSeverity()}
}

func invalid(err error) error {
	if errors.Is(err, notify.ErrNotFound) {
		return connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewError(connect.CodeInvalidArgument, err)
}

func (n *notificationService) ListDestinations(ctx context.Context, _ *connect.Request[apiv1.ListDestinationsRequest]) (*connect.Response[apiv1.ListDestinationsResponse], error) {
	ds, err := n.store().Destinations(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	res := &apiv1.ListDestinationsResponse{}
	for _, d := range ds {
		res.Destinations = append(res.Destinations, toDestinationMsg(d))
	}
	return connect.NewResponse(res), nil
}

func (n *notificationService) PutDestination(ctx context.Context, req *connect.Request[apiv1.PutDestinationRequest]) (*connect.Response[apiv1.PutDestinationResponse], error) {
	if req.Msg.GetDestination() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("destination is required"))
	}
	d := fromDestinationMsg(req.Msg.GetDestination())
	if err := n.store().PutDestination(ctx, d, by(ctx)); err != nil {
		return nil, invalid(err)
	}
	return connect.NewResponse(&apiv1.PutDestinationResponse{Destination: toDestinationMsg(d)}), nil
}

func (n *notificationService) DeleteDestination(ctx context.Context, req *connect.Request[apiv1.DeleteDestinationRequest]) (*connect.Response[apiv1.DeleteDestinationResponse], error) {
	if err := n.store().DeleteDestination(ctx, req.Msg.GetId()); err != nil {
		return nil, invalid(err)
	}
	return connect.NewResponse(&apiv1.DeleteDestinationResponse{}), nil
}

func (n *notificationService) TestDestination(ctx context.Context, req *connect.Request[apiv1.TestDestinationRequest]) (*connect.Response[apiv1.TestDestinationResponse], error) {
	if req.Msg.GetDestination() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("destination is required"))
	}
	d := fromDestinationMsg(req.Msg.GetDestination())
	if err := n.store().MergeSecrets(ctx, d); err != nil {
		return nil, toConnectError(err)
	}
	if err := d.Validate(); err != nil {
		return nil, invalid(err)
	}
	res := &apiv1.TestDestinationResponse{Ok: true}
	if err := n.s.cfg.Notify.Test(ctx, d); err != nil {
		res.Ok, res.Error = false, err.Error()
	}
	return connect.NewResponse(res), nil
}

func toRuleMsg(r *notify.Rule) *apiv1.Rule {
	out := &apiv1.Rule{Id: r.ID, Name: r.Name, Enabled: r.Enabled, Type: r.Type, Severity: r.Severity, Query: r.Query, Threshold: int32(r.Threshold),
		WindowSeconds: int32(r.WindowSeconds), SpikeFactor: r.SpikeFactor, CooldownSeconds: int32(r.CooldownSeconds), Destinations: r.Destinations,
		IpFilters: r.IPFilters, IncludeSimulated: r.IncludeSimulated}
	if !r.LastFiredAt.IsZero() {
		out.LastFiredAt = timestamppb.New(r.LastFiredAt)
	}
	return out
}

func (n *notificationService) ListRules(ctx context.Context, _ *connect.Request[apiv1.ListRulesRequest]) (*connect.Response[apiv1.ListRulesResponse], error) {
	rules, err := n.store().Rules(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	res := &apiv1.ListRulesResponse{}
	for _, r := range rules {
		res.Rules = append(res.Rules, toRuleMsg(r))
	}
	return connect.NewResponse(res), nil
}

func (n *notificationService) PutRule(ctx context.Context, req *connect.Request[apiv1.PutRuleRequest]) (*connect.Response[apiv1.PutRuleResponse], error) {
	m := req.Msg.GetRule()
	if m == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("rule is required"))
	}
	r := &notify.Rule{ID: m.GetId(), Name: m.GetName(), Enabled: m.GetEnabled(), Type: m.GetType(), Severity: m.GetSeverity(), Query: m.GetQuery(),
		Threshold: int(m.GetThreshold()), WindowSeconds: int(m.GetWindowSeconds()), SpikeFactor: m.GetSpikeFactor(), CooldownSeconds: int(m.GetCooldownSeconds()),
		Destinations: m.GetDestinations(), IPFilters: m.GetIpFilters(), IncludeSimulated: m.GetIncludeSimulated()}
	if err := n.store().PutRule(ctx, r, by(ctx)); err != nil {
		return nil, invalid(err)
	}
	return connect.NewResponse(&apiv1.PutRuleResponse{Rule: toRuleMsg(r)}), nil
}

func (n *notificationService) DeleteRule(ctx context.Context, req *connect.Request[apiv1.DeleteRuleRequest]) (*connect.Response[apiv1.DeleteRuleResponse], error) {
	if err := n.store().DeleteRule(ctx, req.Msg.GetId()); err != nil {
		return nil, invalid(err)
	}
	return connect.NewResponse(&apiv1.DeleteRuleResponse{}), nil
}

func (n *notificationService) ListNotifications(ctx context.Context, req *connect.Request[apiv1.ListNotificationsRequest]) (*connect.Response[apiv1.ListNotificationsResponse], error) {
	me := by(ctx)
	limit := clampLimit32(req.Msg.GetLimit(), 50, 500)
	rows, err := n.s.cfg.DB.Query(ctx, `SELECT n.id, n.time, n.rule_id, n.rule_name, n.severity, n.title, n.body, n.subject, n.link, $1 = ANY(n.read_by),
		COALESCE((SELECT jsonb_agg(jsonb_build_object('destination', d.destination_id, 'status', d.status, 'attempts', d.attempts, 'error', d.error,
			'updated_at', d.updated_at)) FROM openpicket.notify_deliveries d WHERE d.notification_id = n.id), '[]')
		FROM openpicket.notifications n WHERE ($2 = 0 OR n.id < $2) AND (NOT $3 OR NOT ($1 = ANY(n.read_by))) ORDER BY n.id DESC LIMIT $4`,
		me, req.Msg.GetBeforeId(), req.Msg.GetUnreadOnly(), limit)
	if err != nil {
		return nil, toConnectError(err)
	}
	defer rows.Close()
	res := &apiv1.ListNotificationsResponse{}
	for rows.Next() {
		var (
			x          apiv1.Notification
			t          time.Time
			deliveries []struct {
				Destination string    `json:"destination"`
				Status      string    `json:"status"`
				Attempts    int32     `json:"attempts"`
				Error       string    `json:"error"`
				UpdatedAt   time.Time `json:"updated_at"`
			}
		)
		if err := rows.Scan(&x.Id, &t, &x.RuleId, &x.RuleName, &x.Severity, &x.Title, &x.Body, &x.Subject, &x.Link, &x.Read, &deliveries); err != nil {
			return nil, toConnectError(err)
		}
		x.Time = timestamppb.New(t)
		for _, d := range deliveries {
			x.Deliveries = append(x.Deliveries, &apiv1.Delivery{Destination: d.Destination, Status: d.Status, Attempts: d.Attempts, Error: d.Error,
				UpdatedAt: timestamppb.New(d.UpdatedAt)})
		}
		res.Notifications = append(res.Notifications, &x)
	}
	if err := rows.Err(); err != nil {
		return nil, toConnectError(err)
	}
	if err := n.s.cfg.DB.QueryRow(ctx, `SELECT count(*) FROM openpicket.notifications WHERE NOT ($1 = ANY(read_by))`, me).Scan(&res.Unread); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(res), nil
}

func (n *notificationService) MarkNotificationsRead(ctx context.Context, req *connect.Request[apiv1.MarkNotificationsReadRequest]) (*connect.Response[apiv1.MarkNotificationsReadResponse], error) {
	_, err := n.s.cfg.DB.Exec(ctx, `UPDATE openpicket.notifications SET read_by = array_append(read_by, $1)
		WHERE NOT ($1 = ANY(read_by)) AND ($2 OR id = ANY($3))`, by(ctx), req.Msg.GetAll(), req.Msg.GetIds())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.MarkNotificationsReadResponse{}), nil
}
