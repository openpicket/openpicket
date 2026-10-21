package api

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/auth"
	"github.com/openpicket/openpicket/manager/misp"
)

type intelService struct{ s *Server }

func (i *intelService) misp() (*misp.Service, error) {
	if i.s.cfg.MISP == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("MISP is not configured"))
	}
	return i.s.cfg.MISP, nil
}

func (i *intelService) GetIntelStatus(ctx context.Context, _ *connect.Request[apiv1.GetIntelStatusRequest]) (*connect.Response[apiv1.GetIntelStatusResponse], error) {
	res := &apiv1.GetIntelStatusResponse{Configured: i.s.cfg.MISP != nil}
	if i.s.cfg.MISP == nil {
		return connect.NewResponse(res), nil
	}
	res.MispUrl = i.s.cfg.MISP.Client().URL()
	res.ProposeMinAlerts, res.DefaultTtl = int32(i.s.cfg.MISPSettings.ProposeMinAlerts), i.s.cfg.MISPSettings.DefaultTTL
	var last *time.Time
	if err := i.s.cfg.DB.QueryRow(ctx, `SELECT last_sync_at, last_error, active,
		(SELECT count(*) FROM openpicket.misp_iocs WHERE state = 'proposed') FROM openpicket.misp_sync WHERE id = 1`).
		Scan(&last, &res.LastError, &res.Active, &res.Proposed); err != nil {
		return nil, toConnectError(err)
	}
	res.LastSyncAt = ts(last)
	return connect.NewResponse(res), nil
}

func (i *intelService) ListIOCs(ctx context.Context, req *connect.Request[apiv1.ListIOCsRequest]) (*connect.Response[apiv1.ListIOCsResponse], error) {
	m := req.Msg
	where := `($1 = '' OR m.state = $1) AND ($2 = '' OR m.value ILIKE '%' || $2 || '%')`
	res := &apiv1.ListIOCsResponse{}
	if err := i.s.cfg.DB.QueryRow(ctx, `SELECT count(*) FROM openpicket.misp_iocs m WHERE `+where, m.GetState(), m.GetValue()).Scan(&res.Total); err != nil {
		return nil, toConnectError(err)
	}
	rows, err := i.s.cfg.DB.Query(ctx, `SELECT m.uuid, m.attribute_id, m.event_id, m.event_info, m.type, m.value, m.to_ids, m.state, m.ttl, m.comment,
		m.tags, m.modified_at, m.approved_at,
		(SELECT count(*) FROM openpicket.alerts a WHERE a.source_value = split_part(m.value, '|', 1)),
		COALESCE((SELECT array_agg(DISTINCT a.scenario) FROM openpicket.alerts a WHERE a.source_value = split_part(m.value, '|', 1)), '{}'),
		COALESCE((SELECT array_agg(DISTINCT a.node_id) FILTER (WHERE a.node_id <> '') FROM openpicket.alerts a WHERE a.source_value = split_part(m.value, '|', 1)), '{}'),
		(SELECT max(a.created_at) FROM openpicket.alerts a WHERE a.source_value = split_part(m.value, '|', 1)),
		COALESCE((SELECT a.country FROM openpicket.alerts a WHERE a.source_value = split_part(m.value, '|', 1) AND a.country <> '' LIMIT 1), ''),
		COALESCE((SELECT a.as_name FROM openpicket.alerts a WHERE a.source_value = split_part(m.value, '|', 1) AND a.as_name <> '' LIMIT 1), '')
		FROM openpicket.misp_iocs m WHERE `+where+`
		ORDER BY CASE m.state WHEN 'proposed' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, m.modified_at DESC NULLS LAST, m.value
		LIMIT $3 OFFSET $4`, m.GetState(), m.GetValue(), clampLimit32(m.GetLimit(), 100, 1000), max(m.GetOffset(), 0))
	if err != nil {
		return nil, toConnectError(err)
	}
	defer rows.Close()
	defTTL := i.s.cfg.MISPSettings.DefaultTTL
	for rows.Next() {
		var (
			x                     apiv1.IOC
			mod, approved, lastAt *time.Time
		)
		if err := rows.Scan(&x.Uuid, &x.AttributeId, &x.EventId, &x.EventInfo, &x.Type, &x.Value, &x.ToIds, &x.State, &x.Ttl, &x.Comment,
			&x.Tags, &mod, &approved, &x.Alerts, &x.Scenarios, &x.Nodes, &lastAt, &x.Country, &x.AsName); err != nil {
			return nil, toConnectError(err)
		}
		x.ModifiedAt, x.ApprovedAt, x.LastAlertAt = ts(mod), ts(approved), ts(lastAt)
		if approved != nil && x.State == misp.StateApproved {
			ttl := x.Ttl
			if ttl == "" {
				ttl = defTTL
			}
			if d, err := misp.ParseTTL(ttl); err == nil {
				x.ExpiresAt = timestamppb.New(approved.Add(d))
			}
		}
		res.Iocs = append(res.Iocs, &x)
	}
	return connect.NewResponse(res), toConnectError(rows.Err())
}

func (i *intelService) SetIOCState(ctx context.Context, req *connect.Request[apiv1.SetIOCStateRequest]) (*connect.Response[apiv1.SetIOCStateResponse], error) {
	svc, err := i.misp()
	if err != nil {
		return nil, err
	}
	if len(req.Msg.GetUuids()) == 0 || len(req.Msg.GetUuids()) > 500 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("1-500 attributes"))
	}
	if err := svc.SetState(ctx, req.Msg.GetUuids(), req.Msg.GetState(), req.Msg.GetTtl()); err != nil {
		if strings.Contains(err.Error(), "unknown state") || strings.Contains(err.Error(), "invalid ttl") {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	i.s.pokeMISP()
	return connect.NewResponse(&apiv1.SetIOCStateResponse{}), nil
}

func (i *intelService) ProposeIOC(ctx context.Context, req *connect.Request[apiv1.ProposeIOCRequest]) (*connect.Response[apiv1.ProposeIOCResponse], error) {
	svc, err := i.misp()
	if err != nil {
		return nil, err
	}
	typ := req.Msg.GetType()
	if typ == "" {
		typ = "ip-src"
	}
	if typ != "ip-src" && typ != "ip-dst" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("type must be ip-src or ip-dst"))
	}
	comment := strings.TrimSpace(req.Msg.GetComment())
	if p := auth.FromContext(ctx); p != nil {
		comment = strings.TrimSpace(fmt.Sprintf("Proposed in OpenPicket by %s. %s", p.Display(), comment))
	}
	a, err := svc.Propose(ctx, req.Msg.GetValue(), typ, comment)
	switch {
	case errors.Is(err, misp.ErrExists):
		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	case err != nil && strings.Contains(err.Error(), "not an IP"):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	i.s.pokeMISP()
	return connect.NewResponse(&apiv1.ProposeIOCResponse{Ioc: &apiv1.IOC{Uuid: a.UUID, AttributeId: a.ID, EventId: a.EventID, Type: a.Type,
		Value: a.Value, State: misp.StateProposed, Comment: a.Comment}}), nil
}

func (s *Server) pokeMISP() {
	if s.cfg.PokeMISP != nil {
		s.cfg.PokeMISP()
	}
}
