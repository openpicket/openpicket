package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/hub"
)

type hubService struct{ s *Server }

func (h *hubService) store() (*hub.Store, error) {
	if h.s.cfg.Hub == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("CrowdSec content is not configured"))
	}
	return h.s.cfg.Hub, nil
}

func hubItemPB(it hub.Item) *apiv1.HubItem {
	out := &apiv1.HubItem{Type: it.Type, Name: it.Name, Source: it.Source, Version: it.Version, Stage: it.Stage, Description: it.Description,
		State: it.State, MemberOf: it.MemberOf, Data: it.Data, Explicit: it.Explicit, Digest: it.Digest, UpdatedBy: it.UpdatedBy}
	if !it.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(it.UpdatedAt)
	}
	for _, m := range it.Members {
		out.Members = append(out.Members, &apiv1.HubRef{Type: m.Type, Name: m.Name})
	}
	return out
}

func hubRef(r *apiv1.HubRef) hub.Ref { return hub.Ref{Type: r.GetType(), Name: r.GetName()} }

func (h *hubService) ListHubItems(ctx context.Context, req *connect.Request[apiv1.ListHubItemsRequest]) (*connect.Response[apiv1.ListHubItemsResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	items, err := st.Items(ctx, req.Msg.GetType())
	if err != nil {
		return nil, toConnectError(err)
	}
	res := &apiv1.ListHubItemsResponse{}
	for _, it := range items {
		res.Items = append(res.Items, hubItemPB(it))
	}
	return connect.NewResponse(res), nil
}

func (h *hubService) GetHubItem(ctx context.Context, req *connect.Request[apiv1.GetHubItemRequest]) (*connect.Response[apiv1.GetHubItemResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	ref := hubRef(req.Msg.GetRef())
	items, err := st.Items(ctx, ref.Type)
	if err != nil {
		return nil, toConnectError(err)
	}
	for _, it := range items {
		if it.Ref == ref {
			content, err := st.Content(ctx, ref)
			if err != nil {
				return nil, toConnectError(err)
			}
			return connect.NewResponse(&apiv1.GetHubItemResponse{Item: hubItemPB(it), Content: string(content)}), nil
		}
	}
	return nil, toConnectError(hub.ErrNotFound)
}

func (h *hubService) SetHubItemState(ctx context.Context, req *connect.Request[apiv1.SetHubItemStateRequest]) (*connect.Response[apiv1.SetHubItemStateResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	if err := st.SetState(ctx, hubRef(req.Msg.GetRef()), req.Msg.GetState(), by(ctx)); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.SetHubItemStateResponse{}), nil
}

func (h *hubService) GetHubRollout(ctx context.Context, _ *connect.Request[apiv1.GetHubRolloutRequest]) (*connect.Response[apiv1.GetHubRolloutResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	m, lps, err := st.Status(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	res := &apiv1.GetHubRolloutResponse{Revision: m.Revision, GoodRevision: m.GoodRevision, FailedRevision: m.FailedRevision, FailedError: m.FailedError}
	for _, l := range lps {
		res.LogProcessors = append(res.LogProcessors, &apiv1.HubLogProcessor{Endpoint: l.Endpoint, Revision: l.Revision, Running: l.Running,
			Error: l.Error, SeenAt: timestamppb.New(l.SeenAt)})
	}
	return connect.NewResponse(res), nil
}
