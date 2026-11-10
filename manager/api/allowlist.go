package api

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/allowlist"
)

type allowlistService struct{ s *Server }

func (a *allowlistService) store() (*allowlist.Store, error) {
	if a.s.cfg.Allowlist == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the allowlist is not available"))
	}
	return a.s.cfg.Allowlist, nil
}

func (a *allowlistService) ListAllowlist(ctx context.Context, _ *connect.Request[apiv1.ListAllowlistRequest]) (*connect.Response[apiv1.ListAllowlistResponse], error) {
	st, err := a.store()
	if err != nil {
		return nil, err
	}
	entries, err := st.List(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	now := a.s.cfg.Now()
	res := &apiv1.ListAllowlistResponse{}
	for _, e := range entries {
		m := &apiv1.AllowlistEntry{Network: e.Network.String(), Description: e.Description, CreatedAt: timestamppb.New(e.CreatedAt), CreatedBy: e.CreatedBy,
			UpdatedAt: timestamppb.New(e.UpdatedAt), UpdatedBy: e.UpdatedBy, Excluded: e.Excluded, Active: e.Active(now)}
		if !e.ExpiresAt.IsZero() {
			m.ExpiresAt = timestamppb.New(e.ExpiresAt)
		}
		res.Entries = append(res.Entries, m)
	}
	if len(a.s.cfg.AllowlistLAPIs) > 0 {
		sts, err := st.SyncStatuses(ctx)
		if err != nil {
			return nil, toConnectError(err)
		}
		for _, l := range a.s.cfg.AllowlistLAPIs {
			m := &apiv1.AllowlistLAPIStatus{Instance: l.Name, Enabled: l.Synced}
			if s, ok := sts[l.Name]; ok && l.Synced {
				m.AttemptAt, m.SyncedAt, m.ChangedAt = timestamppb.New(s.AttemptAt), optTime(s.SyncedAt), optTime(s.ChangedAt)
				m.Items, m.Error = int32(s.Items), s.Error
			}
			res.Lapis = append(res.Lapis, m)
		}
	}
	return connect.NewResponse(res), nil
}

// AllowlistLAPI is a LAPI instance and whether its openpicket allowlist
// follows the entries.
type AllowlistLAPI struct {
	Name   string
	Synced bool
}

func optTime(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func (a *allowlistService) PutAllowlistEntry(ctx context.Context, req *connect.Request[apiv1.PutAllowlistEntryRequest]) (*connect.Response[apiv1.PutAllowlistEntryResponse], error) {
	st, err := a.store()
	if err != nil {
		return nil, err
	}
	m := req.Msg.GetEntry()
	p, err := allowlist.ParseNetwork(m.GetNetwork())
	if err != nil {
		return nil, toConnectError(err)
	}
	e := allowlist.Entry{Network: p, Description: m.GetDescription()}
	if m.ExpiresAt != nil {
		e.ExpiresAt = m.GetExpiresAt().AsTime()
	}
	if err := st.Put(ctx, e, req.Msg.GetWide(), by(ctx)); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.PutAllowlistEntryResponse{Network: p.String()}), nil
}

func (a *allowlistService) DeleteAllowlistEntry(ctx context.Context, req *connect.Request[apiv1.DeleteAllowlistEntryRequest]) (*connect.Response[apiv1.DeleteAllowlistEntryResponse], error) {
	st, err := a.store()
	if err != nil {
		return nil, err
	}
	p, err := allowlist.ParseNetwork(req.Msg.GetNetwork())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := st.Delete(ctx, p); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.DeleteAllowlistEntryResponse{}), nil
}
