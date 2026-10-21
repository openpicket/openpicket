package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/geo"
	"github.com/openpicket/openpicket/pkg/portpolicy"
)

type policyService struct{ s *Server }

func toPolicyMsg(p portpolicy.Policy) *apiv1.Policy {
	out := &apiv1.Policy{Id: p.ID, Description: p.Description, Enabled: p.Enabled, Mode: p.Mode, Proto: p.Proto, DefaultAction: p.Default, LogDrops: p.LogDrops,
		Scope: &apiv1.PolicyScope{Nodes: p.Scope.Nodes}}
	if len(p.Scope.Labels) > 0 {
		out.Scope.Labels = map[string]*apiv1.LabelValues{}
		for k, v := range p.Scope.Labels {
			out.Scope.Labels[k] = &apiv1.LabelValues{Values: v}
		}
	}
	for _, r := range p.Ports {
		out.Ports = append(out.Ports, &apiv1.PortRange{From: r.From, To: r.To})
	}
	for _, r := range p.Rules {
		out.Rules = append(out.Rules, &apiv1.PolicyRule{Action: r.Action, Source: &apiv1.PolicySource{
			Countries: r.Source.Countries, Asns: r.Source.ASNs, Lists: r.Source.Lists, Cidrs: r.Source.CIDRs}})
	}
	return out
}

func fromPolicyMsg(m *apiv1.Policy) portpolicy.Policy {
	p := portpolicy.Policy{ID: m.GetId(), Description: m.GetDescription(), Enabled: m.GetEnabled(), Mode: m.GetMode(), Proto: m.GetProto(),
		Default: m.GetDefaultAction(), LogDrops: m.GetLogDrops(), Scope: portpolicy.Scope{Nodes: m.GetScope().GetNodes()}}
	if l := m.GetScope().GetLabels(); len(l) > 0 {
		p.Scope.Labels = map[string][]string{}
		for k, v := range l {
			p.Scope.Labels[k] = v.GetValues()
		}
	}
	for _, r := range m.GetPorts() {
		p.Ports = append(p.Ports, portpolicy.PortRange{From: r.GetFrom(), To: r.GetTo()})
	}
	for _, r := range m.GetRules() {
		src := r.GetSource()
		p.Rules = append(p.Rules, portpolicy.Rule{Action: r.GetAction(), Source: portpolicy.Source{
			Countries: src.GetCountries(), ASNs: src.GetAsns(), Lists: src.GetLists(), CIDRs: src.GetCidrs()}})
	}
	return p
}

func (p *policyService) ListPolicies(ctx context.Context, _ *connect.Request[apiv1.ListPoliciesRequest]) (*connect.Response[apiv1.ListPoliciesResponse], error) {
	recs, version, err := p.s.cfg.Policies.PolicyRecords(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	status, err := p.s.cfg.Policies.CompileStatuses(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	res := &apiv1.ListPoliciesResponse{Version: version}
	for _, r := range recs {
		m := toPolicyMsg(r.Policy)
		m.Position, m.UpdatedAt, m.UpdatedBy = int32(r.Position), timestamppb.New(r.UpdatedAt), r.UpdatedBy
		if st, ok := status[r.Policy.ID]; ok && st.Error != "" {
			m.CompileError, m.Stale = st.Error, st.Stale
			if !st.ErrorSince.IsZero() {
				m.CompileErrorSince = timestamppb.New(st.ErrorSince)
			}
		}
		res.Policies = append(res.Policies, m)
	}
	return connect.NewResponse(res), nil
}

func (p *policyService) PutPolicy(ctx context.Context, req *connect.Request[apiv1.PutPolicyRequest]) (*connect.Response[apiv1.PutPolicyResponse], error) {
	if req.Msg.GetPolicy() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("policy is required"))
	}
	position := -1
	if req.Msg.Position != nil {
		position = int(req.Msg.GetPosition())
	}
	v, err := p.s.cfg.Policies.PutPolicy(ctx, fromPolicyMsg(req.Msg.GetPolicy()), position, by(ctx))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.PutPolicyResponse{Version: v}), nil
}

func (p *policyService) DeletePolicy(ctx context.Context, req *connect.Request[apiv1.DeletePolicyRequest]) (*connect.Response[apiv1.DeletePolicyResponse], error) {
	v, err := p.s.cfg.Policies.DeletePolicy(ctx, req.Msg.GetId(), by(ctx))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.DeletePolicyResponse{Version: v}), nil
}

func (p *policyService) ReorderPolicies(ctx context.Context, req *connect.Request[apiv1.ReorderPoliciesRequest]) (*connect.Response[apiv1.ReorderPoliciesResponse], error) {
	v, err := p.s.cfg.Policies.Reorder(ctx, req.Msg.GetIds(), by(ctx))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.ReorderPoliciesResponse{Version: v}), nil
}

func (p *policyService) ListAddressLists(ctx context.Context, _ *connect.Request[apiv1.ListAddressListsRequest]) (*connect.Response[apiv1.ListAddressListsResponse], error) {
	recs, err := p.s.cfg.Policies.ListRecords(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	res := &apiv1.ListAddressListsResponse{}
	for _, r := range recs {
		res.Lists = append(res.Lists, &apiv1.AddressList{Name: r.List.Name, Description: r.Description, Cidrs: r.List.CIDRs, Asns: r.List.ASNs,
			UpdatedAt: timestamppb.New(r.UpdatedAt), UpdatedBy: r.UpdatedBy, UsedBy: r.UsedBy})
	}
	return connect.NewResponse(res), nil
}

func (p *policyService) PutAddressList(ctx context.Context, req *connect.Request[apiv1.PutAddressListRequest]) (*connect.Response[apiv1.PutAddressListResponse], error) {
	l := req.Msg.GetList()
	v, err := p.s.cfg.Policies.PutList(ctx, portpolicy.List{Name: l.GetName(), CIDRs: l.GetCidrs(), ASNs: l.GetAsns()}, l.GetDescription(), by(ctx))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.PutAddressListResponse{Version: v}), nil
}

func (p *policyService) DeleteAddressList(ctx context.Context, req *connect.Request[apiv1.DeleteAddressListRequest]) (*connect.Response[apiv1.DeleteAddressListResponse], error) {
	v, err := p.s.cfg.Policies.DeleteList(ctx, req.Msg.GetName(), by(ctx))
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.DeleteAddressListResponse{Version: v}), nil
}

func (p *policyService) PolicyHistory(ctx context.Context, req *connect.Request[apiv1.PolicyHistoryRequest]) (*connect.Response[apiv1.PolicyHistoryResponse], error) {
	changes, err := p.s.cfg.Policies.History(ctx, req.Msg.GetPolicyId(), int(req.Msg.GetLimit()))
	if err != nil {
		return nil, toConnectError(err)
	}
	res := &apiv1.PolicyHistoryResponse{}
	for _, c := range changes {
		res.Changes = append(res.Changes, &apiv1.PolicyChange{PolicyId: c.PolicyID, Version: c.Version, Action: c.Action, SpecJson: string(c.Spec),
			ChangedAt: timestamppb.New(c.ChangedAt), ChangedBy: c.ChangedBy})
	}
	return connect.NewResponse(res), nil
}

func (p *policyService) PreviewBundle(ctx context.Context, req *connect.Request[apiv1.PreviewBundleRequest]) (*connect.Response[apiv1.PreviewBundleResponse], error) {
	var labels map[string]string
	node, err := (&nodeService{p.s}).get(ctx, req.Msg.GetNodeId())
	if err != nil {
		return nil, toConnectError(err)
	}
	labels = node.GetLabels()
	b, skipped, err := p.s.cfg.Policies.Bundle(ctx, node.GetId(), labels)
	if err != nil {
		return nil, toConnectError(err)
	}
	res := &apiv1.PreviewBundleResponse{Version: b.GetVersion()}
	for _, pol := range b.GetPolicies() {
		res.Policies = append(res.Policies, pol.GetId())
	}
	for _, s := range b.GetSets() {
		res.Elements += uint32(len(s.GetCidrs()))
	}
	for _, s := range skipped {
		res.Skipped = append(res.Skipped, &apiv1.SkippedPolicy{PolicyId: s.ID, Reason: s.Reason, Stale: s.Stale})
	}
	raw, _ := protojson.MarshalOptions{UseProtoNames: true, Indent: "  "}.Marshal(b)
	res.BundleJson = string(raw)
	return connect.NewResponse(res), nil
}

type geoService struct{ s *Server }

func (g *geoService) ListDatabases(ctx context.Context, _ *connect.Request[apiv1.ListDatabasesRequest]) (*connect.Response[apiv1.ListDatabasesResponse], error) {
	infos, err := g.s.cfg.Geo.List(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	cur := g.s.cfg.Geo.Current()
	res := &apiv1.ListDatabasesResponse{Loaded: cur.HasCountry() || cur.HasASN()}
	for _, i := range infos {
		res.Databases = append(res.Databases, toGeoMsg(i))
	}
	return connect.NewResponse(res), nil
}

func toGeoMsg(i geo.Info) *apiv1.GeoDatabase {
	return &apiv1.GeoDatabase{Kind: i.Kind, DatabaseType: i.DatabaseType, BuildTime: timestamppb.New(time.Unix(i.BuildEpoch, 0)), Sha256: i.SHA256,
		Size: int64(i.Size), UploadedAt: timestamppb.New(i.UploadedAt), UploadedBy: i.UploadedBy}
}

func (g *geoService) DeleteDatabase(ctx context.Context, req *connect.Request[apiv1.DeleteDatabaseRequest]) (*connect.Response[apiv1.DeleteDatabaseResponse], error) {
	// Deleting a database policies need would freeze them at their last
	// good version: disable or change those policies first.
	users, err := g.s.cfg.Policies.GeoDependents(ctx, req.Msg.GetKind())
	if err != nil {
		return nil, toConnectError(err)
	}
	if len(users) > 0 {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("enabled port policies use the %s database: %s; disable or change them first", req.Msg.GetKind(), strings.Join(users, ", ")))
	}
	if err := g.s.cfg.Geo.Delete(ctx, req.Msg.GetKind()); err != nil {
		return nil, toConnectError(fmt.Errorf("%w: %v", errNotFound, err))
	}
	return connect.NewResponse(&apiv1.DeleteDatabaseResponse{}), nil
}

func (g *geoService) Lookup(_ context.Context, req *connect.Request[apiv1.GeoLookupRequest]) (*connect.Response[apiv1.GeoLookupResponse], error) {
	if len(req.Msg.GetIps()) > 1000 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("at most 1000 addresses"))
	}
	cur := g.s.cfg.Geo.Current()
	res := &apiv1.GeoLookupResponse{}
	for _, ip := range req.Msg.GetIps() {
		r := &apiv1.GeoResult{Ip: ip}
		if l := cur.Lookup(ip); l != nil {
			r.Country, r.Asn, r.AsOrg = l.Country, l.ASN, l.ASOrg
		}
		res.Results = append(res.Results, r)
	}
	return connect.NewResponse(res), nil
}

// uploadGeo accepts a MaxMind database (multipart field "file", or the raw
// body) and answers the stored database as JSON.
func (s *Server) uploadGeo(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, geo.MaxUpload+1<<20)
	var src io.Reader = r.Body
	if ct := r.Header.Get("Content-Type"); len(ct) >= 19 && ct[:19] == "multipart/form-data" {
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for {
			part, err := mr.NextPart()
			if err != nil {
				http.Error(w, "no file part", http.StatusBadRequest)
				return
			}
			if part.FormName() == "file" {
				src = part
				break
			}
		}
	}
	data, err := io.ReadAll(io.LimitReader(src, geo.MaxUpload+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	info, err := s.cfg.Geo.Upload(r.Context(), data, by(r.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit(r.Context(), "GeoService.Upload", info.Kind, fmt.Sprintf(`{"database_type":%q,"sha256":%q}`, info.DatabaseType, info.SHA256))
	raw, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(toGeoMsg(*info))
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}
