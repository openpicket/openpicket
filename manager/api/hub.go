package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/hub"
	"github.com/openpicket/openpicket/pkg/hubitem"
	"github.com/openpicket/openpicket/pkg/record"
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
	compat, err := st.Compatibilities(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	var idx hub.Index
	if h.s.cfg.HubRemote != nil {
		idx, _, _ = h.s.cfg.HubRemote.Index(ctx)
	}
	res := &apiv1.ListHubItemsResponse{}
	for _, it := range items {
		pb := hubItemPB(it)
		if c, ok := compat[it.Name]; ok && it.Type == hubitem.Scenarios {
			pb.Compat, pb.MissingLogTypes = c.Status, c.Missing
		}
		if e := idx[it.Type][it.Name]; e != nil && it.Source == hubitem.SourceHub && e.Version != it.Version {
			pb.LatestVersion = e.Version
		}
		res.Items = append(res.Items, pb)
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

func (h *hubService) remote() (*hub.Hub, error) {
	if h.s.cfg.HubRemote == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the CrowdSec hub is not configured"))
	}
	return h.s.cfg.HubRemote, nil
}

func indexEntryPB(typ, name string, e *hub.IndexEntry) *apiv1.HubIndexEntry {
	out := &apiv1.HubIndexEntry{Type: typ, Name: name, Description: e.Description, Version: e.Version, References: e.References}
	for _, m := range e.Members() {
		out.Members = append(out.Members, &apiv1.HubRef{Type: m.Type, Name: m.Name})
	}
	return out
}

func (h *hubService) ListHubIndex(ctx context.Context, req *connect.Request[apiv1.ListHubIndexRequest]) (*connect.Response[apiv1.ListHubIndexResponse], error) {
	rem, err := h.remote()
	if err != nil {
		return nil, err
	}
	idx, at, err := rem.Index(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	res := &apiv1.ListHubIndexResponse{BaseUrl: rem.Source.BaseURL}
	if at.IsZero() {
		return connect.NewResponse(res), nil
	}
	res.FetchedAt = timestamppb.New(at)
	installed := map[hub.Ref]hub.Item{}
	items, err := h.s.cfg.Hub.Items(ctx, req.Msg.GetType())
	if err != nil {
		return nil, toConnectError(err)
	}
	for _, it := range items {
		installed[it.Ref] = it
	}
	q := strings.ToLower(strings.TrimSpace(req.Msg.GetQuery()))
	var names []hub.Ref
	for typ, entries := range idx {
		if req.Msg.GetType() != "" && typ != req.Msg.GetType() || !hubitem.ValidType(typ) {
			continue
		}
		for name, e := range entries {
			if q == "" || strings.Contains(strings.ToLower(name), q) || strings.Contains(strings.ToLower(e.Description), q) {
				names = append(names, hub.Ref{Type: typ, Name: name})
			}
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i].Type != names[j].Type {
			return names[i].Type < names[j].Type
		}
		return names[i].Name < names[j].Name
	})
	res.Total = int32(len(names))
	limit := int(req.Msg.GetLimit())
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	off := min(max(int(req.Msg.GetOffset()), 0), len(names))
	for _, r := range names[off:min(off+limit, len(names))] {
		pb := indexEntryPB(r.Type, r.Name, idx[r.Type][r.Name])
		if it, ok := installed[r]; ok {
			pb.InstalledSource, pb.InstalledVersion = it.Source, it.Version
		}
		res.Entries = append(res.Entries, pb)
	}
	return connect.NewResponse(res), nil
}

func (h *hubService) RefreshHubIndex(ctx context.Context, _ *connect.Request[apiv1.RefreshHubIndexRequest]) (*connect.Response[apiv1.RefreshHubIndexResponse], error) {
	rem, err := h.remote()
	if err != nil {
		return nil, err
	}
	changed, err := rem.RefreshIndex(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(&apiv1.RefreshHubIndexResponse{Changed: changed}), nil
}

func (h *hubService) PreviewHubItem(ctx context.Context, req *connect.Request[apiv1.PreviewHubItemRequest]) (*connect.Response[apiv1.PreviewHubItemResponse], error) {
	rem, err := h.remote()
	if err != nil {
		return nil, err
	}
	p, err := rem.Preview(ctx, hubRef(req.Msg.GetRef()))
	if err != nil {
		return nil, hubFetchError(err)
	}
	res := &apiv1.PreviewHubItemResponse{Entry: indexEntryPB(p.Root.Type, p.Root.Name, p.Root.Entry), DataFiles: p.Data}
	if p.Root.Type != hubitem.Collections {
		res.Content = string(p.Root.Content)
	}
	produced, err := h.s.cfg.Hub.Produced(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	var required []string
	for _, d := range p.Items {
		res.Items = append(res.Items, &apiv1.HubRef{Type: d.Type, Name: d.Name})
		switch d.Type {
		case hubitem.Parsers:
			produced = append(produced, d.Doc.Produces...)
		case hubitem.Scenarios:
			required = append(required, d.Doc.LogTypes...)
		}
	}
	if len(required) > 0 {
		res.Compat, res.MissingLogTypes = hubitem.Compat(required, produced)
	}
	return connect.NewResponse(res), nil
}

func (h *hubService) InstallHubItem(ctx context.Context, req *connect.Request[apiv1.InstallHubItemRequest]) (*connect.Response[apiv1.InstallHubItemResponse], error) {
	rem, err := h.remote()
	if err != nil {
		return nil, err
	}
	installed, err := rem.Install(ctx, hubRef(req.Msg.GetRef()), by(ctx))
	if err != nil {
		return nil, hubFetchError(err)
	}
	res := &apiv1.InstallHubItemResponse{}
	for _, r := range installed {
		res.Installed = append(res.Installed, &apiv1.HubRef{Type: r.Type, Name: r.Name})
	}
	return connect.NewResponse(res), nil
}

func (h *hubService) RemoveHubItem(ctx context.Context, req *connect.Request[apiv1.RemoveHubItemRequest]) (*connect.Response[apiv1.RemoveHubItemResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	if err := st.Remove(ctx, hubRef(req.Msg.GetRef()), by(ctx)); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.RemoveHubItemResponse{}), nil
}

// hubFetchError maps download failures (the hub unreachable, a digest
// mismatch) to Unavailable; validation and lookups as usual.
func hubFetchError(err error) error {
	if errors.Is(err, hub.ErrNotFound) || errors.Is(err, hub.ErrInvalid) {
		return toConnectError(err)
	}
	return connect.NewError(connect.CodeUnavailable, err)
}

// Upload limits: an item file and its data files.
const (
	hubUploadMaxData  = 64 << 20
	hubUploadMaxTotal = 128 << 20
)

// uploadHub stores a custom item (multipart: fields "type" and "stage",
// file "item", files "data" named as the item's data files).
func (s *Server) uploadHub(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Hub == nil {
		http.Error(w, "CrowdSec content is not configured", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, hubUploadMaxTotal)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var (
		typ, stage string
		item       []byte
		data       = map[string][]byte{}
	)
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "type", "stage":
			v, _ := io.ReadAll(io.LimitReader(part, 64))
			if part.FormName() == "type" {
				typ = strings.TrimSpace(string(v))
			} else {
				stage = strings.TrimSpace(string(v))
			}
		case "item":
			if item, err = io.ReadAll(io.LimitReader(part, hubitem.MaxItemSize+1)); err != nil || len(item) > hubitem.MaxItemSize {
				http.Error(w, "the item file is larger than 1 MiB", http.StatusRequestEntityTooLarge)
				return
			}
		case "data":
			name := path.Base(part.FileName())
			b, err := io.ReadAll(io.LimitReader(part, hubUploadMaxData+1))
			if err != nil || len(b) > hubUploadMaxData {
				http.Error(w, "a data file is larger than 64 MiB", http.StatusRequestEntityTooLarge)
				return
			}
			data[name] = b
		}
	}
	if len(item) == 0 {
		http.Error(w, "no item file", http.StatusBadRequest)
		return
	}
	// Data files are named by their base name; the item says where they go.
	if doc, err := hubitem.ParseDoc(typ, item); err == nil {
		named := map[string][]byte{}
		for _, ref := range doc.Data {
			if b, ok := data[path.Base(ref.DestFile)]; ok {
				named[ref.DestFile] = b
				delete(data, path.Base(ref.DestFile))
			}
		}
		for extra, b := range data {
			named[extra] = b // refused by Upload, with the expected names
		}
		data = named
	}
	ref, err := s.cfg.Hub.Upload(r.Context(), typ, stage, item, data, by(r.Context()))
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, hub.ErrInvalid) {
			code = http.StatusBadRequest
		}
		http.Error(w, err.Error(), code)
		return
	}
	s.audit(r.Context(), "HubService.Upload", ref.Type+" "+ref.Name, fmt.Sprintf(`{"sha256":%q,"data":%d}`, hub.Digest(item), len(data)))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"type": ref.Type, "name": ref.Name})
}

func (h *hubService) ListLogPrograms(ctx context.Context, _ *connect.Request[apiv1.ListLogProgramsRequest]) (*connect.Response[apiv1.ListLogProgramsResponse], error) {
	st, err := h.store()
	if err != nil {
		return nil, err
	}
	if h.s.cfg.LogPrograms == nil {
		return connect.NewResponse(&apiv1.ListLogProgramsResponse{}), nil
	}
	programs, err := h.s.cfg.LogPrograms.List(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	parsers, err := st.EnabledParsers(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	var idx hub.Index
	if h.s.cfg.HubRemote != nil {
		idx, _, _ = h.s.cfg.HubRemote.Index(ctx)
	}
	res := &apiv1.ListLogProgramsResponse{}
	for _, p := range programs {
		pb := &apiv1.LogProgram{Program: p.Program, Nodes: p.Nodes, Lines: p.Lines, LastSeen: timestamppb.New(p.LastSeen), Loki: p.Loki}
		for name, doc := range parsers {
			if doc.HandlesProgram(p.Program) {
				pb.Parsers = append(pb.Parsers, name)
			}
		}
		sort.Strings(pb.Parsers)
		if len(pb.Parsers) == 0 {
			pb.Suggestions = suggestFor(idx, p.Program)
		}
		res.Programs = append(res.Programs, pb)
	}
	return connect.NewResponse(res), nil
}

// suggestFor names hub collections and parsers likely to handle a program
// (by name: crowdsecurity/nginx, crowdsecurity/nginx-logs).
func suggestFor(idx hub.Index, program string) []*apiv1.HubRef {
	var out []*apiv1.HubRef
	base := strings.TrimSuffix(strings.TrimSuffix(program, "d"), "-session")
	for _, typ := range []string{hubitem.Collections, hubitem.Parsers} {
		var names []string
		for name := range idx[typ] {
			short := name[strings.IndexByte(name, '/')+1:]
			short = strings.TrimSuffix(short, "-logs")
			if short == program || short == base {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, &apiv1.HubRef{Type: typ, Name: n})
		}
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

func (h *hubService) SetLogProgramStorage(ctx context.Context, req *connect.Request[apiv1.SetLogProgramStorageRequest]) (*connect.Response[apiv1.SetLogProgramStorageResponse], error) {
	if h.s.cfg.LogPrograms == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("log programs are not tracked"))
	}
	if record.NormalizeProgram(req.Msg.GetProgram()) == "" {
		return nil, toConnectError(fmt.Errorf("%w: program", errInvalid))
	}
	if err := h.s.cfg.LogPrograms.SetLoki(ctx, req.Msg.GetProgram(), req.Msg.GetLoki()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.SetLogProgramStorageResponse{}), nil
}
