package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/gen/openpicket/api/v1/apiv1connect"
	"github.com/openpicket/openpicket/internal/lapitest"
	"github.com/openpicket/openpicket/internal/misptest"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager/alerts"
	"github.com/openpicket/openpicket/manager/auth"
	"github.com/openpicket/openpicket/manager/geo"
	"github.com/openpicket/openpicket/manager/hub"
	"github.com/openpicket/openpicket/manager/lapi"
	"github.com/openpicket/openpicket/manager/logprog"
	"github.com/openpicket/openpicket/manager/misp"
	"github.com/openpicket/openpicket/manager/notify"
	"github.com/openpicket/openpicket/manager/policy"
	"github.com/openpicket/openpicket/manager/settings"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/pkg/geoip/geoiptest"
	"github.com/openpicket/openpicket/pkg/principal"
)

type env struct {
	t      *testing.T
	lapi   *lapitest.LAPI
	syncer *alerts.Syncer
	pokes  chan string
	srv    *httptest.Server
	server *Server
	suri   chan *http.Request
	pub    ed25519.PublicKey
}

func setup(t *testing.T, readOnly bool) *env {
	t.Helper()
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	h, _ := bcrypt.GenerateFromPassword([]byte("s3cret-pw"), bcrypt.MinCost)
	st, err := auth.NewStatic("admin", string(h), auth.RoleAdmin, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st.Insecure = true
	hdr := &auth.Header{UserHeader: "Remote-User", GroupsHeader: "Remote-Groups", SecretHeader: "X-Proxy-Secret", Secret: "proxy", Logout: "https://sso/logout"}
	chain := &auth.Chain{Providers: []auth.Provider{hdr, st}, Roles: auth.Roles{Operator: auth.RoleConfig{Groups: []string{"secops"}}, Viewer: auth.RoleConfig{Groups: []string{"staff"}}}}

	e := &env{t: t, suri: make(chan *http.Request, 4)}
	suri := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.suri <- r
		_, _ = w.Write([]byte("suricontroller " + r.URL.Path))
	}))
	t.Cleanup(suri.Close)
	su, _ := url.Parse(suri.URL + "/base")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e.pub = pub
	g := geo.New(pool, log)
	e.lapi = lapitest.New()
	t.Cleanup(e.lapi.Close)
	lc, _ := lapi.New(lapi.Config{URL: e.lapi.URL, Login: e.lapi.Login, Password: e.lapi.Password})
	w, _ := lc.Watcher()
	e.syncer = alerts.NewSyncer(alerts.Config{DB: pool, Instances: []alerts.Instance{{Name: "default", URL: e.lapi.URL, Watcher: w}}, Logger: log})
	e.pokes = make(chan string, 16)
	e.server, err = New(Config{DB: pool, Auth: chain, ReadOnly: readOnly, Geo: g, Policies: policy.New(pool, g, log), Settings: settings.New(pool),
		HostKey: func() string { return "ssh-ed25519 AAAA host" }, Replica: "r1", Version: "test", Suricontroller: su, PrincipalKey: priv, Logger: log,
		Alerts: &alerts.Querier{DB: pool}, AlertStore: &alerts.Store{DB: pool}, LAPIs: []LAPI{{Name: "default", Watcher: w}},
		Poke: func(i string) { e.pokes <- i }, Hub: hub.NewStore(pool, log), LogPrograms: logprog.New(pool, settings.New(pool), log)})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	e.server.Mount(mux)
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

// client returns API clients sharing a cookie jar; headers are added to
// every request.
type clients struct {
	http   *http.Client
	alerts apiv1connect.AlertServiceClient
	dec    apiv1connect.DecisionServiceClient
	dash   apiv1connect.DashboardServiceClient
	auth   apiv1connect.AuthServiceClient
	nodes  apiv1connect.NodeServiceClient
	pol    apiv1connect.PolicyServiceClient
	system apiv1connect.SystemServiceClient
	geo    apiv1connect.GeoServiceClient
	hub    apiv1connect.HubServiceClient
}

type headerRT struct {
	h    http.Header
	base http.RoundTripper
}

func (h headerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.h {
		r.Header[k] = v
	}
	return h.base.RoundTrip(r)
}

func (e *env) clients(h http.Header) *clients {
	jar, _ := cookiejar.New(nil)
	if h == nil {
		h = http.Header{}
	}
	hc := &http.Client{Jar: jar, Transport: headerRT{h: h, base: http.DefaultTransport}}
	base := e.srv.URL + "/api"
	return &clients{http: hc,
		alerts: apiv1connect.NewAlertServiceClient(hc, base), dec: apiv1connect.NewDecisionServiceClient(hc, base),
		dash: apiv1connect.NewDashboardServiceClient(hc, base),
		auth: apiv1connect.NewAuthServiceClient(hc, base), nodes: apiv1connect.NewNodeServiceClient(hc, base),
		pol: apiv1connect.NewPolicyServiceClient(hc, base), system: apiv1connect.NewSystemServiceClient(hc, base),
		geo: apiv1connect.NewGeoServiceClient(hc, base), hub: apiv1connect.NewHubServiceClient(hc, base)}
}

func code(err error) connect.Code {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Code()
	}
	return 0
}

func viewerHeaders(user, groups string) http.Header {
	return http.Header{"Remote-User": {user}, "Remote-Groups": {groups}, "X-Proxy-Secret": {"proxy"}}
}

func TestAuthAndRBAC(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	anon := e.clients(nil)
	info, err := anon.auth.GetAuthInfo(ctx, connect.NewRequest(&apiv1.GetAuthInfoRequest{}))
	if err != nil || info.Msg.Principal != nil || !info.Msg.PasswordLogin {
		t.Fatalf("anonymous auth info: %v %v", info, err)
	}
	if _, err := anon.nodes.ListNodes(ctx, connect.NewRequest(&apiv1.ListNodesRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("anonymous list: %v", err)
	}
	if _, err := anon.auth.Login(ctx, connect.NewRequest(&apiv1.LoginRequest{Username: "admin", Password: "nope"})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad login: %v", err)
	}
	lr, err := anon.auth.Login(ctx, connect.NewRequest(&apiv1.LoginRequest{Username: "admin", Password: "s3cret-pw"}))
	if err != nil || lr.Msg.Principal.GetRole() != auth.RoleAdmin {
		t.Fatalf("login: %v %v", lr, err)
	}
	admin := anon // the jar holds the session now
	info, _ = admin.auth.GetAuthInfo(ctx, connect.NewRequest(&apiv1.GetAuthInfoRequest{}))
	if info.Msg.Principal.GetId() != "static:admin" {
		t.Fatalf("auth info after login: %v", info.Msg)
	}

	key, _ := sshkey.Generate()
	reg, err := admin.nodes.RegisterNode(ctx, connect.NewRequest(&apiv1.RegisterNodeRequest{PublicKey: key.Public("edge-01").String(), Labels: map[string]string{"site": "seoul"}}))
	if err != nil || reg.Msg.Node.GetId() != "edge-01" || reg.Msg.Node.GetLabels()["site"] != "seoul" || reg.Msg.Node.GetDataPlane().GetConnected() {
		t.Fatalf("register: %v %v", reg, err)
	}
	if _, err := admin.nodes.RegisterNode(ctx, connect.NewRequest(&apiv1.RegisterNodeRequest{PublicKey: key.Public("edge-01").String()})); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := admin.nodes.UpdateNode(ctx, connect.NewRequest(&apiv1.UpdateNodeRequest{Id: "edge-01", SetLabels: true, Labels: map[string]string{"Bad Key": "x"}})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad label: %v", err)
	}
	disabled := false
	up, err := admin.nodes.UpdateNode(ctx, connect.NewRequest(&apiv1.UpdateNodeRequest{Id: "edge-01", Enabled: &disabled}))
	if err != nil || up.Msg.Node.GetEnabled() || up.Msg.Node.GetLabels()["site"] != "seoul" {
		t.Fatalf("update: %v %v", up, err)
	}

	viewer := e.clients(viewerHeaders("vera", "staff"))
	list, err := viewer.nodes.ListNodes(ctx, connect.NewRequest(&apiv1.ListNodesRequest{}))
	if err != nil || len(list.Msg.Nodes) != 1 {
		t.Fatalf("viewer list: %v %v", list, err)
	}
	if _, err := viewer.nodes.DeleteNode(ctx, connect.NewRequest(&apiv1.DeleteNodeRequest{Id: "edge-01"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer delete: %v", err)
	}
	if _, err := viewer.system.ListAudit(ctx, connect.NewRequest(&apiv1.ListAuditRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer audit: %v", err)
	}
	vinfo, _ := viewer.auth.GetAuthInfo(ctx, connect.NewRequest(&apiv1.GetAuthInfoRequest{}))
	if vinfo.Msg.Principal.GetRole() != auth.RoleViewer || vinfo.Msg.LogoutUrl != "https://sso/logout" {
		t.Fatalf("viewer info: %v", vinfo.Msg)
	}
	nobody := e.clients(viewerHeaders("mallory", "guests"))
	if _, err := nobody.nodes.ListNodes(ctx, connect.NewRequest(&apiv1.ListNodesRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("unmapped user: %v", err)
	}
	// A wrong proxy secret is an invalid credential, not a fallback to
	// the next provider.
	forged := e.clients(http.Header{"Remote-User": {"admin"}, "X-Proxy-Secret": {"guess"}})
	if _, err := forged.nodes.ListNodes(ctx, connect.NewRequest(&apiv1.ListNodesRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("forged header: %v", err)
	}

	operator := e.clients(viewerHeaders("olga", "secops"))
	if _, err := operator.system.SetLogPolicy(ctx, connect.NewRequest(&apiv1.SetLogPolicyRequest{Reset_: true})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("operator system setting: %v", err)
	}
	if _, err := operator.nodes.DeleteNode(ctx, connect.NewRequest(&apiv1.DeleteNodeRequest{Id: "edge-01"})); err != nil {
		t.Fatal(err)
	}
	audit, err := admin.system.ListAudit(ctx, connect.NewRequest(&apiv1.ListAuditRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range audit.Msg.Entries {
		got = append(got, a.Principal+" "+a.Action+" "+a.Target)
		if strings.Contains(a.Detail, "s3cret") {
			t.Fatalf("password in audit: %s", a.Detail)
		}
	}
	want := []string{"header:olga NodeService.DeleteNode edge-01", "static:admin NodeService.UpdateNode edge-01", "static:admin NodeService.RegisterNode edge-01",
		"static:admin AuthService.Login static:admin", "anonymous AuthService.LoginFailed admin"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	if _, err := admin.auth.Logout(ctx, connect.NewRequest(&apiv1.LogoutRequest{})); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.nodes.ListNodes(ctx, connect.NewRequest(&apiv1.ListNodesRequest{})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("after logout: %v", err)
	}
}

func TestCSRFAndReadOnly(t *testing.T) {
	e := setup(t, true)
	ctx := context.Background()
	admin := e.clients(nil)
	if _, err := admin.auth.Login(ctx, connect.NewRequest(&apiv1.LoginRequest{Username: "admin", Password: "s3cret-pw"})); err != nil {
		t.Fatal(err)
	}
	// Cross-site requests are refused whatever the credentials.
	evil := e.clients(http.Header{"Origin": {"https://evil.example"}})
	evil.http.Jar = admin.http.Jar
	if _, err := evil.nodes.ListNodes(ctx, connect.NewRequest(&apiv1.ListNodesRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-origin: %v", err)
	}
	same := e.clients(http.Header{"Origin": {e.srv.URL}})
	same.http.Jar = admin.http.Jar
	if _, err := same.nodes.ListNodes(ctx, connect.NewRequest(&apiv1.ListNodesRequest{})); err != nil {
		t.Fatalf("same origin: %v", err)
	}
	// A form post (no Connect headers) is refused.
	req, _ := http.NewRequest("POST", e.srv.URL+"/api"+apiv1connect.NodeServiceListNodesProcedure, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "text/plain")
	res, err := admin.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("form post: %d", res.StatusCode)
	}
	// Read-only: changes are refused, preferences are not.
	key, _ := sshkey.Generate()
	if _, err := admin.nodes.RegisterNode(ctx, connect.NewRequest(&apiv1.RegisterNodeRequest{PublicKey: key.Public("edge-02").String()})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("read-only register: %v", err)
	}
	f, err := admin.system.SaveFilter(ctx, connect.NewRequest(&apiv1.SaveFilterRequest{Filter: &apiv1.SavedFilter{Page: "alerts", Name: "c2", Query: "scenario:outbound"}}))
	if err != nil {
		t.Fatalf("read-only save filter: %v", err)
	}
	other := e.clients(viewerHeaders("vera", "staff"))
	if l, _ := other.system.ListSavedFilters(ctx, connect.NewRequest(&apiv1.ListSavedFiltersRequest{Page: "alerts"})); len(l.Msg.Filters) != 0 {
		t.Fatal("private filter visible to another user")
	}
	if _, err := other.system.DeleteSavedFilter(ctx, connect.NewRequest(&apiv1.DeleteSavedFilterRequest{Id: f.Msg.Filter.Id})); code(err) != connect.CodeNotFound {
		t.Fatalf("delete someone else's filter: %v", err)
	}
	if _, err := other.system.SaveFilter(ctx, connect.NewRequest(&apiv1.SaveFilterRequest{Filter: &apiv1.SavedFilter{Page: "alerts", Name: "x", Shared: true}})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer shares: %v", err)
	}
}

func TestPoliciesAndGeo(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	op := e.clients(viewerHeaders("olga", "secops"))
	put := func(id string, cc string) {
		t.Helper()
		_, err := op.pol.PutPolicy(ctx, connect.NewRequest(&apiv1.PutPolicyRequest{Policy: &apiv1.Policy{Id: id, Enabled: true, Mode: "enforce", Proto: "tcp",
			Ports: []*apiv1.PortRange{{From: 443, To: 443}}, DefaultAction: "accept",
			Rules: []*apiv1.PolicyRule{{Source: &apiv1.PolicySource{Countries: []string{cc}}, Action: "drop"}},
			Scope: &apiv1.PolicyScope{Labels: map[string]*apiv1.LabelValues{"site": {Values: []string{"seoul"}}}}}}))
		if err != nil {
			t.Fatal(err)
		}
	}
	put("block_cn", "CN")
	put("block_ru", "RU")
	if _, err := op.pol.PutPolicy(ctx, connect.NewRequest(&apiv1.PutPolicyRequest{Policy: &apiv1.Policy{Id: "Bad"}})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid: %v", err)
	}
	if _, err := op.pol.ReorderPolicies(ctx, connect.NewRequest(&apiv1.ReorderPoliciesRequest{Ids: []string{"block_ru"}})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("partial reorder: %v", err)
	}
	if _, err := op.pol.ReorderPolicies(ctx, connect.NewRequest(&apiv1.ReorderPoliciesRequest{Ids: []string{"block_ru", "block_cn"}})); err != nil {
		t.Fatal(err)
	}
	l, err := op.pol.ListPolicies(ctx, connect.NewRequest(&apiv1.ListPoliciesRequest{}))
	if err != nil || len(l.Msg.Policies) != 2 || l.Msg.Policies[0].Id != "block_ru" || l.Msg.Policies[1].UpdatedBy != "header:olga" ||
		l.Msg.Policies[1].Scope.Labels["site"].Values[0] != "seoul" {
		t.Fatalf("list: %v %v", l, err)
	}
	if _, err := op.pol.PutAddressList(ctx, connect.NewRequest(&apiv1.PutAddressListRequest{List: &apiv1.AddressList{Name: "google", Asns: []uint32{15169}, Description: "Google"}})); err != nil {
		t.Fatal(err)
	}
	h, _ := op.pol.PolicyHistory(ctx, connect.NewRequest(&apiv1.PolicyHistoryRequest{}))
	if len(h.Msg.Changes) != 4 || h.Msg.Changes[0].PolicyId != "list:google" || h.Msg.Changes[1].Action != "reorder" {
		t.Fatalf("history: %v", h.Msg.Changes)
	}
	if _, err := op.pol.PutPolicy(ctx, connect.NewRequest(&apiv1.PutPolicyRequest{Policy: &apiv1.Policy{Id: "smtp_google", Enabled: true, Mode: "enforce", Proto: "tcp",
		Ports: []*apiv1.PortRange{{From: 587, To: 587}}, DefaultAction: "drop",
		Rules: []*apiv1.PolicyRule{{Source: &apiv1.PolicySource{Lists: []string{"google"}}, Action: "accept"}}}})); err != nil {
		t.Fatal(err)
	}
	if _, err := op.pol.DeleteAddressList(ctx, connect.NewRequest(&apiv1.DeleteAddressListRequest{Name: "google"})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("delete used list: %v", err)
	}
	if ls, _ := op.pol.ListAddressLists(ctx, connect.NewRequest(&apiv1.ListAddressListsRequest{})); len(ls.Msg.Lists) != 1 || ls.Msg.Lists[0].UsedBy[0] != "smtp_google" {
		t.Fatalf("history: %v", h.Msg.Changes)
	}

	// Upload (admin only, needs the custom header).
	upload := func(c *clients, extra bool) int {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("file", "GeoLite2-Country.mmdb")
		_, _ = fw.Write(geoiptest.Country(t, map[string]string{"1.0.0.0/24": "CN"}))
		_ = mw.Close()
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/geo/upload", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		if extra {
			req.Header.Set("X-OpenPicket-Request", "1")
		}
		res, err := c.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		return res.StatusCode
	}
	if c := upload(op, true); c != http.StatusForbidden {
		t.Fatalf("operator upload: %d", c)
	}
	admin := e.clients(viewerHeaders("root", "secops"))
	e.server.cfg.Auth.Roles = auth.Roles{Admin: auth.RoleConfig{Users: []string{"root"}}, Operator: auth.RoleConfig{Groups: []string{"secops"}}}
	if c := upload(admin, false); c != http.StatusForbidden {
		t.Fatalf("upload without header: %d", c)
	}
	if c := upload(admin, true); c != http.StatusOK {
		t.Fatalf("upload: %d", c)
	}
	dbs, _ := admin.geo.ListDatabases(ctx, connect.NewRequest(&apiv1.ListDatabasesRequest{}))
	if len(dbs.Msg.Databases) != 1 || dbs.Msg.Databases[0].Kind != "country" || !dbs.Msg.Loaded {
		t.Fatalf("databases: %v", dbs.Msg)
	}
	lk, _ := admin.geo.Lookup(ctx, connect.NewRequest(&apiv1.GeoLookupRequest{Ips: []string{"1.0.0.9", "9.9.9.9"}}))
	if lk.Msg.Results[0].Country != "CN" || lk.Msg.Results[1].Country != "" {
		t.Fatalf("lookup: %v", lk.Msg)
	}

	key, _ := sshkey.Generate()
	if _, err := admin.nodes.RegisterNode(ctx, connect.NewRequest(&apiv1.RegisterNodeRequest{PublicKey: key.Public("edge-01").String(), Labels: map[string]string{"site": "seoul"}})); err != nil {
		t.Fatal(err)
	}
	pv, err := admin.pol.PreviewBundle(ctx, connect.NewRequest(&apiv1.PreviewBundleRequest{NodeId: "edge-01"}))
	if err != nil {
		t.Fatal(err)
	}
	// RU has no networks in the test database (an empty set); the AS
	// policy is skipped without an ASN database.
	if len(pv.Msg.Policies) != 2 || pv.Msg.Policies[0] != "block_ru" || len(pv.Msg.Skipped) != 1 || pv.Msg.Skipped[0].PolicyId != "smtp_google" ||
		pv.Msg.Skipped[0].Stale || pv.Msg.Elements != 1 {
		t.Fatalf("preview: %v", pv.Msg)
	}
	// The policy list shows why a policy does not compile.
	lp, _ := op.pol.ListPolicies(ctx, connect.NewRequest(&apiv1.ListPoliciesRequest{}))
	for _, p := range lp.Msg.Policies {
		if (p.Id == "smtp_google") != (p.CompileError != "") || p.Stale {
			t.Fatalf("compile status of %s: %q stale=%v", p.Id, p.CompileError, p.Stale)
		}
	}
	// The country database cannot be deleted while enabled policies use it.
	_, err = admin.geo.DeleteDatabase(ctx, connect.NewRequest(&apiv1.DeleteDatabaseRequest{Kind: "country"}))
	if code(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "block_cn") || !strings.Contains(err.Error(), "block_ru") {
		t.Fatalf("delete used database: %v", err)
	}
	for _, p := range lp.Msg.Policies {
		if p.Id == "block_cn" || p.Id == "block_ru" {
			p.Enabled = false
			if _, err := op.pol.PutPolicy(ctx, connect.NewRequest(&apiv1.PutPolicyRequest{Policy: p})); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := admin.geo.DeleteDatabase(ctx, connect.NewRequest(&apiv1.DeleteDatabaseRequest{Kind: "country"})); err != nil {
		t.Fatalf("delete unused database: %v", err)
	}
}

func TestSuricontrollerProxy(t *testing.T) {
	e := setup(t, true)
	op := e.clients(viewerHeaders("olga", "secops"))
	req, _ := http.NewRequest("POST", e.srv.URL+"/suricata/api/suricontroller.api.v1.NodeService/ListNodes", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(principal.Header, "forged")
	req.AddCookie(&http.Cookie{Name: "openpicket_session", Value: "x"})
	res, err := op.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != 200 || string(body) != "suricontroller /base/api/suricontroller.api.v1.NodeService/ListNodes" {
		t.Fatalf("proxy: %d %s", res.StatusCode, body)
	}
	got := <-e.suri
	if got.Header.Get("Cookie") != "" {
		t.Fatal("cookies forwarded")
	}
	c, err := principal.Verify(e.pub, got.Header.Get(principal.Header), principal.AudienceSuricontroller, time.Now())
	if err != nil || c.Subject != "header:olga" {
		t.Fatalf("token: %+v %v", c, err)
	}
	// Read-only mode downgrades to viewer.
	if len(c.Roles) != 1 || c.Roles[0] != principal.RoleViewer {
		t.Fatalf("roles: %v", c.Roles)
	}
	// Unauthenticated browser navigation goes to the login page.
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ = http.NewRequest("GET", e.srv.URL+"/suricata/nodes", nil)
	req.Header.Set("Accept", "text/html")
	res, err = anon.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/login?next=%2Fsuricata%2Fnodes" {
		t.Fatalf("redirect: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(2, time.Minute)
	now := time.Unix(1000, 0)
	for i, want := range []bool{true, true, false} {
		if l.allow("a", now) != want {
			t.Fatalf("attempt %d: want %v", i, want)
		}
	}
	if !l.allow("b", now) {
		t.Fatal("keys are independent")
	}
	if !l.allow("a", now.Add(61*time.Second)) {
		t.Fatal("window")
	}
}

type fence struct{ s *Server }

func (f fence) Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, f.s.cfg.DB, fn)
}

func TestDecisions(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	sync := func() {
		t.Helper()
		if err := e.syncer.SyncOnce(ctx, fence{e.server}, true, true); err != nil {
			t.Fatal(err)
		}
	}
	e.lapi.Add("crowdsecurity/ssh-bf", "198.51.100.4", "CN", "edge-01", 4*time.Hour, time.Now())
	sync()
	op := e.clients(viewerHeaders("olga", "secops"))
	viewer := e.clients(viewerHeaders("vera", "staff"))
	if _, err := viewer.dec.AddDecision(ctx, connect.NewRequest(&apiv1.AddDecisionRequest{Value: "198.51.100.9"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer add: %v", err)
	}
	for _, bad := range []*apiv1.AddDecisionRequest{
		{Value: "not-an-ip"}, {Scope: "Range", Value: "10.0.0.0/4"}, {Value: "198.51.100.9", Duration: "forever"}, {Value: "198.51.100.9", Type: "nuke"},
	} {
		if _, err := op.dec.AddDecision(ctx, connect.NewRequest(bad)); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if _, err := op.dec.AddDecision(ctx, connect.NewRequest(&apiv1.AddDecisionRequest{Value: "198.51.100.9", Duration: "30d", Reason: "phishing",
		Scenario: "openpicket/manual-both"})); err != nil {
		t.Fatal(err)
	}
	if got := <-e.pokes; got != "default" {
		t.Fatalf("poke %q", got)
	}
	created := e.lapi.Alerts()[1]
	d := created.Decisions[0]
	if *d.Origin != "cscli" || *d.Scenario != "openpicket/manual-both" || *d.Value != "198.51.100.9" || !strings.Contains(*created.Message, "olga") {
		t.Fatalf("pushed alert: %+v %+v", created, d)
	}
	if until, _ := time.Parse(time.RFC3339, d.Until); time.Until(until) < 29*24*time.Hour {
		t.Fatalf("until %v", d.Until)
	}
	sync()
	list, err := viewer.dec.SearchDecisions(ctx, connect.NewRequest(&apiv1.SearchDecisionsRequest{}))
	if err != nil || list.Msg.Total != 2 || list.Msg.Decisions[0].Value != "198.51.100.9" {
		t.Fatalf("decisions: %v %v", list, err)
	}
	if _, err := viewer.dec.SearchDecisions(ctx, connect.NewRequest(&apiv1.SearchDecisionsRequest{Query: "bad:"})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad query: %v", err)
	}
	del, err := op.dec.DeleteDecisions(ctx, connect.NewRequest(&apiv1.DeleteDecisionsRequest{Instance: "default", Ids: []int64{list.Msg.Decisions[0].Id}}))
	if err != nil || del.Msg.Deleted != 1 {
		t.Fatalf("delete: %v %v", del, err)
	}
	// The copy follows at once, before the next sync.
	list, _ = viewer.dec.SearchDecisions(ctx, connect.NewRequest(&apiv1.SearchDecisionsRequest{}))
	if list.Msg.Total != 1 {
		t.Fatalf("after delete: %v", list.Msg)
	}
	// It stays in the list with expired decisions, like in the LAPI.
	all, _ := viewer.dec.SearchDecisions(ctx, connect.NewRequest(&apiv1.SearchDecisionsRequest{IncludeExpired: true}))
	if all.Msg.Total != 2 || all.Msg.Decisions[1].Active {
		t.Fatalf("with expired: %v", all.Msg)
	}
	cl, err := op.dec.CleanupIP(ctx, connect.NewRequest(&apiv1.CleanupIPRequest{Ip: "198.51.100.4", DeleteAlerts: true}))
	if err != nil || cl.Msg.DecisionsDeleted != 1 || cl.Msg.AlertsDeleted != 1 {
		t.Fatalf("cleanup: %v %v", cl, err)
	}
	sync()
	al, _ := viewer.alerts.SearchAlerts(ctx, connect.NewRequest(&apiv1.SearchAlertsRequest{}))
	if al.Msg.Total != 1 || al.Msg.Alerts[0].Scenario != "openpicket/manual-both" {
		t.Fatalf("alerts: %v", al.Msg)
	}
	sum, err := viewer.dash.GetSummary(ctx, connect.NewRequest(&apiv1.GetSummaryRequest{}))
	if err != nil || sum.Msg.Alerts != 1 || sum.Msg.ActiveDecisions != 0 {
		t.Fatalf("summary: %v %v", sum, err)
	}
	audit, _ := e.clients(viewerHeaders("olga", "secops")).system.ListAudit(ctx, connect.NewRequest(&apiv1.ListAuditRequest{ActionPrefix: "DecisionService."}))
	if len(audit.Msg.Entries) != 3 || audit.Msg.Entries[2].Target != "198.51.100.9" || audit.Msg.Entries[0].Target != "198.51.100.4" {
		t.Fatalf("audit: %v", audit.Msg.Entries)
	}
}

func TestLogQL(t *testing.T) {
	q, err := LogQL(&apiv1.LogFilter{Nodes: []string{"edge-01", "edge.02"}, Types: []string{"eve"}, EventTypes: []string{"alert"}, Ip: "198.51.100.4",
		Text: "ET SCAN (x)", Direction: "inbound"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{job="openpicket", node=~"^(edge-01|edge\\.02)$", type=~"^(eve)$", event_type=~"^(alert)$"} |~ "(?i)ET SCAN \\(x\\)"` +
		` | src_ip="198.51.100.4" or dest_ip="198.51.100.4" or remote_ip="198.51.100.4" | direction="inbound"`
	if q != want {
		t.Fatalf("got  %s\nwant %s", q, want)
	}
	if _, err := LogQL(&apiv1.LogFilter{Nodes: []string{`a"}`}}); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("injection: %v", err)
	}
}

func TestLogsAndNotifications(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	var mu sync.Mutex
	type line struct {
		ts   time.Time
		text string
	}
	var lines []line
	add := func(text string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, line{time.Now(), text})
		time.Sleep(time.Millisecond)
	}
	fakeLoki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Scope-OrgID") != "openpicket" {
			http.Error(w, "no tenant", http.StatusUnauthorized)
			return
		}
		if strings.Contains(r.URL.Query().Get("query"), "bad") {
			http.Error(w, "parse error", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		start, _ := strconv.ParseInt(r.URL.Query().Get("start"), 10, 64)
		var values [][]any
		for _, l := range lines {
			if l.ts.UnixNano() < start {
				continue
			}
			values = append(values, []any{strconv.FormatInt(l.ts.UnixNano(), 10), l.text,
				map[string]any{"structuredMetadata": map[string]any{"src_ip": "198.51.100.4"}}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams",
			"result": []any{map[string]any{"stream": map[string]string{"node": "edge-01", "type": "eve"}, "values": values}}}})
	}))
	defer fakeLoki.Close()
	lq, _ := loki.NewQuerier(loki.Config{URL: fakeLoki.URL + "/loki/api/v1/push"}, "")
	e.server.cfg.Logs = lq
	add(`{"event_type":"alert","n":1}`)
	add(`{"event_type":"alert","n":2}`)
	viewer := e.clients(viewerHeaders("vera", "staff"))
	logs := apiv1connect.NewLogServiceClient(viewer.http, e.srv.URL+"/api")
	res, err := logs.QueryLogs(ctx, connect.NewRequest(&apiv1.QueryLogsRequest{Filter: &apiv1.LogFilter{Nodes: []string{"edge-01"}}}))
	if err != nil || len(res.Msg.Entries) != 2 || res.Msg.Entries[0].Line != lines[1].text || res.Msg.Entries[0].Labels["src_ip"] != "198.51.100.4" {
		t.Fatalf("query: %v %v", res, err)
	}
	if _, err := logs.QueryLogs(ctx, connect.NewRequest(&apiv1.QueryLogsRequest{Filter: &apiv1.LogFilter{Logql: `{job="bad"}`}})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad logql: %v", err)
	}
	TailInterval = 50 * time.Millisecond
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream, err := logs.TailLogs(tctx, connect.NewRequest(&apiv1.TailLogsRequest{Filter: &apiv1.LogFilter{}}))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() || len(stream.Msg().Entries) != 2 {
		t.Fatalf("first tail batch: %v", stream.Err())
	}
	add(`{"event_type":"alert","n":3}`)
	if !stream.Receive() || len(stream.Msg().Entries) != 1 || !strings.Contains(stream.Msg().Entries[0].Line, `"n":3`) {
		t.Fatalf("second tail batch: %v %v", stream.Msg(), stream.Err())
	}
	cancel()
	_ = stream.Close()

	// Notifications: secrets are write-only and never audited.
	admin := e.clients(viewerHeaders("root", "secops"))
	e.server.cfg.Auth.Roles = auth.Roles{Admin: auth.RoleConfig{Users: []string{"root"}}, Viewer: auth.RoleConfig{Groups: []string{"staff"}}}
	e.server.cfg.Notify = notify.NewEngine(notify.Config{DB: e.server.cfg.DB})
	nc := apiv1connect.NewNotificationServiceClient(admin.http, e.srv.URL+"/api")
	hook, ch := httptestCapture(t)
	put, err := nc.PutDestination(ctx, connect.NewRequest(&apiv1.PutDestinationRequest{Destination: &apiv1.Destination{Id: "hook", Name: "Hook", Type: "webhook",
		Enabled: true, Config: map[string]string{"url": hook}, Secrets: map[string]string{"authorization": "Bearer s3cr3t-token"}}}))
	if err != nil || len(put.Msg.Destination.Secrets) != 0 || put.Msg.Destination.SecretKeys[0] != "authorization" {
		t.Fatalf("put destination: %v %v", put, err)
	}
	// Saving again without the secret keeps it; the test uses it.
	if _, err := nc.PutDestination(ctx, connect.NewRequest(&apiv1.PutDestinationRequest{Destination: &apiv1.Destination{Id: "hook", Name: "Hook 2", Type: "webhook",
		Enabled: true, Config: map[string]string{"url": hook}}})); err != nil {
		t.Fatal(err)
	}
	tr, err := nc.TestDestination(ctx, connect.NewRequest(&apiv1.TestDestinationRequest{Destination: &apiv1.Destination{Id: "hook", Name: "Hook", Type: "webhook",
		Config: map[string]string{"url": hook}}}))
	if err != nil || !tr.Msg.Ok {
		t.Fatalf("test: %v %v", tr, err)
	}
	if auth := <-ch; auth != "Bearer s3cr3t-token" {
		t.Fatalf("secret not kept: %q", auth)
	}
	if _, err := nc.PutRule(ctx, connect.NewRequest(&apiv1.PutRuleRequest{Rule: &apiv1.Rule{Id: "bans", Name: "Bans", Type: "ip_ban", Enabled: true,
		Destinations: []string{"hook"}}})); err != nil {
		t.Fatal(err)
	}
	if _, err := nc.PutRule(ctx, connect.NewRequest(&apiv1.PutRuleRequest{Rule: &apiv1.Rule{Id: "x", Name: "X", Type: "telepathy"}})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad rule: %v", err)
	}
	vn := apiv1connect.NewNotificationServiceClient(viewer.http, e.srv.URL+"/api")
	if _, err := vn.ListDestinations(ctx, connect.NewRequest(&apiv1.ListDestinationsRequest{})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer destinations: %v", err)
	}
	if _, err := e.server.cfg.DB.Exec(ctx, `INSERT INTO openpicket.notifications (rule_id, rule_name, severity, title, body) VALUES ('bans','Bans','warning','Ban x','b')`); err != nil {
		t.Fatal(err)
	}
	ln, err := vn.ListNotifications(ctx, connect.NewRequest(&apiv1.ListNotificationsRequest{}))
	if err != nil || ln.Msg.Unread != 1 || ln.Msg.Notifications[0].Read {
		t.Fatalf("list: %v %v", ln, err)
	}
	if _, err := vn.MarkNotificationsRead(ctx, connect.NewRequest(&apiv1.MarkNotificationsReadRequest{All: true})); err != nil {
		t.Fatal(err)
	}
	ln, _ = vn.ListNotifications(ctx, connect.NewRequest(&apiv1.ListNotificationsRequest{}))
	if ln.Msg.Unread != 0 || !ln.Msg.Notifications[0].Read {
		t.Fatalf("after read: %v", ln.Msg)
	}
	// Another user still has it unread.
	other, _ := apiv1connect.NewNotificationServiceClient(admin.http, e.srv.URL+"/api").ListNotifications(ctx, connect.NewRequest(&apiv1.ListNotificationsRequest{}))
	if other.Msg.Unread != 1 {
		t.Fatalf("other user: %v", other.Msg)
	}
	audit, _ := admin.system.ListAudit(ctx, connect.NewRequest(&apiv1.ListAuditRequest{ActionPrefix: "NotificationService."}))
	for _, a := range audit.Msg.Entries {
		if strings.Contains(a.Detail, "s3cr3t") {
			t.Fatalf("secret in audit: %s", a.Detail)
		}
	}
	if len(audit.Msg.Entries) < 3 {
		t.Fatalf("audit: %v", audit.Msg.Entries)
	}
}

func httptestCapture(t *testing.T) (string, chan string) {
	ch := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ch <- r.Header.Get("Authorization") }))
	t.Cleanup(srv.Close)
	return srv.URL, ch
}

// Every procedure of every API service must be in the access table: a
// missing one is refused at runtime.
func TestEveryProcedureHasAnEntry(t *testing.T) {
	n := 0
	protoregistry.GlobalFiles.RangeFilesByPackage("openpicket.api.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := 0; i < fd.Services().Len(); i++ {
			svc := fd.Services().Get(i)
			for j := 0; j < svc.Methods().Len(); j++ {
				p := "/" + string(svc.FullName()) + "/" + string(svc.Methods().Get(j).Name())
				n++
				if _, ok := procedures[p]; !ok {
					t.Errorf("%s has no access entry", p)
				}
			}
		}
		return true
	})
	if n < 50 {
		t.Fatalf("only %d procedures found", n)
	}
}

func TestIntel(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	viewer := e.clients(viewerHeaders("vera", "staff"))
	ic := apiv1connect.NewIntelServiceClient(viewer.http, e.srv.URL+"/api")
	st, err := ic.GetIntelStatus(ctx, connect.NewRequest(&apiv1.GetIntelStatusRequest{}))
	if err != nil || st.Msg.Configured {
		t.Fatalf("unconfigured: %v %v", st, err)
	}
	fake := misptest.New()
	defer fake.Close()
	mc, _ := misp.NewClient(misp.ClientConfig{URL: fake.URL, APIKey: fake.Key})
	lc, _ := lapi.New(lapi.Config{URL: e.lapi.URL, Login: e.lapi.Login, Password: e.lapi.Password})
	w, _ := lc.Watcher()
	svc := misp.New(misp.Config{DB: e.server.cfg.DB, Client: mc, LAPI: w, Logger: slog.New(slog.DiscardHandler)})
	e.server.cfg.MISP = svc
	e.server.cfg.MISPSettings = MISPSettings{DefaultTTL: "30d"}
	if _, err := ic.ProposeIOC(ctx, connect.NewRequest(&apiv1.ProposeIOCRequest{Value: "198.51.100.8"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer propose: %v", err)
	}
	op := apiv1connect.NewIntelServiceClient(e.clients(viewerHeaders("olga", "secops")).http, e.srv.URL+"/api")
	if _, err := op.ProposeIOC(ctx, connect.NewRequest(&apiv1.ProposeIOCRequest{Value: "not-ip"})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad value: %v", err)
	}
	res, err := op.ProposeIOC(ctx, connect.NewRequest(&apiv1.ProposeIOCRequest{Value: "198.51.100.8", Type: "ip-dst", Comment: "phishing"}))
	if err != nil || res.Msg.Ioc.State != "proposed" {
		t.Fatalf("propose: %v %v", res, err)
	}
	if a := fake.Attributes(); len(a) != 1 || !strings.Contains(a[0].Comment, "olga") || !strings.Contains(a[0].Comment, "phishing") {
		t.Fatalf("misp attribute: %+v", a)
	}
	if err := svc.Sync(ctx, fence{e.server}); err != nil {
		t.Fatal(err)
	}
	if _, err := op.SetIOCState(ctx, connect.NewRequest(&apiv1.SetIOCStateRequest{Uuids: []string{res.Msg.Ioc.Uuid}, State: "approved", Ttl: "forever"})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad ttl: %v", err)
	}
	if _, err := op.SetIOCState(ctx, connect.NewRequest(&apiv1.SetIOCStateRequest{Uuids: []string{res.Msg.Ioc.Uuid}, State: "approved", Ttl: "7d"})); err != nil {
		t.Fatal(err)
	}
	list, err := ic.ListIOCs(ctx, connect.NewRequest(&apiv1.ListIOCsRequest{State: "approved"}))
	if err != nil || list.Msg.Total != 1 || list.Msg.Iocs[0].Ttl != "7d" || list.Msg.Iocs[0].ExpiresAt == nil {
		t.Fatalf("list: %v %v", list, err)
	}
	audit, _ := e.clients(viewerHeaders("olga", "secops")).system.ListAudit(ctx, connect.NewRequest(&apiv1.ListAuditRequest{ActionPrefix: "IntelService."}))
	if len(audit.Msg.Entries) != 2 {
		t.Fatalf("audit: %v", audit.Msg.Entries)
	}
}
