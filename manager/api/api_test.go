package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/bcrypt"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/gen/openpicket/api/v1/apiv1connect"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager/auth"
	"github.com/openpicket/openpicket/manager/geo"
	"github.com/openpicket/openpicket/manager/policy"
	"github.com/openpicket/openpicket/manager/settings"
	"github.com/openpicket/openpicket/pkg/geoip/geoiptest"
	"github.com/openpicket/openpicket/pkg/principal"
)

type env struct {
	t      *testing.T
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
	e.server, err = New(Config{DB: pool, Auth: chain, ReadOnly: readOnly, Geo: g, Policies: policy.New(pool, g, log), Settings: settings.New(pool),
		HostKey: "ssh-ed25519 AAAA host", Replica: "r1", Version: "test", Suricontroller: su, PrincipalKey: priv, Logger: log})
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
	auth   apiv1connect.AuthServiceClient
	nodes  apiv1connect.NodeServiceClient
	pol    apiv1connect.PolicyServiceClient
	system apiv1connect.SystemServiceClient
	geo    apiv1connect.GeoServiceClient
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
		auth: apiv1connect.NewAuthServiceClient(hc, base), nodes: apiv1connect.NewNodeServiceClient(hc, base),
		pol: apiv1connect.NewPolicyServiceClient(hc, base), system: apiv1connect.NewSystemServiceClient(hc, base),
		geo: apiv1connect.NewGeoServiceClient(hc, base)}
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
	if len(pv.Msg.Policies) != 2 || pv.Msg.Policies[0] != "block_ru" || len(pv.Msg.Skipped) != 1 || pv.Msg.Skipped[0].PolicyId != "smtp_google" || pv.Msg.Elements != 1 {
		t.Fatalf("preview: %v", pv.Msg)
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
