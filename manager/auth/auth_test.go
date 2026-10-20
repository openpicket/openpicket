package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/bcrypt"
)

func staticProvider(t *testing.T) *Static {
	t.Helper()
	h, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	s, err := NewStatic("admin", string(h), RoleAdmin, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStatic(t *testing.T) {
	s := staticProvider(t)
	now := time.Unix(1_800_000_000, 0)
	s.Now = func() time.Time { return now }
	if _, err := s.Login(context.Background(), "admin", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := s.Login(context.Background(), "root", "s3cret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong user: %v", err)
	}
	p, err := s.Login(context.Background(), "admin", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := s.IssueSession(rec, p); err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie attributes: %+v", cookie)
	}
	req := httptest.NewRequest("GET", "/", nil)
	if _, err := s.Authenticate(req); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("no cookie: %v", err)
	}
	req.AddCookie(cookie)
	got, err := s.Authenticate(req)
	if err != nil || got.Subject != "admin" || !got.Has(RoleAdmin) || !got.Cookie {
		t.Fatalf("session = %+v %v", got, err)
	}
	// Tampered roles fail the signature.
	tampered := httptest.NewRequest("GET", "/", nil)
	tampered.AddCookie(&http.Cookie{Name: CookieName, Value: b64.EncodeToString([]byte(`{"sub":"admin","roles":["admin"],"exp":9999999999}`)) + ".x"})
	if _, err := s.Authenticate(tampered); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("tampered: %v", err)
	}
	now = now.Add(25 * time.Hour)
	if _, err := s.Authenticate(req); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expired: %v", err)
	}
}

func TestHeader(t *testing.T) {
	h := &Header{UserHeader: "Remote-User", GroupsHeader: "Remote-Groups", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&Header{UserHeader: "X"}).Validate(); err == nil {
		t.Fatal("a header provider without trust anchor must be refused")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:4567"
	req.Header.Set("Remote-User", "alice")
	req.Header.Set("Remote-Groups", "secops, staff")
	p, err := h.Authenticate(req)
	if err != nil || p.Subject != "alice" || len(p.Groups) != 2 || p.Groups[0] != "secops" {
		t.Fatalf("principal = %+v %v", p, err)
	}
	req.RemoteAddr = "203.0.113.9:1"
	if _, err := h.Authenticate(req); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("untrusted peer: %v", err)
	}
	sec := &Header{UserHeader: "Remote-User", SecretHeader: "X-Proxy-Secret", Secret: "k"}
	req.Header.Set("X-Proxy-Secret", "nope")
	if _, err := sec.Authenticate(req); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong secret: %v", err)
	}
	req.Header.Set("X-Proxy-Secret", "k")
	if _, err := sec.Authenticate(req); err != nil {
		t.Fatalf("secret: %v", err)
	}
}

func TestJWT(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	now := time.Unix(1_800_000_000, 0)
	mint := func(iss string, exp time.Time, extra map[string]any) string {
		claims := map[string]any{"iss": iss, "aud": "openpicket", "sub": "bob", "email": "bob@example.com", "exp": exp.Unix(), "groups": []string{"ops"}}
		for k, v := range extra {
			claims[k] = v
		}
		tok, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	j := &JWT{Header: "Cf-Access-Jwt-Assertion", StaticJWKS: jwks, Issuer: "https://team.cloudflareaccess.com", Audience: "openpicket", Now: func() time.Time { return now }}
	if err := j.Validate(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", mint("https://team.cloudflareaccess.com", now.Add(time.Hour), nil))
	p, err := j.Authenticate(req)
	if err != nil || p.Subject != "bob" || p.Email != "bob@example.com" || len(p.Groups) != 1 || p.Cookie {
		t.Fatalf("principal = %+v %v", p, err)
	}
	for name, tok := range map[string]string{
		"issuer":  mint("https://evil", now.Add(time.Hour), nil),
		"expired": mint("https://team.cloudflareaccess.com", now.Add(-time.Hour), nil),
		"garbage": "abc.def.ghi",
	} {
		req.Header.Set("Cf-Access-Jwt-Assertion", tok)
		if _, err := j.Authenticate(req); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: %v", name, err)
		}
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSigner, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	forged, _ := jwt.Signed(otherSigner).Claims(map[string]any{"iss": j.Issuer, "aud": "openpicket", "sub": "eve", "exp": now.Add(time.Hour).Unix()}).Serialize()
	req.Header.Set("Cf-Access-Jwt-Assertion", forged)
	if _, err := j.Authenticate(req); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("forged: %v", err)
	}
	// JWKS URL with key rotation.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(jwks) }))
	defer srv.Close()
	jurl := &JWT{Cookie: "idp_token", JWKSURL: srv.URL, Issuer: j.Issuer, Audience: "openpicket", Now: j.Now}
	creq := httptest.NewRequest("GET", "/", nil)
	creq.AddCookie(&http.Cookie{Name: "idp_token", Value: mint(j.Issuer, now.Add(time.Hour), nil)})
	if p, err := jurl.Authenticate(creq); err != nil || !p.Cookie {
		t.Fatalf("cookie jwt: %+v %v", p, err)
	}
}

func TestForward(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Cookie") != "authelia_session=good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Remote-User", "carol")
		w.Header().Set("Remote-Groups", "admins")
	}))
	defer srv.Close()
	f := &Forward{URL: srv.URL, UserHeader: "Remote-User", GroupsHeader: "Remote-Groups"}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cookie", "authelia_session=good")
	for i := 0; i < 3; i++ {
		p, err := f.Authenticate(req)
		if err != nil || p.Subject != "carol" || p.Groups[0] != "admins" || !p.Cookie {
			t.Fatalf("principal = %+v %v", p, err)
		}
	}
	if calls != 1 {
		t.Fatalf("verify called %d times (cache)", calls)
	}
	bad := httptest.NewRequest("GET", "/", nil)
	bad.Header.Set("Cookie", "authelia_session=bad")
	if _, err := f.Authenticate(bad); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("bad cookie: %v", err)
	}
}

func TestChainAndRoles(t *testing.T) {
	s := staticProvider(t)
	h := &Header{UserHeader: "Remote-User", GroupsHeader: "Remote-Groups", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	c := &Chain{Providers: []Provider{h, s}, Roles: Roles{Operator: RoleConfig{Groups: []string{"secops"}}, Viewer: RoleConfig{Users: []string{"dave"}}}}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Remote-User", "alice")
	req.Header.Set("Remote-Groups", "secops")
	p, prov, err := c.Authenticate(req)
	if err != nil || prov.Name() != "header" || p.Role() != RoleOperator || p.ID() != "header:alice" || !p.Has(RoleViewer) || p.Has(RoleAdmin) {
		t.Fatalf("principal = %+v %v", p, err)
	}
	req.Header.Set("Remote-User", "mallory")
	req.Header.Set("Remote-Groups", "")
	if _, _, err := c.Authenticate(req); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unmatched: %v", err)
	}
	if _, _, err := c.Authenticate(httptest.NewRequest("GET", "/", nil)); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("anonymous: %v", err)
	}
	// A static session keeps its configured role.
	ps, _ := s.Login(context.Background(), "admin", "s3cret")
	rec := httptest.NewRecorder()
	_ = s.IssueSession(rec, ps)
	sreq := httptest.NewRequest("GET", "/", nil)
	sreq.AddCookie(rec.Result().Cookies()[0])
	if p, _, err := c.Authenticate(sreq); err != nil || p.Role() != RoleAdmin || p.Provider != "static" {
		t.Fatalf("static via chain: %+v %v", p, err)
	}
}
