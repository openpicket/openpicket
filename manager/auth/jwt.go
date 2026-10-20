package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// JWT verifies signed tokens from a header or cookie: Cloudflare Access
// (Cf-Access-Jwt-Assertion), Pomerium, an IdP cookie, or service account
// tokens for automation. Keys come from a JWKS URL (refreshed) or a static
// JWKS document (offline).
type JWT struct {
	ProviderName string
	// Header holds the token ("Authorization" accepts "Bearer <token>").
	Header string
	// Cookie holds the token (CSRF checks then apply).
	Cookie string
	// JWKSURL is fetched and cached; StaticJWKS is used instead offline.
	JWKSURL    string
	StaticJWKS []byte
	Issuer     string
	Audience   string
	// Claim names (defaults: sub, name, email, groups).
	SubjectClaim, NameClaim, EmailClaim, GroupsClaim string
	Logout                                           string
	HTTPClient                                       *http.Client
	Now                                              func() time.Time

	mu      sync.Mutex
	keys    *jose.JSONWebKeySet
	fetched time.Time
}

var jwtAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA}

// Validate checks the configuration.
func (j *JWT) Validate() error {
	if j.Header == "" && j.Cookie == "" {
		return errors.New("auth: jwt: header or cookie is required")
	}
	if j.JWKSURL == "" && len(j.StaticJWKS) == 0 {
		return errors.New("auth: jwt: jwks_url or static keys are required")
	}
	if j.Issuer == "" || j.Audience == "" {
		return errors.New("auth: jwt: issuer and audience are required")
	}
	if len(j.StaticJWKS) > 0 {
		var ks jose.JSONWebKeySet
		if err := json.Unmarshal(j.StaticJWKS, &ks); err != nil || len(ks.Keys) == 0 {
			return errors.New("auth: jwt: static keys are not a JWKS document")
		}
	}
	return nil
}

// Name implements Provider.
func (j *JWT) Name() string {
	if j.ProviderName != "" {
		return j.ProviderName
	}
	return "jwt"
}

func (j *JWT) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

func (j *JWT) keySet(ctx context.Context, refresh bool) (*jose.JSONWebKeySet, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.StaticJWKS) > 0 {
		if j.keys == nil {
			var ks jose.JSONWebKeySet
			if err := json.Unmarshal(j.StaticJWKS, &ks); err != nil {
				return nil, err
			}
			j.keys = &ks
		}
		return j.keys, nil
	}
	if j.keys != nil && !refresh && j.now().Sub(j.fetched) < 10*time.Minute {
		return j.keys, nil
	}
	// Refetch at most every 10 seconds, even on unknown key ids.
	if j.keys != nil && j.now().Sub(j.fetched) < 10*time.Second {
		return j.keys, nil
	}
	client := j.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		if j.keys != nil {
			return j.keys, nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	var ks jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ks); err != nil {
		return nil, err
	}
	j.keys, j.fetched = &ks, j.now()
	return j.keys, nil
}

func (j *JWT) token(r *http.Request) (string, bool) {
	if j.Header != "" {
		if v := r.Header.Get(j.Header); v != "" {
			if strings.EqualFold(j.Header, "Authorization") {
				t, ok := strings.CutPrefix(v, "Bearer ")
				return strings.TrimSpace(t), ok
			}
			return strings.TrimSpace(v), true
		}
	}
	if j.Cookie != "" {
		if c, err := r.Cookie(j.Cookie); err == nil && c.Value != "" {
			return c.Value, true
		}
	}
	return "", false
}

func claimString(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// Authenticate implements Provider.
func (j *JWT) Authenticate(r *http.Request) (*Principal, error) {
	raw, ok := j.token(r)
	if !ok || raw == "" {
		return nil, ErrNoCredentials
	}
	fromCookie := j.Header == "" || r.Header.Get(j.Header) == ""
	tok, err := jwt.ParseSigned(raw, jwtAlgs)
	if err != nil || len(tok.Headers) == 0 {
		return nil, ErrInvalidCredentials
	}
	var claims map[string]any
	var std jwt.Claims
	verified := false
	for attempt := 0; attempt < 2 && !verified; attempt++ {
		ks, err := j.keySet(r.Context(), attempt == 1)
		if err != nil {
			return nil, fmt.Errorf("%w: keys: %v", ErrInvalidCredentials, err)
		}
		keys := ks.Key(tok.Headers[0].KeyID)
		if tok.Headers[0].KeyID == "" {
			keys = ks.Keys
		}
		for _, k := range keys {
			if tok.Claims(k, &std, &claims) == nil {
				verified = true
				break
			}
		}
	}
	if !verified {
		return nil, ErrInvalidCredentials
	}
	if err := std.ValidateWithLeeway(jwt.Expected{Issuer: j.Issuer, AnyAudience: jwt.Audience{j.Audience}, Time: j.now()}, 30*time.Second); err != nil {
		return nil, ErrInvalidCredentials
	}
	if std.Expiry == nil {
		return nil, ErrInvalidCredentials
	}
	sub := claimString(claims, or(j.SubjectClaim, "sub"))
	if sub == "" {
		return nil, ErrInvalidCredentials
	}
	p := &Principal{Subject: sub, Name: claimString(claims, or(j.NameClaim, "name")), Email: claimString(claims, or(j.EmailClaim, "email")), Cookie: fromCookie}
	if p.Name == "" {
		p.Name = sub
	}
	switch g := claims[or(j.GroupsClaim, "groups")].(type) {
	case []any:
		for _, v := range g {
			if s, ok := v.(string); ok {
				p.Groups = append(p.Groups, s)
			}
		}
	case string:
		p.Groups = splitGroups(g, ",")
	}
	return p, nil
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// LoginURL implements ExternalLogin.
func (j *JWT) LoginURL(string) string { return "" }

// LogoutURL implements ExternalLogin.
func (j *JWT) LogoutURL() string { return j.Logout }
