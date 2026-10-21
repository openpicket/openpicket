package auth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/bcrypt"
)

// Config is the auth configuration file (OPENPICKET_AUTH_CONFIG). Providers
// are tried in order; the static login comes last.
//
//	providers:
//	  - type: header
//	    user_header: Remote-User
//	    groups_header: Remote-Groups
//	    trusted_proxies: [10.0.0.0/8]
//	static:
//	  username: admin
//	  password_hash: $2a$10$...
//	roles:
//	  admin: {groups: [secops-admins]}
//	  operator: {groups: [secops]}
//	  viewer: {groups: [staff]}
type Config struct {
	Providers []ProviderConfig `yaml:"providers"`
	Static    *StaticConfig    `yaml:"static"`
	Roles     struct {
		Admin     RoleConfig `yaml:"admin"`
		Operator  RoleConfig `yaml:"operator"`
		Viewer    RoleConfig `yaml:"viewer"`
		Unmatched string     `yaml:"unmatched"`
	} `yaml:"roles"`
	// InsecureCookies drops the Secure attribute (plain HTTP only).
	InsecureCookies bool `yaml:"insecure_cookies"`
	// SessionTTL of static logins (default 24h).
	SessionTTL time.Duration `yaml:"session_ttl"`
}

// StaticConfig is the built-in login.
type StaticConfig struct {
	Username string `yaml:"username"`
	// PasswordHash is bcrypt; Password (plain) is hashed at startup.
	PasswordHash string `yaml:"password_hash"`
	Password     string `yaml:"password"`
	PasswordFile string `yaml:"password_file"`
	Role         string `yaml:"role"`
}

// ProviderConfig configures one external provider.
type ProviderConfig struct {
	// Type is header, jwt or forward.
	Type string `yaml:"type"`
	Name string `yaml:"name"`

	// header and forward
	UserHeader      string   `yaml:"user_header"`
	NameHeader      string   `yaml:"name_header"`
	EmailHeader     string   `yaml:"email_header"`
	GroupsHeader    string   `yaml:"groups_header"`
	GroupsSeparator string   `yaml:"groups_separator"`
	TrustedProxies  []string `yaml:"trusted_proxies"`
	SecretHeader    string   `yaml:"secret_header"`
	Secret          string   `yaml:"secret"`
	SecretFile      string   `yaml:"secret_file"`

	// jwt
	Header       string `yaml:"header"`
	Cookie       string `yaml:"cookie"`
	JWKSURL      string `yaml:"jwks_url"`
	JWKS         string `yaml:"jwks"`
	JWKSFile     string `yaml:"jwks_file"`
	Issuer       string `yaml:"issuer"`
	Audience     string `yaml:"audience"`
	SubjectClaim string `yaml:"subject_claim"`
	NameClaim    string `yaml:"name_claim"`
	EmailClaim   string `yaml:"email_claim"`
	GroupsClaim  string `yaml:"groups_claim"`

	// forward
	URL      string        `yaml:"url"`
	CacheTTL time.Duration `yaml:"cache_ttl"`

	LoginURL  string `yaml:"login_url"`
	LogoutURL string `yaml:"logout_url"`
}

// ParseConfig decodes a configuration file.
func ParseConfig(data []byte) (*Config, error) {
	c := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("auth config: %w", err)
	}
	return c, nil
}

func readSecret(value, file string) (string, error) {
	if file == "" {
		return value, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// Build creates the provider chain. sessionKey signs static sessions.
func (c *Config) Build(sessionKey []byte) (*Chain, error) {
	chain := &Chain{Roles: Roles{Admin: c.Roles.Admin, Operator: c.Roles.Operator, Viewer: c.Roles.Viewer, Unmatched: c.Roles.Unmatched}}
	if u := c.Roles.Unmatched; u != "" {
		if _, ok := roleRank[u]; !ok {
			return nil, fmt.Errorf("auth config: roles.unmatched: unknown role %q", u)
		}
	}
	for i, pc := range c.Providers {
		p, err := pc.build()
		if err != nil {
			return nil, fmt.Errorf("auth config: providers[%d] (%s): %w", i, pc.Type, err)
		}
		chain.Providers = append(chain.Providers, p)
	}
	if s := c.Static; s != nil && s.Username != "" {
		hash := s.PasswordHash
		if hash == "" {
			pw, err := readSecret(s.Password, s.PasswordFile)
			if err != nil {
				return nil, fmt.Errorf("auth config: static: %w", err)
			}
			if len(pw) < 8 {
				return nil, errors.New("auth config: static: the password must have at least 8 characters")
			}
			h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			hash = string(h)
		}
		st, err := NewStatic(s.Username, hash, s.Role, sessionKey)
		if err != nil {
			return nil, err
		}
		st.Insecure = c.InsecureCookies
		if c.SessionTTL > 0 {
			st.TTL = c.SessionTTL
		}
		chain.Providers = append(chain.Providers, st)
	}
	if len(chain.Providers) == 0 {
		return nil, errors.New("auth config: no provider configured (set static or providers)")
	}
	return chain, nil
}

func (pc ProviderConfig) build() (Provider, error) {
	secret, err := readSecret(pc.Secret, pc.SecretFile)
	if err != nil {
		return nil, err
	}
	switch pc.Type {
	case "header":
		h := &Header{ProviderName: pc.Name, UserHeader: pc.UserHeader, NameHeader: pc.NameHeader, EmailHeader: pc.EmailHeader,
			GroupsHeader: pc.GroupsHeader, GroupsSep: pc.GroupsSeparator, SecretHeader: pc.SecretHeader, Secret: secret, Logout: pc.LogoutURL}
		for _, s := range pc.TrustedProxies {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				a, aerr := netip.ParseAddr(s)
				if aerr != nil {
					return nil, fmt.Errorf("trusted_proxies: %w", err)
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			h.TrustedProxies = append(h.TrustedProxies, p)
		}
		return h, h.Validate()
	case "jwt":
		jwks := pc.JWKS
		if pc.JWKSFile != "" {
			b, err := os.ReadFile(pc.JWKSFile)
			if err != nil {
				return nil, err
			}
			jwks = string(b)
		}
		j := &JWT{ProviderName: pc.Name, Header: pc.Header, Cookie: pc.Cookie, JWKSURL: pc.JWKSURL, Issuer: pc.Issuer, Audience: pc.Audience,
			SubjectClaim: pc.SubjectClaim, NameClaim: pc.NameClaim, EmailClaim: pc.EmailClaim, GroupsClaim: pc.GroupsClaim, Logout: pc.LogoutURL}
		if jwks != "" {
			j.StaticJWKS = []byte(jwks)
		}
		return j, j.Validate()
	case "forward":
		f := &Forward{ProviderName: pc.Name, URL: pc.URL, UserHeader: pc.UserHeader, NameHeader: pc.NameHeader, EmailHeader: pc.EmailHeader,
			GroupsHeader: pc.GroupsHeader, GroupsSep: pc.GroupsSeparator, CacheTTL: pc.CacheTTL, Login: pc.LoginURL, Logout: pc.LogoutURL}
		return f, f.Validate()
	}
	return nil, fmt.Errorf("unknown provider type %q (header, jwt, forward)", pc.Type)
}
