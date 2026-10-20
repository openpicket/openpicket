package auth

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Header trusts identity headers set by an authenticating reverse proxy
// (oauth2-proxy, Authelia, Authentik, Traefik ForwardAuth...).
//
// The headers are only believed when the request comes directly from a
// trusted proxy address and/or carries the shared secret header: anyone
// else could set them. In Kubernetes the direct peer is the ingress
// controller, so the proxy in front must overwrite client-supplied identity
// headers (docs/ARCHITECTURE.md §5.7).
type Header struct {
	ProviderName   string
	UserHeader     string
	NameHeader     string
	EmailHeader    string
	GroupsHeader   string
	GroupsSep      string
	TrustedProxies []netip.Prefix
	SecretHeader   string
	Secret         string
	// LogoutURL is the proxy's sign-out endpoint.
	Logout string
}

// Validate checks that the provider has a trust anchor.
func (h *Header) Validate() error {
	if h.UserHeader == "" {
		return errors.New("auth: header: user header is required")
	}
	if len(h.TrustedProxies) == 0 && (h.SecretHeader == "" || h.Secret == "") {
		return errors.New("auth: header: trusted proxies or a shared secret header are required")
	}
	return nil
}

// Name implements Provider.
func (h *Header) Name() string {
	if h.ProviderName != "" {
		return h.ProviderName
	}
	return "header"
}

func (h *Header) trustedPeer(r *http.Request) bool {
	if len(h.TrustedProxies) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range h.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Authenticate implements Provider.
func (h *Header) Authenticate(r *http.Request) (*Principal, error) {
	user := strings.TrimSpace(r.Header.Get(h.UserHeader))
	if user == "" {
		return nil, ErrNoCredentials
	}
	if !h.trustedPeer(r) {
		return nil, ErrInvalidCredentials
	}
	if h.SecretHeader != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get(h.SecretHeader)), []byte(h.Secret)) != 1 {
		return nil, ErrInvalidCredentials
	}
	p := &Principal{Subject: user, Name: user}
	if h.NameHeader != "" {
		if v := r.Header.Get(h.NameHeader); v != "" {
			p.Name = v
		}
	}
	if h.EmailHeader != "" {
		p.Email = r.Header.Get(h.EmailHeader)
	}
	if h.GroupsHeader != "" {
		p.Groups = splitGroups(r.Header.Get(h.GroupsHeader), h.GroupsSep)
	}
	return p, nil
}

func splitGroups(v, sep string) []string {
	if sep == "" {
		sep = ","
	}
	var out []string
	for _, g := range strings.Split(v, sep) {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

// LoginURL implements ExternalLogin (the proxy handles login).
func (h *Header) LoginURL(string) string { return "" }

// LogoutURL implements ExternalLogin.
func (h *Header) LogoutURL() string { return h.Logout }
