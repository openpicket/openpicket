// Package auth authenticates and authorizes UI and API requests
// (docs/ARCHITECTURE.md §5.7).
//
// OpenPicket is not an identity provider: accounts, MFA and SSO belong to
// a reverse proxy or IdP in front of it. The manager only extracts the
// identity from a request through a chain of providers (header, jwt,
// forward) and maps it to a role. The only login it offers itself is one
// fixed username/password (static), for bootstrap and emergencies.
package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
)

// Roles, from least to most privileged.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

var roleRank = map[string]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// Principal is an authenticated user.
type Principal struct {
	// Provider is the name of the provider that authenticated the request.
	Provider string
	Subject  string
	Name     string
	Email    string
	Groups   []string
	// Roles are filled by the RoleMapper.
	Roles []string
	// Cookie is set when the credential came from a cookie (CSRF checks
	// apply).
	Cookie bool
}

// ID is the stable user id used for audit records and saved filters.
func (p *Principal) ID() string { return p.Provider + ":" + p.Subject }

// Display returns a human-readable name.
func (p *Principal) Display() string {
	if p.Name != "" {
		return p.Name
	}
	return p.Subject
}

// Has reports whether the principal has role or a higher one.
func (p *Principal) Has(role string) bool {
	if p == nil {
		return false
	}
	want := roleRank[role]
	for _, r := range p.Roles {
		if roleRank[r] >= want {
			return true
		}
	}
	return false
}

// Role returns the highest role.
func (p *Principal) Role() string {
	best := ""
	for _, r := range p.Roles {
		if roleRank[r] > roleRank[best] {
			best = r
		}
	}
	return best
}

var (
	// ErrNoCredentials: the request carries nothing for this provider; the
	// chain tries the next one.
	ErrNoCredentials = errors.New("auth: no credentials")
	// ErrInvalidCredentials: credentials were present but wrong. The chain
	// stops (no fallback to another provider).
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	// ErrForbidden: authenticated but not allowed.
	ErrForbidden = errors.New("auth: permission denied")
)

// Provider extracts the principal of a request.
type Provider interface {
	Name() string
	Authenticate(r *http.Request) (*Principal, error)
}

// PasswordLogin is implemented by providers with a login form.
type PasswordLogin interface {
	Login(ctx context.Context, username, password string) (*Principal, error)
}

// SessionIssuer is implemented by providers that keep a session cookie.
type SessionIssuer interface {
	IssueSession(w http.ResponseWriter, p *Principal) error
	ClearSession(w http.ResponseWriter)
}

// ExternalLogin is implemented by providers whose login happens elsewhere.
type ExternalLogin interface {
	LoginURL(returnTo string) string
	LogoutURL() string
}

// RoleMapper assigns roles.
type RoleMapper interface {
	Map(p *Principal) []string
}

// RoleConfig maps users and groups to a role.
type RoleConfig struct {
	Users  []string `json:"users,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// Roles maps principals to roles by user name or group. Principals that
// match nothing get Unmatched (empty: denied).
type Roles struct {
	Admin, Operator, Viewer RoleConfig
	Unmatched               string
}

// Map implements RoleMapper. A role already set by the provider (static)
// is kept.
func (r Roles) Map(p *Principal) []string {
	if len(p.Roles) > 0 {
		return p.Roles
	}
	match := func(c RoleConfig) bool {
		if slices.Contains(c.Users, p.Subject) || (p.Email != "" && slices.Contains(c.Users, p.Email)) {
			return true
		}
		for _, g := range p.Groups {
			if slices.Contains(c.Groups, g) {
				return true
			}
		}
		return false
	}
	switch {
	case match(r.Admin):
		return []string{RoleAdmin}
	case match(r.Operator):
		return []string{RoleOperator}
	case match(r.Viewer):
		return []string{RoleViewer}
	case r.Unmatched != "":
		return []string{r.Unmatched}
	}
	return nil
}

// Chain tries providers in order.
type Chain struct {
	Providers []Provider
	Roles     RoleMapper
}

// Authenticate returns the principal (with roles) and the provider that
// recognized the request.
func (c *Chain) Authenticate(r *http.Request) (*Principal, Provider, error) {
	for _, p := range c.Providers {
		pr, err := p.Authenticate(r)
		switch {
		case errors.Is(err, ErrNoCredentials):
			continue
		case err != nil:
			return nil, p, err
		}
		pr.Provider = p.Name()
		if c.Roles != nil {
			pr.Roles = c.Roles.Map(pr)
		}
		if len(pr.Roles) == 0 {
			return pr, p, ErrForbidden
		}
		return pr, p, nil
	}
	return nil, nil, ErrNoCredentials
}

// Find returns the first provider implementing T.
func Find[T any](c *Chain) (T, bool) {
	for _, p := range c.Providers {
		if t, ok := p.(T); ok {
			return t, true
		}
	}
	var zero T
	return zero, false
}

type ctxKey struct{}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the request's principal, or nil.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}
