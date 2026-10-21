// Package suriauth authenticates suricontroller API requests with the
// principal token openpicket-manager adds when it proxies /suricata/, and
// maps OpenPicket roles to suricontroller permissions.
package suriauth

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"time"

	"github.com/jc-lab/suricontroller/controller/auth"

	"github.com/openpicket/openpicket/pkg/principal"
)

// Provider implements auth.Provider and auth.ExternalLogin.
type Provider struct {
	// Key verifies tokens (the manager's principal key).
	Key ed25519.PublicKey
	// Login is where the UI sends unauthenticated users (the OpenPicket
	// login page).
	Login string
	Now   func() time.Time
}

var (
	_ auth.Provider      = (*Provider)(nil)
	_ auth.ExternalLogin = (*Provider)(nil)
)

// Authenticate implements auth.Provider.
func (p *Provider) Authenticate(r *http.Request) (*auth.Principal, error) {
	tok := r.Header.Get(principal.Header)
	if tok == "" {
		return nil, auth.ErrUnauthenticated
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	c, err := principal.Verify(p.Key, tok, principal.AudienceSuricontroller, now())
	if err != nil {
		return nil, auth.ErrUnauthenticated
	}
	return &auth.Principal{ID: c.Subject, DisplayName: c.Name, Roles: c.Roles}, nil
}

// LoginURL implements auth.ExternalLogin.
func (p *Provider) LoginURL(string) string { return p.Login }

// Authorizer maps roles: viewer reads, operator also changes nodes, rules,
// repositories, deployment and logs, admin also changes system settings.
type Authorizer struct{}

// Authorize implements auth.Authorizer.
func (Authorizer) Authorize(_ context.Context, p *auth.Principal, action auth.Action, resource string) error {
	if p == nil {
		return auth.ErrPermissionDenied
	}
	has := func(role string) bool {
		for _, r := range p.Roles {
			if r == role {
				return true
			}
		}
		return false
	}
	switch {
	case has(principal.RoleAdmin):
		return nil
	case has(principal.RoleOperator):
		if action == auth.ActionRead || resource != auth.ResourceSystem {
			return nil
		}
	case has(principal.RoleViewer):
		if action == auth.ActionRead {
			return nil
		}
	}
	return auth.ErrPermissionDenied
}
