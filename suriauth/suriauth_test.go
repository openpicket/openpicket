package suriauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/controller/auth"

	"github.com/openpicket/openpicket/pkg/principal"
)

func TestProviderAndAuthorizer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := &Provider{Key: pub, Login: "/login"}
	r := httptest.NewRequest("POST", "/suricontroller.api.v1.NodeService/ListNodes", nil)
	if _, err := p.Authenticate(r); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("no token: %v", err)
	}
	tok, _ := principal.Mint(priv, principal.AudienceSuricontroller, "header:alice", "Alice", []string{principal.RoleOperator}, time.Minute, time.Now())
	r.Header.Set(principal.Header, tok)
	pr, err := p.Authenticate(r)
	if err != nil || pr.ID != "header:alice" || pr.Name() != "Alice" {
		t.Fatalf("principal = %+v, %v", pr, err)
	}
	r.Header.Set(principal.Header, tok+"x")
	if _, err := p.Authenticate(r); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("bad token: %v", err)
	}

	ctx := context.Background()
	az := Authorizer{}
	op := &auth.Principal{Roles: []string{principal.RoleOperator}}
	viewer := &auth.Principal{Roles: []string{principal.RoleViewer}}
	admin := &auth.Principal{Roles: []string{principal.RoleAdmin}}
	cases := []struct {
		p        *auth.Principal
		action   auth.Action
		resource string
		ok       bool
	}{
		{viewer, auth.ActionRead, auth.ResourceNodes, true},
		{viewer, auth.ActionWrite, auth.ResourceNodes, false},
		{op, auth.ActionWrite, auth.ResourceDeploy, true},
		{op, auth.ActionWrite, auth.ResourceSystem, false},
		{op, auth.ActionRead, auth.ResourceSystem, true},
		{admin, auth.ActionWrite, auth.ResourceSystem, true},
		{&auth.Principal{}, auth.ActionRead, auth.ResourceNodes, false},
		{nil, auth.ActionRead, auth.ResourceNodes, false},
	}
	for i, c := range cases {
		if err := az.Authorize(ctx, c.p, c.action, c.resource); (err == nil) != c.ok {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}
