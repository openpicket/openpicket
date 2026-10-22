package manager

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	suriapiv1 "github.com/jc-lab/suricontroller/gen/suricontroller/api/v1"
	"github.com/jc-lab/suricontroller/gen/suricontroller/api/v1/apiv1connect"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/pkg/principal"
)

// fakeSystem answers GetInfo for callers holding a principal token.
type fakeSystem struct {
	apiv1connect.UnimplementedSystemServiceHandler
	verify *sshkey.PrivateKey

	mu        sync.Mutex
	hostKey   string
	agentPath string
	roles     []string
}

func (f *fakeSystem) GetInfo(_ context.Context, req *connect.Request[suriapiv1.GetInfoRequest]) (*connect.Response[suriapiv1.GetInfoResponse], error) {
	c, err := principal.Verify(f.verify.Key.Public().(ed25519.PublicKey), req.Header().Get(principal.Header), principal.AudienceSuricontroller, time.Now())
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roles = c.Roles
	return connect.NewResponse(&suriapiv1.GetInfoResponse{HostKey: f.hostKey, AgentPath: f.agentPath}), nil
}

func (f *fakeSystem) set(hostKey string) {
	f.mu.Lock()
	f.hostKey = hostKey
	f.mu.Unlock()
}

func startFakeSystem(t *testing.T, principalKey *sshkey.PrivateKey) (*fakeSystem, *url.URL) {
	t.Helper()
	f := &fakeSystem{verify: principalKey, agentPath: "/agent/v1/connect"}
	mux := http.NewServeMux()
	mux.Handle("/api/", http.StripPrefix("/api", func() http.Handler { _, h := apiv1connect.NewSystemServiceHandler(f); return h }()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return f, u
}

func TestControllerEndpoint(t *testing.T) {
	host, _ := sshkey.Generate()
	keys, err := DeriveKeys(host)
	if err != nil {
		t.Fatal(err)
	}
	ctlKey, _ := sshkey.Generate()
	line := ctlKey.Public("suri-controller").String()
	f, base := startFakeSystem(t, keys.Principal)
	f.set(line)
	ctx := context.Background()

	c := newControllerEndpoint(base, keys.Principal, "", 0, slog.New(slog.DiscardHandler))
	if c.Get() != nil {
		t.Fatal("known before the first read")
	}
	changed, err := c.refresh(ctx)
	if err != nil || !changed {
		t.Fatalf("refresh: %v %v", changed, err)
	}
	if ep := c.Get(); ep.GetUrl() != "/agent/v1/connect" || ep.GetHostKey() != line {
		t.Fatalf("endpoint = %v", ep)
	}
	if len(f.roles) != 1 || f.roles[0] != principal.RoleViewer {
		t.Fatalf("token roles = %v", f.roles)
	}
	if changed, _ := c.refresh(ctx); changed {
		t.Fatal("unchanged endpoint reported as a change")
	}
	// Key rotation is a change.
	other, _ := sshkey.Generate()
	f.set(other.Public("suri-controller").String())
	if changed, _ := c.refresh(ctx); !changed {
		t.Fatal("new host key not reported")
	}
	// A token from another key is refused, and the endpoint is kept.
	wrong, _ := sshkey.Generate()
	bad := newControllerEndpoint(base, wrong, "", 0, slog.New(slog.DiscardHandler))
	if _, err := bad.refresh(ctx); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("wrong principal key: %v", err)
	}

	// The override replaces the URL.
	o := newControllerEndpoint(base, keys.Principal, "wss://suricata.example.com/agent/v1/connect", 0, slog.New(slog.DiscardHandler))
	if _, err := o.refresh(ctx); err != nil || o.Get().GetUrl() != "wss://suricata.example.com/agent/v1/connect" {
		t.Fatalf("override: %v %v", o.Get(), err)
	}
}
