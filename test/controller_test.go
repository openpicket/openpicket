package test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	suriapiv1 "github.com/jc-lab/suricontroller/gen/suricontroller/api/v1"
	"github.com/jc-lab/suricontroller/gen/suricontroller/api/v1/apiv1connect"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent/dataplane"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/pkg/principal"
	"github.com/openpicket/openpicket/suristore"
)

// fakeSuriInfo is openpicket-suricontroller's SystemService.GetInfo.
type fakeSuriInfo struct {
	apiv1connect.UnimplementedSystemServiceHandler
	principal ed25519.PublicKey

	mu      sync.Mutex
	hostKey string
}

func (f *fakeSuriInfo) GetInfo(_ context.Context, req *connect.Request[suriapiv1.GetInfoRequest]) (*connect.Response[suriapiv1.GetInfoResponse], error) {
	if _, err := principal.Verify(f.principal, req.Header().Get(principal.Header), principal.AudienceSuricontroller, time.Now()); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return connect.NewResponse(&suriapiv1.GetInfoResponse{HostKey: f.hostKey, AgentPath: "/agent/v1/connect"}), nil
}

func (f *fakeSuriInfo) set(k string) {
	f.mu.Lock()
	f.hostKey = k
	f.mu.Unlock()
}

// Agents learn the controller endpoint from the manager: in the HelloAck,
// and pushed when it changes.
func TestControllerEndpointFromManager(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	lokiSrv := httptest.NewServer(&fakeLoki{rids: map[string]int{}})
	defer lokiSrv.Close()
	lpSrv := httptest.NewServer(&fakeLP{rids: map[string]int{}})
	defer lpSrv.Close()

	hostKey, _ := sshkey.Generate()
	keys, err := manager.DeriveKeys(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	ctl1, _ := sshkey.Generate()
	suri := &fakeSuriInfo{principal: keys.Principal.Key.Public().(ed25519.PublicKey)}
	suri.set(ctl1.Public("suri-controller").String())
	mux := http.NewServeMux()
	_, h := apiv1connect.NewSystemServiceHandler(suri)
	mux.Handle("/api/", http.StripPrefix("/api", h))
	suriSrv := httptest.NewServer(mux)
	defer suriSrv.Close()
	suriURL, _ := url.Parse(suriSrv.URL)

	m, err := manager.New(manager.Options{
		DB: pool, HostKey: hostKey, ReplicaID: "replica-a",
		Loki:           loki.Config{URL: lokiSrv.URL},
		CrowdSec:       crowdsec.Config{Endpoints: []string{lpSrv.URL}},
		Suricontroller: suriURL, ControllerPollInterval: 50 * time.Millisecond,
		PipelineOpenAfter: time.Hour,
		Logger:            slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	mctx, mcancel := context.WithCancel(ctx)
	mdone := make(chan struct{})
	go func() { _ = m.Run(mctx); close(mdone) }()
	srv := httptest.NewServer(m.Handler())
	defer func() { mcancel(); <-mdone; srv.CloseClientConnections(); srv.Close() }()

	agentKey, _ := sshkey.Generate()
	line := agentKey.Public("edge-01").String()
	x, _ := suristore.X25519(line)
	pk, _ := sshkey.ParsePublicKey(line)
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint) VALUES ('edge-01',$1,$2,$3)`, line, x, pk.Fingerprint()); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var got []*dataplanev1.ControllerEndpoint
	last := func() *dataplanev1.ControllerEndpoint {
		mu.Lock()
		defer mu.Unlock()
		if len(got) == 0 {
			return nil
		}
		return got[len(got)-1]
	}
	waitUntil := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timeout: %s", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	client := dataplane.NewClient(dataplane.DialConfig{
		URL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/data/v1/connect", Key: agentKey,
		ServerKey: hostKey.Public(manager.HostKeyComment), NodeID: "edge-01", Version: "test",
	}, dataplane.Handlers{
		Hello: func() *dataplanev1.Hello {
			return &dataplanev1.Hello{NodeId: "edge-01", AgentVersion: "test", BootId: "boot-1"}
		},
		Controller: func(ep *dataplanev1.ControllerEndpoint) {
			mu.Lock()
			got = append(got, ep)
			mu.Unlock()
		},
	}, slog.New(slog.DiscardHandler))
	cctx, ccancel := context.WithCancel(ctx)
	defer ccancel()
	go client.Run(cctx)

	waitUntil("endpoint in the HelloAck", func() bool {
		ep := last()
		return ep.GetUrl() == "/agent/v1/connect" && ep.GetHostKey() == ctl1.Public("suri-controller").String()
	})

	// Key rotation on the controller reaches the connected agent.
	ctl2, _ := sshkey.Generate()
	suri.set(ctl2.Public("suri-controller").String())
	waitUntil("pushed new endpoint", func() bool { return last().GetHostKey() == ctl2.Public("suri-controller").String() })
}
