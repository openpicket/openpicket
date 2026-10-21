package suristore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/agent/conn"
	"github.com/jc-lab/suricontroller/controller"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/suriauth"
)

// A node registered directly in openpicket.nodes (the way openpicket-manager
// registers nodes) can connect to suricontroller without a restart, and is
// disconnected within the recheck interval once disabled there.
func TestSharedRegistryWithController(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ctl, err := controller.New(controller.Options{
		DataDir:                t.TempDir(),
		Store:                  s,
		Auth:                   &suriauth.Provider{Key: pub},
		Authorizer:             suriauth.Authorizer{},
		DisableETOpen:          true,
		SessionRecheckInterval: 100 * time.Millisecond,
		Logger:                 slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	runCtx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go func() { _ = ctl.Run(runCtx); close(runDone) }()
	defer func() { cancel(); <-runDone }()
	if !ctl.Nodes().Delegated() {
		t.Fatal("controller must delegate key lookups to the shared store")
	}
	srv := httptest.NewServer(ctl.AgentHandler())
	defer srv.Close()

	key, _ := sshkey.Generate()
	line := key.Public("edge-01").String()
	x, _ := X25519(line)
	pk, _ := sshkey.ParsePublicKey(line)
	if _, err := s.db.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint) VALUES ($1,$2,$3,$4)`,
		"edge-01", line, x, pk.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	hostKey, err := sshkey.ParsePublicKey(ctl.HostPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	dial := func() (*conn.Session, error) {
		return conn.Dial(ctx, conn.Config{
			URL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/v1/connect", Key: key, ServerKey: hostKey,
			NodeID: "edge-01", AgentVersion: "test",
		}, &agentv1.Hello{NodeId: "edge-01", AgentVersion: "test"}, func(context.Context, *agentv1.Envelope) (*agentv1.Envelope, error) { return nil, nil })
	}
	sess, err := dial()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	go sess.Run(ctx)

	// The controller records the Hello in the shared row.
	deadline := time.Now().Add(10 * time.Second)
	for {
		n, err := s.GetNode(ctx, "edge-01")
		if err == nil && n.Hello.GetAgentVersion() == "test" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hello not recorded: %v %+v", err, n)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if _, err := s.db.Exec(ctx, `UPDATE openpicket.nodes SET enabled = false WHERE id = 'edge-01'`); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sess.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("session of the disabled node was not closed")
	}
	time.Sleep(5 * time.Millisecond) // handshake timestamps must increase
	var re *conn.RejectedError
	if _, err := dial(); !errors.As(err, &re) || re.Reason != agentv1.RejectReason_REJECT_REASON_DISABLED {
		t.Fatalf("reconnect of disabled node: %v", err)
	}
}
