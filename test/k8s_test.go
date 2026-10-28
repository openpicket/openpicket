package test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent/k8slogs"
	"github.com/openpicket/openpicket/agent/k8slogs/kubetest"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager"
	"github.com/openpicket/openpicket/suristore"
)

// TestKubernetesCollector runs openpicket-agent-k8s-collector against a
// fake Kubernetes API and a real manager: the selected containers' lines
// reach CrowdSec under the target's program and the collector's node.
func TestKubernetesCollector(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	lk := &lokiLabels{}
	lokiSrv := httptest.NewServer(lk)
	defer lokiSrv.Close()
	lp := &envelopeLP{}
	lpSrv := httptest.NewServer(lp)
	defer lpSrv.Close()
	hostKey, _ := sshkey.Generate()
	r := startReplica(t, pool, hostKey, lokiSrv.URL, lpSrv.URL, "replica-a")
	defer r.stop()

	api := kubetest.New(t)
	api.SetWorkload("ingress", "deployment", "controller", map[string]any{"matchLabels": map[string]string{"app": "ingress"}})
	api.AddPod(kubetest.Pod{Namespace: "ingress", Name: "controller-1", UID: "c1", Labels: map[string]string{"app": "ingress"}, Containers: []string{"controller", "metrics"}})

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	key, _, err := sshkey.LoadOrGenerate(keyFile, "k8s-logs")
	if err != nil {
		t.Fatal(err)
	}
	line := key.Public("k8s-logs").String()
	x, _ := suristore.X25519(line)
	pk, _ := sshkey.ParsePublicKey(line)
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint, labels) VALUES ('k8s-logs',$1,$2,$3,'{"site":"cluster-a"}')`, line, x, pk.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	cfg, err := k8slogs.Parse([]byte(fmt.Sprintf(`node_id: k8s-logs
key_file: %s
state_file: %s
scan_interval: 1s
openpicket:
  url: %s
  host_key: %q
kubernetes:
  api_url: %s
targets:
  - { namespace: ingress, workload: deployment/controller, containers: [controller], program: nginx }
`, keyFile, filepath.Join(dir, "state", "positions.json"), "ws"+strings.TrimPrefix(r.srv.URL, "http")+"/agent/data/v1/connect",
		hostKey.Public(manager.HostKeyComment).String(), api.URL)))
	if err != nil {
		t.Fatal(err)
	}
	a, err := k8slogs.NewAgent(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Run(actx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timeout: %s (CrowdSec got %q)", what, lp.lines())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitFor("node online", func() bool { return r.m.Gateway().Session("k8s-logs") != nil })
	waitFor("following", func() bool { return len(api.LogRequests()) > 0 })
	access := `198.51.100.67 - - [26/Oct/2026:01:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 0 "-" "curl"`
	api.Log("ingress", "controller-1", "controller", time.Now(), access)
	api.Log("ingress", "controller-1", "metrics", time.Now(), "not selected")
	waitFor("line at CrowdSec", func() bool { return len(lp.lines()) == 1 })
	if got := lp.lines()[0]; got != "nginx: "+access {
		t.Fatalf("CrowdSec got %q", got)
	}
	lp.mu.Lock()
	m := lp.meta[0]
	lp.mu.Unlock()
	if m["node_id"] != "k8s-logs" || m["site"] != "cluster-a" {
		t.Fatalf("meta %v", m)
	}
	if h := r.m.Gateway().Session("k8s-logs").Hello(); !slices.Contains(h.Capabilities, k8slogs.Capability) || h.Platform.GetProfile() != "kubernetes" {
		t.Fatalf("hello %v", h)
	}
}
