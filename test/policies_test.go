package test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent/dataplane"
	"github.com/openpicket/openpicket/agent/nft"
	"github.com/openpicket/openpicket/agent/policy"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/pkg/geoip/geoiptest"
	"github.com/openpicket/openpicket/pkg/portpolicy"
	"github.com/openpicket/openpicket/suristore"
)

// scriptExec records the nft scripts the agent applies.
type scriptExec struct {
	mu      sync.Mutex
	scripts []string
}

func (s *scriptExec) Run(_ context.Context, _ string, args []string, stdin []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(args) > 0 && (args[0] == "list" || args[0] == "-j") {
		return []byte(`{"nftables":[]}`), nil
	}
	s.scripts = append(s.scripts, string(stdin))
	return nil, nil
}
func (s *scriptExec) LookPath(n string) (string, error) { return n, nil }

func (s *scriptExec) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.scripts) == 0 {
		return ""
	}
	return s.scripts[len(s.scripts)-1]
}

func TestPortPoliciesReachTheEdge(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer sink.Close()
	hostKey, _ := sshkey.Generate()
	m, err := manager.New(manager.Options{DB: pool, HostKey: hostKey, ReplicaID: "r1",
		Loki: loki.Config{URL: sink.URL}, CrowdSec: crowdsec.Config{Endpoints: []string{sink.URL}}, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	mctx, mcancel := context.WithCancel(ctx)
	mdone := make(chan struct{})
	go func() { _ = m.Run(mctx); close(mdone) }()
	defer func() { mcancel(); <-mdone }()
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	// MaxMind databases are uploaded by the user (generated here).
	if _, err := m.Geo().Upload(ctx, geoiptest.Country(t, map[string]string{"1.0.0.0/24": "CN", "1.0.1.0/24": "CN", "2.0.0.0/16": "KR"}), "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Geo().Upload(ctx, geoiptest.ASN(t, map[string]uint32{"8.8.8.0/24": 15169}), "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Policies().PutList(ctx, portpolicy.List{Name: "google", ASNs: []uint32{15169}}, "Google (AS15169)", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Policies().PutPolicy(ctx, portpolicy.Policy{ID: "https_block_cn", Enabled: true, Mode: portpolicy.ModeEnforce, Proto: "tcp",
		Ports: []portpolicy.PortRange{{From: 443, To: 443}}, Default: portpolicy.ActionAccept,
		Rules: []portpolicy.Rule{{Source: portpolicy.Source{Countries: []string{"CN"}}, Action: portpolicy.ActionDrop}}}, -1, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Policies().PutPolicy(ctx, portpolicy.Policy{ID: "smtp_submission", Enabled: true, Mode: portpolicy.ModeEnforce, Proto: "tcp",
		Ports: []portpolicy.PortRange{{From: 587, To: 587}}, Default: portpolicy.ActionDrop, LogDrops: true,
		Scope: portpolicy.Scope{Labels: map[string][]string{"site": {"seoul"}}},
		Rules: []portpolicy.Rule{{Source: portpolicy.Source{Countries: []string{"KR"}}, Action: portpolicy.ActionAccept},
			{Source: portpolicy.Source{Lists: []string{"google"}}, Action: portpolicy.ActionAccept}}}, -1, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Policies().PutPolicy(ctx, portpolicy.Policy{ID: "bad", Enabled: true, Mode: "enforce", Proto: "tcp", Default: "drop"}, -1, "admin"); err == nil {
		t.Fatal("invalid policy saved")
	}

	agentKey, _ := sshkey.Generate()
	line := agentKey.Public("edge-01").String()
	x, _ := suristore.X25519(line)
	pk, _ := sshkey.ParsePublicKey(line)
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint, labels) VALUES ('edge-01',$1,$2,$3,'{"site":"busan"}')`, line, x, pk.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	ex := &scriptExec{}
	sinkPol := policy.New(policy.Config{Host: &nft.Host{Exec: ex}, Table: nft.PolicyConfig{WAN: []string{"wan"}}, MaxElements: 1000,
		StateFile: t.TempDir() + "/policy.pb", Logger: slog.New(slog.DiscardHandler)})
	client := dataplane.NewClient(dataplane.DialConfig{
		URL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/data/v1/connect", Key: agentKey,
		ServerKey: hostKey.Public(manager.HostKeyComment), NodeID: "edge-01", Version: "test",
	}, dataplane.Handlers{Hello: func() *dataplanev1.Hello { return &dataplanev1.Hello{NodeId: "edge-01", BootId: "b1"} }, Policy: sinkPol},
		slog.New(slog.DiscardHandler))
	cctx, ccancel := context.WithCancel(ctx)
	defer ccancel()
	go client.Run(cctx)

	waitScript := func(what string, cond func(string) bool) string {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			if s := ex.last(); cond(s) {
				return s
			}
			if time.Now().After(deadline) {
				t.Fatalf("timeout: %s\nlast script:\n%s", what, ex.last())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// busan: only the global CN policy.
	s := waitScript("CN policy", func(s string) bool { return strings.Contains(s, "jump p_https_block_cn") })
	if !strings.Contains(s, "elements = { 1.0.0.0/23 }") || strings.Contains(s, "smtp_submission") {
		t.Fatalf("busan bundle:\n%s", s)
	}
	// Moving the node to seoul brings the SMTP allowlist policy.
	if _, err := pool.Exec(ctx, `UPDATE openpicket.nodes SET labels = '{"site":"seoul"}' WHERE id = 'edge-01'`); err != nil {
		t.Fatal(err)
	}
	s = waitScript("SMTP policy", func(s string) bool { return strings.Contains(s, "jump p_smtp_submission") })
	for _, want := range []string{"tcp dport { 587 } jump p_smtp_submission", "s_smtp_submission_r0_4", "elements = { 2.0.0.0/16 }",
		"elements = { 8.8.8.0/24 }", `counter drop comment "smtp_submission/default"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("seoul bundle lacks %q:\n%s", want, s)
		}
	}
	// A new GeoIP database changes the CN networks: a new bundle follows.
	if _, err := m.Geo().Upload(ctx, geoiptest.Country(t, map[string]string{"1.0.0.0/24": "CN", "3.0.0.0/8": "CN", "2.0.0.0/16": "KR"}), "admin"); err != nil {
		t.Fatal(err)
	}
	waitScript("updated CN networks", func(s string) bool { return strings.Contains(s, "1.0.0.0/24, 3.0.0.0/8") })
	var acked int64
	var ackErr string
	if err := pool.QueryRow(ctx, `SELECT version, error FROM openpicket.node_policy_state WHERE node_id = 'edge-01'`).Scan(&acked, &ackErr); err != nil || ackErr != "" {
		t.Fatalf("ack: %d %q %v", acked, ackErr, err)
	}
}
