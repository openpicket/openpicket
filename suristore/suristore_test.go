package suristore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/controller/store"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
)

func open(t *testing.T) *Store {
	t.Helper()
	pool := pgtest.Pool(t)
	if err := schema.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	return New(pool)
}

func newNode(t *testing.T, id string) *store.Node {
	t.Helper()
	k, err := sshkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.Public(id)
	now := time.UnixMilli(time.Now().UnixMilli())
	return &store.Node{ID: id, PublicKey: pub.String(), Fingerprint: pub.Fingerprint(), Enabled: true, CreatedAt: now, UpdatedAt: now}
}

func TestNodes(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	n := newNode(t, "router-01")
	now := n.CreatedAt
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNode(ctx, n); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	got, err := s.UpdateNode(ctx, "router-01", func(n *store.Node) error {
		n.Hello = &agentv1.Hello{NodeId: "router-01", AgentVersion: "1.0"}
		n.InterfaceModes = map[string]agentv1.InterfaceMode{"br-lan": agentv1.InterfaceMode_INTERFACE_MODE_IPS}
		n.Desired = &agentv1.DesiredState{Generation: 3}
		n.LastSeenAt = now
		n.LastReportAt = now
		n.DesiredError = "render failed"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Desired.Generation != 3 {
		t.Fatal("update result")
	}
	got, err = s.GetNode(ctx, "router-01")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hello.GetAgentVersion() != "1.0" || got.InterfaceModes["br-lan"] != agentv1.InterfaceMode_INTERFACE_MODE_IPS ||
		got.Desired.GetGeneration() != 3 || !got.LastSeenAt.Equal(now) || !got.LastReportAt.Equal(now) ||
		got.DesiredError != "render failed" || got.LogPolicy != nil || !got.CreatedAt.Equal(now) {
		t.Fatalf("unexpected node %+v", got)
	}

	// Failed update leaves the node unchanged.
	if _, err = s.UpdateNode(ctx, "router-01", func(n *store.Node) error {
		n.Description = "changed"
		return errors.New("abort")
	}); err == nil {
		t.Fatal("expected abort error")
	}
	if got, _ = s.GetNode(ctx, "router-01"); got.Description != "" {
		t.Fatal("aborted update was saved")
	}
	if _, err := s.UpdateNode(ctx, "missing", func(*store.Node) error { return nil }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}

	for g := uint64(1); g <= 2; g++ {
		if err := s.AppendApplyHistory(ctx, &store.ApplyHistoryEntry{NodeID: "router-01", Report: &agentv1.ApplyReport{Generation: g}, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PruneApplyHistory(ctx, 1); err != nil {
		t.Fatal(err)
	}
	hist, err := s.ListApplyHistory(ctx, "router-01", 10)
	if err != nil || len(hist) != 1 || hist[0].Report.Generation != 2 {
		t.Fatalf("history = %v, %v", hist, err)
	}

	if err := s.DeleteNode(ctx, "router-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetNode(ctx, "router-01"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
	if err := s.DeleteNode(ctx, "router-01"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if hist, _ = s.ListApplyHistory(ctx, "router-01", 10); len(hist) != 0 {
		t.Fatal("history not cascaded")
	}
}

func TestLookupAndRegistryColumns(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	n := newNode(t, "router-02")
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	x, _ := X25519(n.PublicKey)
	if id, enabled, err := s.LookupNodeByX25519(ctx, x); err != nil || id != "router-02" || !enabled {
		t.Fatalf("lookup = %q %v %v", id, enabled, err)
	}
	if _, _, err := s.LookupNodeByX25519(ctx, make([]byte, 32)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
	// OpenPicket-owned columns survive suricontroller updates.
	if _, err := s.db.Exec(ctx, `UPDATE openpicket.nodes SET labels = '{"site":"seoul"}', dp_last_seen_at = now() WHERE id = $1`, n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateNode(ctx, n.ID, func(n *store.Node) error { n.Enabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	var site string
	var dpSeen *time.Time
	if err := s.db.QueryRow(ctx, `SELECT labels->>'site', dp_last_seen_at FROM openpicket.nodes WHERE id = $1`, n.ID).Scan(&site, &dpSeen); err != nil ||
		site != "seoul" || dpSeen == nil {
		t.Fatalf("labels=%q dp=%v err=%v", site, dpSeen, err)
	}
	if _, enabled, _ := s.LookupNodeByX25519(ctx, x); enabled {
		t.Fatal("disable not visible to lookup")
	}
}

func TestPoliciesProvidersSettingsAudit(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if _, err := s.GetDeployPolicy(ctx, "rules"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.PutDeployPolicy(ctx, &store.DeployPolicy{Kind: "rules", Mode: "pinned", PinnedCommit: "abc", EffectiveCommit: "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutDeployPolicy(ctx, &store.DeployPolicy{Kind: "rules", Mode: "auto", EffectiveCommit: "def", UpdatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	p, err := s.GetDeployPolicy(ctx, "rules")
	if err != nil || p.Mode != "auto" || p.EffectiveCommit != "def" || p.UpdatedBy != "admin" {
		t.Fatalf("policy = %+v %v", p, err)
	}

	if err := s.PutProvider(ctx, &store.Provider{Name: "et-open", Type: "et-open", Enabled: true, Interval: time.Hour, Options: map[string]string{"suricata_version": "8.0.5"}}); err != nil {
		t.Fatal(err)
	}
	pr, err := s.GetProvider(ctx, "et-open")
	if err != nil || pr.Interval != time.Hour || pr.Options["suricata_version"] != "8.0.5" || !pr.LastFetchAt.IsZero() {
		t.Fatalf("provider = %+v %v", pr, err)
	}
	if list, err := s.ListProviders(ctx); err != nil || len(list) != 1 {
		t.Fatalf("providers = %v %v", list, err)
	}
	if err := s.DeleteProvider(ctx, "et-open"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetProvider(ctx, "et-open"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}

	pol := &agentv1.LogCollectionPolicy{Enabled: true, Types: []agentv1.LogType{agentv1.LogType_LOG_TYPE_EVE}}
	if err := s.PutSetting(ctx, "log_policy", pol); err != nil {
		t.Fatal(err)
	}
	var got agentv1.LogCollectionPolicy
	if ok, err := s.GetSetting(ctx, "log_policy", &got); !ok || err != nil || !got.Enabled || len(got.Types) != 1 {
		t.Fatalf("setting = %v %v %v", &got, ok, err)
	}
	var n int
	if ok, _ := s.GetSetting(ctx, "missing", &n); ok {
		t.Fatal("missing setting reported as set")
	}

	e := &store.AuditEntry{Time: time.Now(), Principal: "admin", Action: "deploy.pin", Target: "rules"}
	if err := s.AppendAudit(ctx, e); err != nil || e.ID == 0 {
		t.Fatalf("audit: %v id=%d", err, e.ID)
	}
	var source string
	if err := s.db.QueryRow(ctx, `SELECT source FROM openpicket.audit WHERE id = $1`, e.ID).Scan(&source); err != nil || source != AuditSource {
		t.Fatalf("source = %q %v", source, err)
	}
	if list, err := s.ListAudit(ctx, 10); err != nil || len(list) != 1 || list[0].Action != "deploy.pin" {
		t.Fatalf("audit list = %v %v", list, err)
	}
}

func TestRegistryNotifyOnlyOnRegistryChange(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN openpicket_nodes"); err != nil {
		t.Fatal(err)
	}
	expect := func(want bool) {
		t.Helper()
		wctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer cancel()
		n, err := conn.Conn().WaitForNotification(wctx)
		if want && (err != nil || n.Payload != "router-03") {
			t.Fatalf("notification = %v, %v", n, err)
		}
		if !want && err == nil {
			t.Fatalf("unexpected notification %v", n)
		}
	}
	n := newNode(t, "router-03")
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	expect(true)
	// A heartbeat-style update (suri_state only) does not notify.
	if _, err := s.UpdateNode(ctx, n.ID, func(n *store.Node) error { n.LastSeenAt = time.Now(); return nil }); err != nil {
		t.Fatal(err)
	}
	expect(false)
	if _, err := s.UpdateNode(ctx, n.ID, func(n *store.Node) error { n.Enabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	expect(true)
}
