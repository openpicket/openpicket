package test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent"
	"github.com/openpicket/openpicket/agent/config"
	"github.com/openpicket/openpicket/agent/dataplane"
	"github.com/openpicket/openpicket/agent/enforcer"
	"github.com/openpicket/openpicket/agent/nft"
	"github.com/openpicket/openpicket/agent/policy"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager"
	"github.com/openpicket/openpicket/manager/dbroles"
	"github.com/openpicket/openpicket/manager/lapi"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/pkg/direction"
	"github.com/openpicket/openpicket/pkg/portpolicy"
	"github.com/openpicket/openpicket/suristore"
)

// restrictedPools returns a pool on a fresh, migrated database and one
// connecting as a new gateway role (granted like the API replicas do).
func restrictedPools(t *testing.T) (pool, gwPool *pgxpool.Pool, role string) {
	t.Helper()
	admin := os.Getenv(pgtest.Env)
	if admin == "" {
		t.Skip(pgtest.Env + " not set")
	}
	ctx := context.Background()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	role, password := "op_gw_"+hex.EncodeToString(b), "pw-"+hex.EncodeToString(b)
	// Roles are cluster wide: drop it after the database (cleanups run in
	// reverse order).
	t.Cleanup(func() {
		if c, err := pgx.Connect(context.Background(), admin); err == nil {
			_, _ = c.Exec(context.Background(), "DROP ROLE IF EXISTS "+role)
			c.Close(context.Background())
		}
	})
	dsn := pgtest.DSN(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := dbroles.EnsureGateway(ctx, pool, role, password, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(dsn)
	u.User = url.UserPassword(role, password)
	gwPool, err = pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gwPool.Close)
	if err := schema.Wait(ctx, gwPool, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	return pool, gwPool, role
}

// TestGatewayAndAPISplit runs the API and the gateway as separate replicas,
// the gateway on a restricted database account: logs reach the sinks, the
// decisions and port policies the API side writes reach the nodes, and the
// gateway cannot change what the API manages.
func TestGatewayAndAPISplit(t *testing.T) {
	ctx := context.Background()
	pool, gwPool, role := restrictedPools(t)
	if restricted, user, err := dbroles.Restricted(ctx, gwPool); err != nil || !restricted || user != role {
		t.Fatalf("restricted = %v %q %v", restricted, user, err)
	}
	for _, q := range []string{
		`INSERT INTO openpicket.hub_items (type, name, source) VALUES ('parsers', 'x/y', 'custom')`,
		`UPDATE openpicket.nodes SET labels = '{}'`,
		`DELETE FROM openpicket.port_policies`,
		`DELETE FROM openpicket.edge_decisions`,
		`INSERT INTO openpicket.settings (key, value) VALUES ('x', '1')`,
		`SELECT version FROM public.openpicket_schema_migrations`,
	} {
		if _, err := gwPool.Exec(ctx, q); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("gateway account ran %q: %v", q, err)
		}
	}

	fl := &fakeLAPI{}
	fl.add(1, "198.51.100.4", "manual/web-ui", 4*time.Hour)
	lapiSrv := httptest.NewServer(fl)
	defer lapiSrv.Close()
	lk := &lokiLabels{}
	lokiSrv := httptest.NewServer(lk)
	defer lokiSrv.Close()
	lp := &envelopeLP{}
	lpSrv := httptest.NewServer(lp)
	defer lpSrv.Close()

	keys, err := manager.DeriveKeysFrom([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	apiM, err := manager.New(manager.Options{
		DB: pool, Role: manager.RoleAPI, Keys: keys, ReplicaID: "api-1",
		CrowdSec: crowdsec.Config{Endpoints: []string{lpSrv.URL}},
		LAPI:     lapi.Config{URL: lapiSrv.URL, BouncerKey: "bouncer-key"}, RelayPullInterval: 100 * time.Millisecond,
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	if apiM.Gateway() != nil || apiM.Pipeline() != nil {
		t.Fatal("the API replica faces the agents")
	}
	hostKey, _ := sshkey.Generate()
	gwM, err := manager.New(manager.Options{
		DB: gwPool, Role: manager.RoleGateway, HostKey: hostKey, ReplicaID: "gw-1",
		Loki: loki.Config{URL: lokiSrv.URL}, CrowdSec: crowdsec.Config{Endpoints: []string{lpSrv.URL}},
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	run := func(m *manager.Manager) func() {
		rctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { _ = m.Run(rctx); close(done) }()
		return func() { cancel(); <-done }
	}
	stopAPI := run(apiM)
	defer stopAPI()
	stopGW := run(gwM)
	defer stopGW()
	gwSrv := httptest.NewServer(gwM.Handler())
	defer gwSrv.Close()
	wsURL := "ws" + strings.TrimPrefix(gwSrv.URL, "http") + "/agent/data/v1/connect"

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timeout: %s", what)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	// The API shows the host key the gateway published.
	want := hostKey.Public(manager.HostKeyComment).String()
	waitFor("gateway published", func() bool { return apiM.HostPublicKey() == want })
	gws, err := apiM.Gateways(ctx)
	if err != nil || len(gws) != 1 || gws[0].Replica != "gw-1" || !gws[0].DBRestricted || gws[0].DBUser != role {
		t.Fatalf("gateways: %+v %v", gws, err)
	}

	register := func(id, labels string) *sshkey.PrivateKey {
		key, _ := sshkey.Generate()
		line := key.Public(id).String()
		x, _ := suristore.X25519(line)
		pk, _ := sshkey.ParsePublicKey(line)
		if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint, labels) VALUES ($1,$2,$3,$4,$5)`,
			id, line, x, pk.Fingerprint(), labels); err != nil {
			t.Fatal(err)
		}
		return key
	}

	// An edge node gets the relayed decisions and the port policies.
	edgeKey := register("edge-01", `{"site":"seoul"}`)
	inside, _ := direction.NewNets([]string{"192.168.1.0/24"})
	enf := enforcer.New(enforcer.Config{Host: &nft.Host{Exec: fakeNft{}}, Table: nft.BanConfig{WAN: nft.NewWAN("wan"), Egress: true},
		Allow: func() []netip.Prefix { return nil }, Nets: func() *direction.Nets { return inside },
		StateFile: t.TempDir() + "/decisions.json", Logger: slog.New(slog.DiscardHandler)})
	if err := enf.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	ex := &scriptExec{}
	pol := policy.New(policy.Config{Host: &nft.Host{Exec: ex}, Table: nft.PolicyConfig{WAN: nft.NewWAN("wan")}, MaxElements: 1000,
		StateFile: t.TempDir() + "/policy.pb", Logger: slog.New(slog.DiscardHandler)})
	client := dataplane.NewClient(dataplane.DialConfig{
		URL: wsURL, Key: edgeKey, ServerKey: hostKey.Public(manager.HostKeyComment), NodeID: "edge-01", Version: "test",
	}, dataplane.Handlers{
		Hello:     func() *dataplanev1.Hello { return &dataplanev1.Hello{NodeId: "edge-01", BootId: "b1"} },
		Decisions: enf, Policy: pol,
	}, slog.New(slog.DiscardHandler))
	cctx, ccancel := context.WithCancel(ctx)
	defer ccancel()
	go client.Run(cctx)

	waitFor("relayed decision", func() bool { return enf.Status().BanBothV4+enf.Status().BanInV4 == 1 })
	fl.add(2, "198.51.100.30", "openpicket/wan-reject-portscan", time.Hour)
	waitFor("second decision", func() bool { return enf.Status().BanBothV4+enf.Status().BanInV4 == 2 })
	waitFor("decisions acked", func() bool {
		var v int64
		return pool.QueryRow(ctx, `SELECT version FROM openpicket.node_decision_state WHERE node_id = 'edge-01'`).Scan(&v) == nil && uint64(v) == enf.Version()
	})

	if _, err := apiM.Policies().PutPolicy(ctx, portpolicy.Policy{ID: "rdp_block", Enabled: true, Mode: portpolicy.ModeEnforce, Proto: "tcp",
		Ports: []portpolicy.PortRange{{From: 3389, To: 3389}}, Default: portpolicy.ActionDrop,
		Rules: []portpolicy.Rule{{Source: portpolicy.Source{CIDRs: []string{"10.0.0.0/8"}}, Action: portpolicy.ActionAccept}}}, -1, "admin"); err != nil {
		t.Fatal(err)
	}
	waitFor("policy bundle", func() bool { return strings.Contains(ex.last(), "jump p_rdp_block") })
	waitFor("policy acked", func() bool {
		var v int64
		var e string
		return pool.QueryRow(ctx, `SELECT version, error FROM openpicket.node_policy_state WHERE node_id = 'edge-01'`).Scan(&v, &e) == nil && v > 0 && e == ""
	})
	// The compilation result is recorded by the API replica.
	waitFor("compiled", func() bool {
		var n int
		return pool.QueryRow(ctx, `SELECT count(*) FROM openpicket.policy_compiled WHERE policy_id = 'rdp_block' AND compiled IS NOT NULL`).Scan(&n) == nil && n == 1
	})

	// A server ships its log files through the gateway.
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "agent_ed25519")
	webKey, _, err := sshkey.LoadOrGenerate(keyFile, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	line := webKey.Public("web-01").String()
	x, _ := suristore.X25519(line)
	pk, _ := sshkey.ParsePublicKey(line)
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint) VALUES ('web-01',$1,$2,$3)`, line, x, pk.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	access := filepath.Join(dir, "access.log")
	_ = os.WriteFile(access, nil, 0o644)
	cfg, err := config.Parse([]byte(fmt.Sprintf(`node_id: web-01
key_file: %s
state_dir: %s
openpicket:
  url: %s
  host_key: %q
  suricata: { enabled: false }
  log_sources:
    - { program: nginx, path: %q }
`, keyFile, filepath.Join(dir, "state"), wsURL, want, access)))
	if err != nil {
		t.Fatal(err)
	}
	noFw4 := false
	a, err := agent.New(ctx, cfg, agent.Options{Logger: slog.New(slog.DiscardHandler), Host: fakeHost(t), Fw4: &noFw4})
	if err != nil {
		t.Fatal(err)
	}
	actx, acancel := context.WithCancel(ctx)
	adone := make(chan struct{})
	go func() { _ = a.Run(actx); close(adone) }()
	defer func() { acancel(); <-adone }()
	waitFor("web-01 online", func() bool { return gwM.Gateway().Session("web-01") != nil })
	time.Sleep(1500 * time.Millisecond)
	f, _ := os.OpenFile(access, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString(`198.51.100.67 - - [23/Oct/2026:12:00:00 +0000] "GET /x HTTP/1.1" 404 0 "-" "curl"` + "\n")
	f.Close()
	waitFor("line at CrowdSec", func() bool { return len(lp.lines()) == 1 && strings.HasPrefix(lp.lines()[0], "nginx: 198.51.100.67") })
	waitFor("line at Loki", func() bool {
		lk.mu.Lock()
		defer lk.mu.Unlock()
		for _, s := range lk.streams {
			if s["program"] == "nginx" {
				return true
			}
		}
		return false
	})
	// Presence (written by the gateway) is what the API reads.
	var replica string
	if err := pool.QueryRow(ctx, `SELECT replica FROM openpicket.node_sessions WHERE node_id = 'web-01'`).Scan(&replica); err != nil || replica != "gw-1" {
		t.Fatalf("session replica %q %v", replica, err)
	}
	acancel()
	<-adone
	stopGW()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM openpicket.log_programs WHERE node_id = 'web-01' AND program = 'nginx'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("log_programs: %d %v", n, err)
	}
}
