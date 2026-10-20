package test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent/dataplane"
	"github.com/openpicket/openpicket/agent/enforcer"
	"github.com/openpicket/openpicket/agent/nft"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager"
	"github.com/openpicket/openpicket/manager/lapi"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/pkg/direction"
	"github.com/openpicket/openpicket/suristore"
)

// fakeLAPI serves /v1/decisions/stream with the cursor semantics of the
// real LAPI: startup returns every active decision, later pulls return new
// ones (by id) and the ones expired since the last pull.
type fakeLAPI struct {
	mu        sync.Mutex
	decisions []*fakeDecision
	cursor    int64
	lastPull  time.Time
}

type fakeDecision struct {
	lapi.Decision
	until time.Time
}

func (f *fakeLAPI) add(id int64, value, scenario string, d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decisions = append(f.decisions, &fakeDecision{Decision: lapi.Decision{ID: id, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: value, Scenario: scenario}, until: time.Now().Add(d)})
}

func (f *fakeLAPI) expire(id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.decisions {
		if d.ID == id {
			d.until = time.Now()
		}
	}
}

func (f *fakeLAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/decisions/stream" || r.Header.Get("X-Api-Key") != "bouncer-key" {
		http.Error(w, "not allowed", http.StatusForbidden)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	startup := r.URL.Query().Get("startup") == "true"
	resp := struct {
		New     []lapi.Decision `json:"new"`
		Deleted []lapi.Decision `json:"deleted"`
	}{New: []lapi.Decision{}, Deleted: []lapi.Decision{}}
	var latest int64
	for _, d := range f.decisions {
		latest = max(latest, d.ID)
		dd := d.Decision
		dd.Duration = d.until.Sub(now).Round(time.Second).String()
		switch {
		case d.until.After(now) && (startup || d.ID > f.cursor):
			resp.New = append(resp.New, dd)
		case !d.until.After(now) && (startup || d.until.After(f.lastPull.Add(-2*time.Second))):
			resp.Deleted = append(resp.Deleted, dd)
		}
	}
	f.cursor, f.lastPull = latest, now
	_ = json.NewEncoder(w).Encode(resp)
}

// fakeNft records nft scripts; the enforcer keeps the state.
type fakeNft struct{}

func (fakeNft) Run(_ context.Context, _ string, args []string, _ []byte) ([]byte, error) {
	if len(args) > 0 && args[0] == "list" {
		return []byte("chain guard { ip saddr @both4 }"), nil
	}
	return nil, nil
}
func (fakeNft) LookPath(n string) (string, error) { return n, nil }

func TestDecisionsReachTheEdge(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	fl := &fakeLAPI{}
	fl.add(1, "198.51.100.4", "manual/web-ui", 4*time.Hour)
	fl.add(2, "198.51.100.9", "openpicket/suricata-outbound-c2", 24*time.Hour)
	fl.add(3, "192.168.1.77", "openpicket/dnat-miss-portscan", time.Hour) // inside: refused by the node
	lapiSrv := httptest.NewServer(fl)
	defer lapiSrv.Close()
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer sink.Close()

	hostKey, _ := sshkey.Generate()
	start := func(name string) *replica {
		m, err := manager.New(manager.Options{
			DB: pool, HostKey: hostKey, ReplicaID: name,
			Loki: loki.Config{URL: sink.URL}, CrowdSec: crowdsec.Config{Endpoints: []string{sink.URL}},
			LAPI: lapi.Config{URL: lapiSrv.URL, BouncerKey: "bouncer-key"}, RelayPullInterval: 100 * time.Millisecond,
			Logger: slog.New(slog.DiscardHandler),
		})
		if err != nil {
			t.Fatal(err)
		}
		rctx, cancel := context.WithCancel(context.Background())
		r := &replica{m: m, srv: httptest.NewServer(m.Handler()), cancel: cancel, done: make(chan struct{})}
		go func() { _ = m.Run(rctx); close(r.done) }()
		return r
	}
	a, b := start("replica-a"), start("replica-b")
	lb := &switchProxy{}
	lb.set(a.srv.URL)
	lbSrv := httptest.NewServer(lb)
	defer lbSrv.Close()

	agentKey, _ := sshkey.Generate()
	line := agentKey.Public("edge-01").String()
	x, _ := suristore.X25519(line)
	pk, _ := sshkey.ParsePublicKey(line)
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint) VALUES ('edge-01',$1,$2,$3)`, line, x, pk.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	inside, _ := direction.NewNets([]string{"192.168.1.0/24"})
	enf := enforcer.New(enforcer.Config{Host: &nft.Host{Exec: fakeNft{}}, Table: nft.BanConfig{WAN: []string{"wan"}, Egress: true},
		Allow: func() []netip.Prefix { return nil }, Nets: func() *direction.Nets { return inside },
		StateFile: t.TempDir() + "/decisions.json", Logger: slog.New(slog.DiscardHandler)})
	if err := enf.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	client := dataplane.NewClient(dataplane.DialConfig{
		URL: "ws" + strings.TrimPrefix(lbSrv.URL, "http") + "/agent/data/v1/connect", Key: agentKey,
		ServerKey: hostKey.Public(manager.HostKeyComment), NodeID: "edge-01", Version: "test",
	}, dataplane.Handlers{
		Hello:     func() *dataplanev1.Hello { return &dataplanev1.Hello{NodeId: "edge-01", BootId: "b1"} },
		Decisions: enf,
	}, slog.New(slog.DiscardHandler))
	cctx, ccancel := context.WithCancel(ctx)
	defer ccancel()
	go client.Run(cctx)

	waitUntil := func(what string, cond func(*dataplanev1.EnforcerStatus) bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !cond(enf.Status()) {
			if time.Now().After(deadline) {
				t.Fatalf("timeout: %s (status %+v)", what, enf.Status())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// 192.168.1.77 is inside the node: refused locally.
	waitUntil("initial decisions", func(s *dataplanev1.EnforcerStatus) bool { return s.BanInV4 == 1 && s.BanBothV4 == 1 && s.Rejected >= 1 })

	fl.add(4, "198.51.100.30", "openpicket/dnat-miss-portscan", time.Hour)
	fl.expire(1)
	v := enf.Version()
	waitUntil("delta applied", func(s *dataplanev1.EnforcerStatus) bool { return s.BanInV4 == 1 && s.DecisionsVersion > v })

	// Both replicas go down one after the other; the relay leadership and
	// the agent session move to replica B, then the whole manager stops.
	lb.set(b.srv.URL)
	a.stop()
	fl.add(5, "198.51.100.40", "manual/web-ui", time.Hour)
	waitUntil("decision after failover", func(s *dataplanev1.EnforcerStatus) bool { return s.BanInV4 == 2 })
	// The node's acknowledgement is recorded asynchronously.
	var acked int64
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		err := pool.QueryRow(ctx, `SELECT version FROM openpicket.node_decision_state WHERE node_id = 'edge-01'`).Scan(&acked)
		if err == nil && uint64(acked) == enf.Version() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("acked version %d vs node %d (%v)", acked, enf.Version(), err)
		}
	}
	b.stop()
	before := enf.Status()
	time.Sleep(500 * time.Millisecond)
	if after := enf.Status(); after.BanInV4 != before.BanInV4 || after.BanBothV4 != before.BanBothV4 {
		t.Fatalf("blocks changed while the manager is down: %+v -> %+v", before, after)
	}
}
