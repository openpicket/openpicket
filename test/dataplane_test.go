// Package test holds end-to-end tests across the manager and the agent.
package test

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent/dataplane"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/pkg/record"
	"github.com/openpicket/openpicket/suristore"
)

// fakeLoki records the rid of every pushed line; it fails while failing is set.
type fakeLoki struct {
	failing atomic.Bool
	mu      sync.Mutex
	rids    map[string]int
}

func (f *fakeLoki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.failing.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	zr, _ := gzip.NewReader(r.Body)
	var p struct {
		Streams []struct {
			Values [][]any `json:"values"`
		} `json:"streams"`
	}
	if err := json.NewDecoder(zr).Decode(&p); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range p.Streams {
		for _, v := range s.Values {
			md, _ := v[2].(map[string]any)
			rid, _ := md["rid"].(string)
			f.rids[rid]++
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeLoki) count() (distinct int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rids)
}

// fakeLP records the rid of every record CrowdSec receives.
type fakeLP struct {
	mu   sync.Mutex
	rids map[string]int
}

func (f *fakeLP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zr, _ := gzip.NewReader(r.Body)
	sc := bufio.NewScanner(zr)
	f.mu.Lock()
	defer f.mu.Unlock()
	for sc.Scan() {
		var e record.Eve
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil || e.OpenPicket == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.rids[e.OpenPicket.RID]++
	}
}

// switchProxy forwards to the current backend (a load balancer).
type switchProxy struct {
	mu     sync.Mutex
	target *url.URL
}

func (p *switchProxy) set(u string) {
	t, _ := url.Parse(u)
	p.mu.Lock()
	p.target = t
	p.mu.Unlock()
}

func (p *switchProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	t := p.target
	p.mu.Unlock()
	httputil.NewSingleHostReverseProxy(t).ServeHTTP(w, r)
}

type replica struct {
	m      *manager.Manager
	srv    *httptest.Server
	cancel context.CancelFunc
	done   chan struct{}
}

func startReplica(t *testing.T, pool *pgxpool.Pool, key *sshkey.PrivateKey, lokiURL, lpURL, name string) *replica {
	t.Helper()
	m, err := manager.New(manager.Options{
		DB: pool, HostKey: key, ReplicaID: name,
		Loki:              loki.Config{URL: lokiURL},
		CrowdSec:          crowdsec.Config{Endpoints: []string{lpURL}, NflogPrefixes: []string{"WAN-REJECT"}},
		PipelineOpenAfter: time.Hour,
		Logger:            slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &replica{m: m, srv: httptest.NewServer(m.Handler()), cancel: cancel, done: make(chan struct{})}
	go func() { _ = m.Run(ctx); close(r.done) }()
	return r
}

func (r *replica) stop() {
	r.cancel()
	<-r.done
	r.srv.CloseClientConnections()
	r.srv.Close()
}

func nflogRecord(s *dataplane.Shipper, i int) *dataplanev1.Record {
	rid := s.NextMemoryRID()
	line := record.AppendTag([]byte(fmt.Sprintf(`{"timestamp":"%s","event_type":"nflog","prefix":"WAN-REJECT","src_ip":"198.51.100.%d","dest_ip":"203.0.113.1","dest_port":3389}`,
		time.Now().UTC().Format(time.RFC3339Nano), i%250)), record.Tag{RID: rid, Direction: "inbound", RemoteIP: fmt.Sprintf("198.51.100.%d", i%250)})
	return &dataplanev1.Record{Line: line, Rid: rid, TimeUnixNano: time.Now().UnixNano()}
}

func TestReplicaFailoverLosesNothing(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	lk := &fakeLoki{rids: map[string]int{}}
	lokiSrv := httptest.NewServer(lk)
	defer lokiSrv.Close()
	lp := &fakeLP{rids: map[string]int{}}
	lpSrv := httptest.NewServer(lp)
	defer lpSrv.Close()

	hostKey, _ := sshkey.Generate()
	a := startReplica(t, pool, hostKey, lokiSrv.URL, lpSrv.URL, "replica-a")
	b := startReplica(t, pool, hostKey, lokiSrv.URL, lpSrv.URL, "replica-b")
	defer b.stop()
	lb := &switchProxy{}
	lb.set(a.srv.URL)
	lbSrv := httptest.NewServer(lb)
	defer lbSrv.Close()

	// Register the node the way the UI does: in the shared registry.
	agentKey, _ := sshkey.Generate()
	line := agentKey.Public("edge-01").String()
	x, _ := suristore.X25519(line)
	pk, _ := sshkey.ParsePublicKey(line)
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint) VALUES ('edge-01',$1,$2,$3)`, line, x, pk.Fingerprint()); err != nil {
		t.Fatal(err)
	}

	shipper := dataplane.NewShipper(dataplane.ShipperConfig{NodeID: "edge-01", BootID: "boot-1"})
	client := dataplane.NewClient(dataplane.DialConfig{
		URL: "ws" + strings.TrimPrefix(lbSrv.URL, "http") + "/agent/data/v1/connect", Key: agentKey,
		ServerKey: hostKey.Public(manager.HostKeyComment), NodeID: "edge-01", Version: "test",
	}, dataplane.Handlers{
		Hello: func() *dataplanev1.Hello {
			return &dataplanev1.Hello{NodeId: "edge-01", AgentVersion: "test", BootId: "boot-1"}
		},
		Shipper: shipper,
	}, slog.New(slog.DiscardHandler))
	cctx, ccancel := context.WithCancel(ctx)
	defer ccancel()
	go client.Run(cctx)

	push := func(from, to int) {
		for i := from; i < to; i += 10 {
			var recs []*dataplanev1.Record
			for j := i; j < i+10; j++ {
				recs = append(recs, nflogRecord(shipper, j))
			}
			if !shipper.Push(ctx, record.TypeNflog, recs, 0) {
				t.Fatal("push failed")
			}
		}
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

	push(0, 50)
	waitUntil("first records in Loki", func() bool { return lk.count() == 50 })
	waitUntil("acknowledged", func() bool { return shipper.Stats().InflightBatches == 0 })

	// Loki goes down. Batches of a session are processed in order: the
	// first new batch reaches CrowdSec and waits for Loki; it and the
	// following ones stay unacknowledged on the agent.
	lk.failing.Store(true)
	push(50, 100)
	waitUntil("crowdsec has the first new batch", func() bool {
		lp.mu.Lock()
		defer lp.mu.Unlock()
		return len(lp.rids) == 60
	})
	if n := shipper.Stats().InflightBatches; n == 0 {
		t.Fatal("batches should be in flight while Loki is down")
	}

	// Replica A goes away; the load balancer sends the agent to B, Loki
	// recovers.
	lb.set(b.srv.URL)
	a.stop()
	lk.failing.Store(false)
	push(100, 120)
	waitUntil("every record in Loki", func() bool { return lk.count() == 120 })
	waitUntil("everything acknowledged", func() bool { return shipper.Stats().InflightBatches == 0 })

	lp.mu.Lock()
	defer lp.mu.Unlock()
	if len(lp.rids) != 120 {
		t.Fatalf("crowdsec distinct records = %d", len(lp.rids))
	}
	for rid, n := range lp.rids {
		if n != 1 {
			t.Fatalf("record %s reached CrowdSec %d times", rid, n)
		}
	}
	var replicaName string
	if err := pool.QueryRow(ctx, `SELECT replica FROM openpicket.node_sessions WHERE node_id = 'edge-01'`).Scan(&replicaName); err != nil || replicaName != "replica-b" {
		t.Fatalf("presence = %q, %v", replicaName, err)
	}
}
