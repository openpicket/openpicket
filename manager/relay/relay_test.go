package relay

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager/lapi"
)

func dec(id int64, typ, scope, value, scenario, dur string) *lapi.Decision {
	return &lapi.Decision{ID: id, Origin: "crowdsec", Type: typ, Scope: scope, Value: value, Duration: dur, Scenario: scenario}
}

func setup(t *testing.T) (*pgxpool.Pool, *Relay, *time.Time) {
	t.Helper()
	pool := pgtest.Pool(t)
	if err := schema.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	r := New(Config{Rules: DefaultRules(), Now: func() time.Time { return now }})
	return pool, r, &now
}

func apply(t *testing.T, pool *pgxpool.Pool, r *Relay, s *lapi.Stream, full bool) int {
	t.Helper()
	var n int
	err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		var err error
		n, err = r.Apply(context.Background(), tx, s, full)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

type edge struct {
	direction string
	until     time.Time
	deleted   bool
	version   int64
}

func edges(t *testing.T, pool *pgxpool.Pool) map[string]edge {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT value, direction, until, deleted, version FROM openpicket.edge_decisions`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]edge{}
	for rows.Next() {
		var v string
		var e edge
		if err := rows.Scan(&v, &e.direction, &e.until, &e.deleted, &e.version); err != nil {
			t.Fatal(err)
		}
		out[v] = e
	}
	return out
}

func TestApplyBuildsTheEdgeView(t *testing.T) {
	pool, r, now := setup(t)
	s := &lapi.Stream{ReceivedAt: *now, New: []*lapi.Decision{
		dec(1, "ban", "Ip", "198.51.100.4", "openpicket/suricata-inbound-major", "4h"),
		dec(2, "ban", "Ip", "198.51.100.4", "openpicket/wan-reject-portscan", "1h"), // same value, shorter
		dec(3, "ban", "Ip", "198.51.100.9", "openpicket/suricata-outbound-c2", "24h"),
		dec(4, "captcha", "Ip", "198.51.100.10", "crowdsecurity/http-bf", "4h"),     // L7 only
		dec(5, "ban", "Range", "203.0.113.77/24", "manual/web-ui", "1h"),            // normalized
		dec(6, "ban", "Country", "CN", "manual/web-ui", "1h"),                       // not an edge scope
		dec(7, "ban", "Ip", "::ffff:198.51.100.20", "openpicket/manual-both", "2h"), // mapped v4, both
	}}
	if n := apply(t, pool, r, s, true); n != 4 {
		t.Fatalf("changes = %d", n)
	}
	e := edges(t, pool)
	if len(e) != 4 {
		t.Fatalf("edge rows = %v", e)
	}
	if got := e["198.51.100.4"]; got.direction != DirInbound || !got.until.Equal(now.Add(4*time.Hour)) {
		t.Fatalf("merged value = %+v", got)
	}
	if e["198.51.100.9"].direction != DirBoth || e["198.51.100.20"].direction != DirBoth {
		t.Fatal("outbound/manual-both must block both ways")
	}
	if _, ok := e["203.0.113.0/24"]; !ok {
		t.Fatal("range not normalized")
	}

	// Re-pulling the same state (startup) with rounding jitter changes nothing.
	*now = now.Add(5 * time.Second)
	s2 := &lapi.Stream{ReceivedAt: *now, New: []*lapi.Decision{
		dec(1, "ban", "Ip", "198.51.100.4", "openpicket/suricata-inbound-major", "3h59m56s"),
		dec(2, "ban", "Ip", "198.51.100.4", "openpicket/wan-reject-portscan", "59m55s"),
		dec(3, "ban", "Ip", "198.51.100.9", "openpicket/suricata-outbound-c2", "23h59m55s"),
		dec(5, "ban", "Range", "203.0.113.0/24", "manual/web-ui", "59m55s"),
		dec(7, "ban", "Ip", "198.51.100.20", "openpicket/manual-both", "1h59m55s"),
	}}
	if n := apply(t, pool, r, s2, true); n != 0 {
		t.Fatalf("idempotent resync changed %d rows", n)
	}

	// A delta deletes the longer decision of 198.51.100.4: the shorter one
	// remains, so the value stays blocked with the shorter until.
	if n := apply(t, pool, r, &lapi.Stream{ReceivedAt: *now, Deleted: []*lapi.Decision{{ID: 1}}}, false); n != 1 {
		t.Fatalf("delete changes = %d", n)
	}
	if got := edges(t, pool)["198.51.100.4"]; got.deleted || !got.until.Equal(time.Date(2026, 10, 20, 13, 0, 0, 0, time.UTC)) {
		t.Fatalf("after partial delete = %+v", got)
	}

	// A full resync without decision 3 tombstones its value.
	before := edges(t, pool)["198.51.100.9"].version
	if n := apply(t, pool, r, &lapi.Stream{ReceivedAt: *now, New: []*lapi.Decision{
		dec(2, "ban", "Ip", "198.51.100.4", "openpicket/wan-reject-portscan", "59m55s"),
		dec(5, "ban", "Range", "203.0.113.0/24", "manual/web-ui", "59m55s"),
		dec(7, "ban", "Ip", "198.51.100.20", "openpicket/manual-both", "1h59m55s"),
	}}, true); n != 1 {
		t.Fatalf("resync changes = %d", n)
	}
	if got := edges(t, pool)["198.51.100.9"]; !got.deleted || got.version <= before {
		t.Fatalf("tombstone = %+v", got)
	}
}

func pipe(t *testing.T) (*wire.MsgStream, *wire.MsgStream) {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return wire.NewMsgStream(a, 0), wire.NewMsgStream(b, 0)
}

func recvDown(t *testing.T, ms *wire.MsgStream) *dataplanev1.DecisionsDown {
	t.Helper()
	ch := make(chan *dataplanev1.DecisionsDown, 1)
	go func() {
		m := &dataplanev1.DecisionsDown{}
		if err := ms.Recv(m); err == nil {
			ch <- m
		}
	}()
	select {
	case m := <-ch:
		return m
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
		return nil
	}
}

func TestDistributorSnapshotThenDelta(t *testing.T) {
	pool, r, now := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint) VALUES ('n1','k','\x01','f')`); err != nil {
		t.Fatal(err)
	}
	apply(t, pool, r, &lapi.Stream{ReceivedAt: *now, New: []*lapi.Decision{
		dec(1, "ban", "Ip", "198.51.100.4", "openpicket/suricata-inbound-major", "4h"),
		dec(2, "ban", "Ip", "198.51.100.9", "openpicket/suricata-outbound-c2", "24h"),
	}}, true)

	d := NewDistributor(pool, nil)
	sendTime := now.Add(10 * time.Minute)
	d.now = func() time.Time { return sendTime }
	agent, mgr := pipe(t)
	go func() { _ = d.Serve(ctx, "n1", mgr) }()

	if err := agent.Send(&dataplanev1.DecisionsUp{Body: &dataplanev1.DecisionsUp_Subscribe{Subscribe: &dataplanev1.DecisionSubscribe{}}}); err != nil {
		t.Fatal(err)
	}
	snap := recvDown(t, agent).GetSnapshot()
	if snap == nil || len(snap.Decisions) != 2 {
		t.Fatalf("snapshot = %v", snap)
	}
	sort.Slice(snap.Decisions, func(i, j int) bool { return snap.Decisions[i].Value < snap.Decisions[j].Value })
	// TTL is computed at send time from the stored until.
	if got := snap.Decisions[0]; got.TtlMs != (4*time.Hour-10*time.Minute).Milliseconds() || got.Direction != dataplanev1.Direction_DIRECTION_INBOUND {
		t.Fatalf("decision = %+v", got)
	}
	if snap.Decisions[1].Direction != dataplanev1.Direction_DIRECTION_BOTH {
		t.Fatal("c2 must be BOTH")
	}
	_ = agent.Send(&dataplanev1.DecisionsUp{Body: &dataplanev1.DecisionsUp_Ack{Ack: &dataplanev1.DecisionAck{Version: snap.Version, SetSize: 2}}})

	// A change arrives as a delta from the acknowledged version.
	apply(t, pool, r, &lapi.Stream{ReceivedAt: *now, New: []*lapi.Decision{dec(3, "ban", "Ip", "198.51.100.30", "manual/web-ui", "1h")},
		Deleted: []*lapi.Decision{{ID: 1}}}, false)
	d.Notified("")
	delta := recvDown(t, agent).GetDelta()
	if delta == nil || delta.FromVersion != snap.Version || len(delta.Upserts) != 1 || len(delta.Deletes) != 1 || delta.Deletes[0] != "198.51.100.4" {
		t.Fatalf("delta = %v", delta)
	}
	// The node reports it could not apply: the next message is a snapshot.
	_ = agent.Send(&dataplanev1.DecisionsUp{Body: &dataplanev1.DecisionsUp_Ack{Ack: &dataplanev1.DecisionAck{Version: snap.Version, Error: "version mismatch"}}})
	if s := recvDown(t, agent).GetSnapshot(); s == nil || len(s.Decisions) != 2 || s.Version != delta.ToVersion {
		t.Fatalf("resync snapshot = %v", s)
	}
	var acked int64
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := pool.QueryRow(ctx, `SELECT version FROM openpicket.node_decision_state WHERE node_id = 'n1'`).Scan(&acked); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if acked != int64(snap.Version) {
		t.Fatalf("recorded ack = %d", acked)
	}
}

func TestExpireAndPrune(t *testing.T) {
	pool, r, now := setup(t)
	r.cfg.TombstoneRetention = time.Hour
	apply(t, pool, r, &lapi.Stream{ReceivedAt: *now, New: []*lapi.Decision{dec(1, "ban", "Ip", "198.51.100.4", "x", "10m")}}, true)
	*now = now.Add(11 * time.Minute)
	l := leadership(t, pool)
	if err := r.expire(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if !edges(t, pool)["198.51.100.4"].deleted {
		t.Fatal("expired value not tombstoned")
	}
	// Tombstones older than the retention go, and the horizon moves.
	if _, err := pool.Exec(context.Background(), `UPDATE openpicket.edge_decisions SET updated_at = $1`, now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := r.expire(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	var horizon int64
	_ = pool.QueryRow(context.Background(), `SELECT horizon FROM openpicket.edge_meta`).Scan(&horizon)
	if len(edges(t, pool)) != 0 || horizon == 0 {
		t.Fatalf("prune: rows=%d horizon=%d", len(edges(t, pool)), horizon)
	}
}

// txFencer runs transactions unconditionally (the test is the leader).
type txFencer struct{ pool *pgxpool.Pool }

func (f txFencer) Fenced(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, f.pool, fn)
}

func leadership(_ *testing.T, pool *pgxpool.Pool) Fencer { return txFencer{pool} }

func allow(t *testing.T, pool *pgxpool.Pool, network string, expires *time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO openpicket.allowlist (network, expires_at) VALUES ($1, $2)`, network, expires); err != nil {
		t.Fatal(err)
	}
}

func TestAllowlistKeepsDecisionsOffTheEdge(t *testing.T) {
	pool, r, now := setup(t)
	r.cfg.FullResyncInterval = 2 * time.Hour
	ctx := context.Background()
	l := leadership(t, pool)
	allow(t, pool, "192.0.2.0/24", nil)
	apply(t, pool, r, &lapi.Stream{ReceivedAt: *now, New: []*lapi.Decision{
		dec(1, "ban", "Ip", "192.0.2.7", "openpicket/suricata-inbound-major", "4h"),    // inside
		dec(2, "ban", "Range", "192.0.0.0/16", "manual/web-ui", "4h"),                  // covers the entry
		dec(3, "ban", "Ip", "198.51.100.4", "openpicket/suricata-inbound-major", "4h"), // outside
		dec(4, "ban", "Ip", "2001:db8::1", "openpicket/suricata-inbound-major", "4h"),  // outside (v6)
		dec(5, "ban", "Ip", "fe80::1%eth0", "openpicket/suricata-inbound-major", "4h"), // zoned: not an edge value
		dec(6, "ban", "Country", "CN", "manual/web-ui", "4h"),                          // not an edge scope
	}}, true)
	e := edges(t, pool)
	if _, ok := e["192.0.2.7"]; ok {
		t.Fatal("allowlisted address reached the edge")
	}
	if _, ok := e["192.0.0.0/16"]; ok {
		t.Fatal("a range overlapping the allowlist reached the edge")
	}
	if len(e) != 2 {
		t.Fatalf("edge rows = %v", e)
	}

	// A new entry tombstones what it covers.
	allow(t, pool, "198.51.100.0/24", nil)
	exp := now.Add(time.Hour)
	allow(t, pool, "2001:db8::/32", &exp)
	next, err := r.Reconcile(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Equal(exp) {
		t.Fatalf("next reconcile = %v, want the expiry %v", next, exp)
	}
	e = edges(t, pool)
	if !e["198.51.100.4"].deleted || !e["2001:db8::1"].deleted {
		t.Fatalf("covered values not tombstoned: %v", e)
	}
	// Nothing left to change.
	before := edges(t, pool)
	if _, err := r.Reconcile(ctx, l); err != nil {
		t.Fatal(err)
	}
	if after := edges(t, pool); after["198.51.100.4"].version != before["198.51.100.4"].version {
		t.Fatal("a second reconcile changed versions")
	}

	// Removing an entry and an entry running out bring their values back.
	if _, err := pool.Exec(ctx, `DELETE FROM openpicket.allowlist WHERE network = '192.0.2.0/24'`); err != nil {
		t.Fatal(err)
	}
	*now = exp
	next, err = r.Reconcile(ctx, l)
	if err != nil {
		t.Fatal(err)
	}
	if !next.Equal(now.Add(r.cfg.FullResyncInterval)) {
		t.Fatalf("next reconcile without expiries = %v", next)
	}
	e = edges(t, pool)
	for _, v := range []string{"192.0.2.7", "192.0.0.0/16", "2001:db8::1"} {
		if got, ok := e[v]; !ok || got.deleted {
			t.Fatalf("%s not blocked again: %v", v, e)
		}
	}
	if !e["198.51.100.4"].deleted {
		t.Fatal("198.51.100.4 is still allowlisted")
	}
}

func TestNotifiedWakesRun(t *testing.T) {
	r := New(Config{})
	r.Notified("")
	r.Notified("") // never blocks
	select {
	case <-r.poke:
	default:
		t.Fatal("no wake-up queued")
	}
}
