package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
)

type fence struct{ db *pgxpool.Pool }

func (f fence) Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, f.db, fn)
}

var nextID int64 = 1

func addAlert(t *testing.T, db *pgxpool.Pool, scenario, ip, scope string, created time.Time, ban bool) {
	t.Helper()
	ctx := context.Background()
	id := nextID
	nextID++
	if _, err := db.Exec(ctx, `INSERT INTO openpicket.alerts (instance, id, scenario, source_scope, source_value, country, node_id, created_at, events_count)
		VALUES ('default', $1, $2, $3, $4, 'CN', 'edge-01', $5, 3)`, id, scenario, scope, ip, created); err != nil {
		t.Fatal(err)
	}
	if ban {
		if _, err := db.Exec(ctx, `INSERT INTO openpicket.alert_decisions (instance, id, alert_id, type, scope, value, origin, scenario, until)
			VALUES ('default', $1, $1, 'ban', 'Ip', $2, 'crowdsec', $3, $4)`, id, ip, scenario, created.Add(4*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
}

func notifications(t *testing.T, db *pgxpool.Pool, rule string) []string {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT title FROM openpicket.notifications WHERE rule_id = $1 ORDER BY id`, rule)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

func TestEngine(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var (
		mu       sync.Mutex
		received []Message
		failing  = true
	)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/flaky" && failing {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var m Message
		_ = json.Unmarshal(b, &m)
		received = append(received, m)
	}))
	defer hook.Close()
	now := time.Now().Truncate(time.Second)
	clock := now
	e := NewEngine(Config{DB: pool, PublicURL: "https://op.example", Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return clock }})
	st := &Store{DB: pool}
	for _, d := range []*Destination{
		{ID: "hook", Name: "Hook", Type: "webhook", Enabled: true, Config: map[string]string{"url": hook.URL + "/ok"}},
		{ID: "flaky", Name: "Flaky", Type: "webhook", Enabled: true, Config: map[string]string{"url": hook.URL + "/flaky"}, Severities: []string{"critical"}},
	} {
		if err := st.PutDestination(ctx, d, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	addAlert(t, pool, "crowdsecurity/ssh-bf", "198.51.100.1", "Ip", now.Add(-time.Hour), true)
	for _, r := range []*Rule{
		{ID: "all", Name: "New alerts", Enabled: true, Type: NewAlert, Query: "-scenario:portscan", Destinations: []string{"hook"}},
		{ID: "bans", Name: "Bans in TEST-NET-3", Enabled: true, Type: IPBan, IPFilters: []string{"203.0.113.0/24"}, Destinations: []string{"hook"}},
		{ID: "hosts", Name: "Compromised", Enabled: true, Type: CompromisedHost, Destinations: []string{"hook", "flaky"}},
		{ID: "many", Name: "Many", Enabled: true, Type: AlertThreshold, Threshold: 3, WindowSeconds: 300, Destinations: []string{"hook"}},
	} {
		if err := st.PutRule(ctx, r, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.PutRule(ctx, &Rule{ID: "bad", Name: "x", Type: NewAlert, Query: "nope:1"}, "admin"); err == nil {
		t.Fatal("invalid query accepted")
	}
	// The first pass only records where the rules start.
	if err := e.Evaluate(ctx, fence{pool}); err != nil {
		t.Fatal(err)
	}
	if n := notifications(t, pool, "all"); len(n) != 0 {
		t.Fatalf("history notified: %v", n)
	}
	addAlert(t, pool, "crowdsecurity/ssh-bf", "203.0.113.5", "Ip", now, true)
	addAlert(t, pool, "openpicket/wan-reject-portscan", "198.51.100.9", "Ip", now, true)
	addAlert(t, pool, "openpicket/compromised-host", "192.168.1.60", "openpicket_host", now, false)
	if err := e.Evaluate(ctx, fence{pool}); err != nil {
		t.Fatal(err)
	}
	if n := notifications(t, pool, "all"); len(n) != 2 || n[0] != "crowdsecurity/ssh-bf from 203.0.113.5" {
		t.Fatalf("new alerts: %v", n)
	}
	if n := notifications(t, pool, "bans"); len(n) != 1 || n[0] != "Ban 203.0.113.5" {
		t.Fatalf("bans: %v", n)
	}
	if n := notifications(t, pool, "hosts"); len(n) != 1 || n[0] != "Compromised host 192.168.1.60" {
		t.Fatalf("hosts: %v", n)
	}
	if n := notifications(t, pool, "many"); len(n) != 1 {
		t.Fatalf("threshold: %v", n)
	}
	// Cooldown: the threshold stays exceeded but does not fire again.
	clock = now.Add(time.Minute)
	if err := e.Evaluate(ctx, fence{pool}); err != nil {
		t.Fatal(err)
	}
	if n := notifications(t, pool, "many"); len(n) != 1 {
		t.Fatalf("cooldown: %v", n)
	}

	if err := e.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(received) != 5 || received[0].Link == "" || received[0].Link[:19] != "https://op.example/" {
		t.Fatalf("received: %+v", received)
	}
	mu.Unlock()
	// The critical notification failed on "flaky" and is retried later.
	var status string
	var attempts int
	if err := pool.QueryRow(ctx, `SELECT status, attempts FROM openpicket.notify_deliveries WHERE destination_id = 'flaky'`).Scan(&status, &attempts); err != nil ||
		status != "pending" || attempts != 1 {
		t.Fatalf("flaky: %s %d %v", status, attempts, err)
	}
	mu.Lock()
	failing = false
	mu.Unlock()
	clock = now.Add(2 * time.Minute)
	if err := e.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM openpicket.notify_deliveries WHERE destination_id = 'flaky'`).Scan(&status); err != nil || status != "sent" {
		t.Fatalf("retry: %s %v", status, err)
	}

	// A node going offline fires once, until it comes back.
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint, dp_last_seen_at) VALUES ('edge-01','k','\x01','f',$1)`,
		now.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.PutRule(ctx, &Rule{ID: "offline", Name: "Offline", Enabled: true, Type: NodeOffline, CooldownSeconds: 1}, "admin"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		clock = clock.Add(5 * time.Second)
		if err := e.Evaluate(ctx, fence{pool}); err != nil {
			t.Fatal(err)
		}
	}
	if n := notifications(t, pool, "offline"); len(n) != 1 || n[0] != "Node edge-01 is offline" {
		t.Fatalf("offline: %v", n)
	}
}
