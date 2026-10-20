package misp_test

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/internal/lapitest"
	"github.com/openpicket/openpicket/internal/misptest"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager/lapi"
	"github.com/openpicket/openpicket/manager/misp"
)

type fence struct{ db *pgxpool.Pool }

func (f fence) Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, f.db, fn)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// activeMISPDecisions returns value -> until of the active MISP decisions.
func activeMISPDecisions(l *lapitest.LAPI, now time.Time) map[string][]string {
	out := map[string][]string{}
	for _, a := range l.Alerts() {
		for _, d := range a.Decisions {
			until, _ := time.Parse(time.RFC3339, d.Until)
			if strings.HasPrefix(*d.Scenario, "openpicket/misp-") && until.After(now) {
				out[*d.Value] = append(out[*d.Value], *d.Scenario+" "+*d.Origin)
			}
		}
	}
	return out
}

func TestApproveBlockRevoke(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	fakeLAPI := lapitest.New()
	defer fakeLAPI.Close()
	fakeLAPI.Now = clk.Now
	fakeMISP := misptest.New()
	defer fakeMISP.Close()
	lc, _ := lapi.New(lapi.Config{URL: fakeLAPI.URL, Login: fakeLAPI.Login, Password: fakeLAPI.Password})
	w, _ := lc.Watcher()
	mc, err := misp.NewClient(misp.ClientConfig{URL: fakeMISP.URL, APIKey: fakeMISP.Key})
	if err != nil {
		t.Fatal(err)
	}
	svc := misp.New(misp.Config{DB: pool, Client: mc, LAPI: w, ProposeMinAlerts: 3, Logger: slog.New(slog.DiscardHandler), Now: clk.Now})
	sync := func() {
		t.Helper()
		if err := svc.Sync(ctx, fence{pool}); err != nil {
			t.Fatal(err)
		}
	}

	// (1) A repeated attacker is proposed to MISP.
	for i := 1; i <= 3; i++ {
		if _, err := pool.Exec(ctx, `INSERT INTO openpicket.alerts (instance, id, scenario, source_scope, source_value, node_id, created_at)
			VALUES ('default', $1, 'openpicket/dnat-miss-portscan', 'Ip', '198.51.100.7', 'edge-01', $2)`, i, clk.Now()); err != nil {
			t.Fatal(err)
		}
	}
	sync() // proposes
	sync() // reads the proposal back
	attrs := fakeMISP.Attributes()
	if len(attrs) != 1 || attrs[0].Value != "198.51.100.7" || attrs[0].ToIDS || attrs[0].Machine("state") != "proposed" ||
		!strings.Contains(attrs[0].Comment, "3 alerts") {
		t.Fatalf("proposal: %+v", attrs)
	}
	var state, event string
	if err := pool.QueryRow(ctx, `SELECT state, event_info FROM openpicket.misp_iocs WHERE value = '198.51.100.7'`).Scan(&state, &event); err != nil ||
		state != "proposed" || !strings.HasPrefix(event, "OpenPicket sightings ") {
		t.Fatalf("copy: %s %s %v", state, event, err)
	}
	if len(activeMISPDecisions(fakeLAPI, clk.Now())) != 0 {
		t.Fatal("decision before approval")
	}
	if _, err := svc.Propose(ctx, "198.51.100.7", "ip-src", ""); err == nil {
		t.Fatal("duplicate proposal accepted")
	}

	// (2)+(3) Approval in OpenPicket -> decision; an analyst approves an
	// ip-dst in MISP directly -> both-way decision.
	uuid := attrs[0].UUID
	if err := svc.SetState(ctx, []string{uuid}, misp.StateApproved, "30d"); err != nil {
		t.Fatal(err)
	}
	fakeMISP.Add("ip-dst", "203.0.113.66", true, misp.StateTag(misp.StateApproved), misp.TTLTag("7d"))
	fakeMISP.Add("ip-src", "203.0.113.67", true) // no openpicket tag: ignored
	sync()
	a := fakeMISP.Attributes()[0]
	if !a.ToIDS || a.Machine("state") != "approved" || a.Machine("ttl") != "30d" || len(a.Tags) != 2 {
		t.Fatalf("approved attribute: %+v", a)
	}
	got := activeMISPDecisions(fakeLAPI, clk.Now())
	if len(got) != 2 || got["198.51.100.7"][0] != "openpicket/misp-ip-src misp" || got["203.0.113.66"][0] != "openpicket/misp-ip-dst misp" {
		t.Fatalf("decisions: %v", got)
	}
	// (4) Kept: no duplicate while the decision is fresh, renewed when
	// less than the renew interval remains.
	sync()
	if n := len(fakeLAPI.Alerts()); n != 2 {
		t.Fatalf("duplicate decisions: %d alerts", n)
	}
	clk.Add(7 * time.Hour)
	sync()
	if n := len(fakeLAPI.Alerts()); n != 4 {
		t.Fatalf("renewal: %d alerts", n)
	}
	// MISP down: nothing is deleted.
	fakeMISP.Down = true
	if err := svc.Sync(ctx, fence{pool}); err == nil {
		t.Fatal("sync with MISP down succeeded")
	}
	if len(activeMISPDecisions(fakeLAPI, clk.Now())) != 2 {
		t.Fatal("decisions removed while MISP was down")
	}
	var lastErr string
	_ = pool.QueryRow(ctx, `SELECT last_error FROM openpicket.misp_sync`).Scan(&lastErr)
	if lastErr == "" {
		t.Fatal("error not recorded")
	}
	fakeMISP.Down = false

	// (4) Revocation removes the decision; the 7d approval expires.
	if err := svc.SetState(ctx, []string{uuid}, misp.StateRevoked, ""); err != nil {
		t.Fatal(err)
	}
	sync()
	got = activeMISPDecisions(fakeLAPI, clk.Now())
	if _, ok := got["198.51.100.7"]; ok || len(got) != 1 {
		t.Fatalf("after revoke: %v", got)
	}
	if fakeMISP.Attributes()[0].ToIDS {
		t.Fatal("revoked attribute still to_ids")
	}
	clk.Add(8 * 24 * time.Hour)
	sync()
	if got := activeMISPDecisions(fakeLAPI, clk.Now()); len(got) != 0 {
		t.Fatalf("after ttl: %v", got)
	}
	// Deleted in MISP: the copy shows it revoked.
	fakeMISP.Delete(fakeMISP.Attributes()[1].UUID)
	sync()
	if err := pool.QueryRow(ctx, `SELECT state FROM openpicket.misp_iocs WHERE value = '203.0.113.66'`).Scan(&state); err != nil || state != "revoked" {
		t.Fatalf("deleted attribute: %s %v", state, err)
	}
}

func TestParseTTL(t *testing.T) {
	for in, want := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "12h": 12 * time.Hour} {
		if got, err := misp.ParseTTL(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0d", "forever", "-1h"} {
		if _, err := misp.ParseTTL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
