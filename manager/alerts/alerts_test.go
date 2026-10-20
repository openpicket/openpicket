package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/internal/lapitest"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager/lapi"
)

type fence struct{ db *pgxpool.Pool }

func (f fence) Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, f.db, fn)
}

func count(t *testing.T, db *pgxpool.Pool, sql string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSyncAndQuery(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	fake := lapitest.New()
	defer fake.Close()
	c, _ := lapi.New(lapi.Config{URL: fake.URL, Login: fake.Login, Password: fake.Password})
	w, _ := c.Watcher()
	now := time.Now().Truncate(time.Second)
	syncer := NewSyncer(Config{DB: pool, Instances: []Instance{{Name: "default", URL: fake.URL, Watcher: w}}, Logger: slog.New(slog.DiscardHandler)})

	for i := range 300 {
		cc := []string{"CN", "RU", "US"}[i%3]
		var ban time.Duration
		if i%10 == 0 {
			ban = 4 * time.Hour
		}
		fake.Add("crowdsecurity/ssh-bf", fmt.Sprintf("198.51.%d.%d", i/250, i%250), cc, "edge-01", ban, now.Add(-time.Duration(300-i)*time.Minute))
	}
	if err := syncer.SyncOnce(ctx, fence{pool}, true, true); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, `SELECT count(*) FROM openpicket.alerts`); n != 300 {
		t.Fatalf("full sync: %d alerts", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM openpicket.alert_decisions`); n != 30 {
		t.Fatalf("full sync: %d decisions", n)
	}
	// 250 new alerts: more than the first page, the limit grows.
	for i := range 250 {
		fake.Add("openpicket/dnat-miss-portscan", fmt.Sprintf("203.0.%d.%d", i/200, i%200), "KR", "edge-02", 0, now)
	}
	if err := syncer.SyncOnce(ctx, fence{pool}, false, false); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, `SELECT count(*) FROM openpicket.alerts`); n != 550 {
		t.Fatalf("incremental: %d alerts", n)
	}
	// Decisions deleted in the LAPI (cscli) leave with the active pass;
	// deleted alerts with the full pass.
	// Alert 291 (i=290) carries an active ban (alerts older than 4h have
	// expired ones).
	active := fake.Alerts()[290]
	if _, err := w.DeleteDecision(ctx, active.Decisions[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := w.DeleteAlert(ctx, fake.Alerts()[1].ID); err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(ctx, fence{pool}, true, false); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, `SELECT count(*) FROM openpicket.alert_decisions`); n != 29 {
		t.Fatalf("active pass: %d decisions", n)
	}
	if err := syncer.SyncOnce(ctx, fence{pool}, true, true); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, `SELECT count(*) FROM openpicket.alerts`); n != 549 {
		t.Fatalf("full pass: %d alerts", n)
	}

	q := &Querier{DB: pool}
	list, total, err := q.Search(ctx, Filter{Query: "country:CN node:edge-01"}, 10, 0, "", false)
	if err != nil || total != 100 || len(list) != 10 || list[0].NodeId != "edge-01" || list[0].Source.Country != "CN" {
		t.Fatalf("search: %d %v %v", total, list, err)
	}
	if list[0].CreatedAt.AsTime().Before(list[9].CreatedAt.AsTime()) {
		t.Fatal("not newest first")
	}
	_, total, _ = q.Search(ctx, Filter{Query: "meta.dst_ip=192.168.1.10 -scenario:ssh"}, 1, 0, "", false)
	if total != 250 {
		t.Fatalf("meta search: %d", total)
	}
	_, total, _ = q.Search(ctx, Filter{Query: "active:true"}, 1, 0, "", false)
	if total != 22 {
		t.Fatalf("active: %d", total)
	}
	if _, _, err := q.Search(ctx, Filter{Query: "nope:x"}, 1, 0, "", false); err == nil {
		t.Fatal("unknown field")
	}
	a, events, err := q.Get(ctx, "default", 3)
	if err != nil || a.Scenario != "crowdsecurity/ssh-bf" || len(a.Meta) != 3 || events == "[]" {
		t.Fatalf("get: %v %s %v", a, events, err)
	}

	facets, err := q.Facets(ctx, Filter{Query: "country:CN"}, []string{"country", "scenario", "origin"}, "", 5)
	if err != nil {
		t.Fatal(err)
	}
	// country ignores its own clause, scenario does not.
	if len(facets[0].Values) != 4 || facets[0].Values[0].Value != "KR" || facets[0].Values[0].Count != 250 {
		t.Fatalf("country facet: %v", facets[0])
	}
	if len(facets[1].Values) != 1 || facets[1].Values[0].Count != 100 {
		t.Fatalf("scenario facet: %v", facets[1])
	}
	if facets[2].Values[0].Value != "crowdsec" {
		t.Fatalf("origin facet: %v", facets[2])
	}

	decs, total, err := q.Decisions(ctx, DecisionFilter{Query: "country:RU"}, 100, 0)
	if err != nil || total != 8 || !decs[0].Active || decs[0].Type != "ban" {
		t.Fatalf("decisions: %d %v %v", total, decs, err)
	}
	sum, err := q.Summary(ctx, Filter{From: now.Add(-24 * time.Hour)})
	if err != nil || sum.Alerts != 549 || sum.ActiveDecisions != 22 || len(sum.TopCountries) != 4 || len(sum.Series) == 0 {
		t.Fatalf("summary: %v %v", sum, err)
	}
	p, err := q.Propagation(ctx, "198.51.0.10")
	if err != nil || p.AtEdge || len(p.Decisions) != 1 {
		t.Fatalf("propagation: %v %v", p, err)
	}
}
