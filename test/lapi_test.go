package test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager/alerts"
	"github.com/openpicket/openpicket/manager/lapi"
)

type txFence struct{ db *pgxpool.Pool }

func (f txFence) Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, f.db, fn)
}

// TestLAPIWatcher runs against a real CrowdSec LAPI (scripts/lapi-test.sh).
func TestLAPIWatcher(t *testing.T) {
	base := os.Getenv("OPENPICKET_TEST_LAPI_URL")
	if base == "" {
		t.Skip("OPENPICKET_TEST_LAPI_URL not set (scripts/lapi-test.sh)")
	}
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	c, err := lapi.New(lapi.Config{URL: base, Login: os.Getenv("OPENPICKET_TEST_LAPI_LOGIN"), Password: os.Getenv("OPENPICKET_TEST_LAPI_PASSWORD"),
		BouncerKey: os.Getenv("OPENPICKET_TEST_LAPI_BOUNCER_KEY")})
	if err != nil {
		t.Fatal(err)
	}
	w, err := c.Watcher()
	if err != nil {
		t.Fatal(err)
	}
	syncer := alerts.NewSyncer(alerts.Config{DB: pool, Instances: []alerts.Instance{{Name: "default", URL: base, Watcher: w}}, Logger: slog.New(slog.DiscardHandler)})
	q := &alerts.Querier{DB: pool}

	// A manual decision as the UI creates it.
	ids, err := w.PushAlerts(ctx, []*lapi.Alert{lapi.ManualDecision("Ip", "198.51.100.200", "ban", "720h", "openpicket/manual-both", "phishing", "olga", time.Now())})
	if err != nil || len(ids) != 1 {
		t.Fatalf("push: %v %v", ids, err)
	}
	// Records the manager would send: a port scan from 198.51.100.77.
	var body bytes.Buffer
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	for i, p := range []int{21, 22, 23, 25, 80, 110, 135, 139, 445, 3389} {
		fmt.Fprintf(&body, `{"timestamp":%q,"event_type":"nflog","prefix":"DNAT-MISS","group":100,"in_iface":"wan","ip_version":4,"proto":"TCP",`+
			`"src_ip":"198.51.100.77","src_port":40000,"dest_ip":"203.0.113.10","dest_port":%d,"tcp_flags":"S","ttl":50,"pkt_len":60,`+
			`"openpicket":{"rid":"n%d","direction":"inbound","direction_confidence":"high","remote_ip":"198.51.100.77","local_ip":"203.0.113.10"},`+
			`"openpicket_meta":{"ts":%q,"node_id":"edge-02","site":"seoul","remote_geo":{"cc":"US","asn":64500,"as_org":"TEST-AS"}}}`+"\n", now, p, i, now)
	}
	req, _ := http.NewRequest("POST", os.Getenv("OPENPICKET_TEST_ACQUIS_URL"), &body)
	req.Header.Set("X-OpenPicket-Token", os.Getenv("OPENPICKET_TEST_ACQUIS_TOKEN"))
	req.Header.Set("Content-Type", "application/x-ndjson")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode >= 300 {
		t.Fatalf("acquis: %d", res.StatusCode)
	}

	// The first pass is a full one, then incremental passes.
	var scan []string
	for i := 0; ; i++ {
		if err := syncer.SyncOnce(ctx, txFence{pool}, true, i == 0); err != nil {
			t.Fatal(err)
		}
		list, _, err := q.Search(ctx, alerts.Filter{Query: "scenario:dnat-miss-portscan"}, 10, 0, "", false)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) > 0 {
			a := list[0]
			if a.NodeId != "edge-02" || a.Direction != "inbound" || a.Source.Value != "198.51.100.77" || a.Source.Country != "US" || len(a.Decisions) == 0 {
				t.Fatalf("scan alert: %v", a)
			}
			for _, m := range a.Meta {
				scan = append(scan, m.Key)
			}
			break
		}
		if i > 40 {
			t.Fatal("port scan alert not synced")
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !slices.Contains(scan, "dst_ip") || !slices.Contains(scan, "nflog_prefix") {
		t.Fatalf("alert context keys: %v", scan)
	}
	decs, _, err := q.Decisions(ctx, alerts.DecisionFilter{Query: "value=198.51.100.200"}, 10, 0)
	if err != nil || len(decs) != 1 || decs[0].Origin != "cscli" || decs[0].Scenario != "openpicket/manual-both" ||
		time.Until(decs[0].Until.AsTime()) < 29*24*time.Hour {
		t.Fatalf("manual decision: %v %v", decs, err)
	}
	// MISP decisions (origin "misp", both-way scenario) are accepted.
	if _, err := w.PushAlerts(ctx, []*lapi.Alert{lapi.DecisionAlert("Ip", "198.51.100.201", "ban", "12h0m0s", "openpicket/misp-ip-dst", "misp", "MISP test", time.Now())}); err != nil {
		t.Fatalf("misp decision: %v", err)
	}
	// The bouncer stream (relay) sees the bans.
	st, err := c.Stream(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	var values []string
	for _, d := range st.New {
		values = append(values, d.Value)
		if d.Value == "198.51.100.201" && (d.Origin != "misp" || d.Scenario != "openpicket/misp-ip-dst") {
			t.Fatalf("misp decision in stream: %+v", d)
		}
	}
	if !slices.Contains(values, "198.51.100.200") || !slices.Contains(values, "198.51.100.77") || !slices.Contains(values, "198.51.100.201") {
		t.Fatalf("stream: %v", values)
	}

	// Deletes.
	n, err := w.DeleteDecision(ctx, decs[0].Id)
	if err != nil || n != 1 {
		t.Fatalf("delete decision: %d %v", n, err)
	}
	n, err = w.DeleteDecisions(ctx, url.Values{"ip": {"198.51.100.77"}})
	if err != nil || n < 1 {
		t.Fatalf("delete decisions by ip: %d %v", n, err)
	}
	if n, err := w.DeleteDecisions(ctx, url.Values{"ip": {"198.51.100.201"}}); err != nil || n != 1 {
		t.Fatalf("delete misp decision: %d %v", n, err)
	}
	if err := syncer.SyncOnce(ctx, txFence{pool}, true, false); err != nil {
		t.Fatal(err)
	}
	if active, _, _ := q.Decisions(ctx, alerts.DecisionFilter{}, 10, 0); len(active) != 0 {
		t.Fatalf("decisions left: %v", active)
	}
	n, err = w.DeleteAlerts(ctx, url.Values{"ip": {"198.51.100.77"}})
	if err != nil || n < 1 {
		t.Fatalf("delete alerts by ip: %d %v", n, err)
	}
	all, err := w.Alerts(ctx, url.Values{"limit": {"0"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range all {
		if a.Source != nil && a.Source.Value != nil && *a.Source.Value == "198.51.100.77" {
			t.Fatal("alert of 198.51.100.77 still listed")
		}
	}
	id := all[0].ID
	if err := w.DeleteAlert(ctx, id); err != nil {
		t.Fatalf("delete alert %d: %v", id, err)
	}
	if _, err := w.Alert(ctx, id); err != lapi.ErrNotFound {
		t.Fatalf("deleted alert: %v", err)
	}
	if err := syncer.SyncOnce(ctx, txFence{pool}, true, true); err != nil {
		t.Fatal(err)
	}
	if left, total, _ := q.Search(ctx, alerts.Filter{IncludeSimulated: true}, 10, 0, "", false); total != int64(len(all)-1) {
		t.Fatalf("copy after full pass: %d (%v), LAPI had %d", total, left, len(all)-1)
	}
}
