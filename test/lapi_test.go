package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
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
	"github.com/openpicket/openpicket/manager/allowlist"
	"github.com/openpicket/openpicket/manager/lapi"
	"github.com/openpicket/openpicket/pkg/allowsync"
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
		fmt.Fprintf(&body, `{"timestamp":%q,"event_type":"nflog","prefix":"WAN-REJECT","group":100,"in_iface":"wan","ip_version":4,"proto":"TCP",`+
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
		list, _, err := q.Search(ctx, alerts.Filter{Query: "scenario:wan-reject-portscan"}, 10, 0, "", false)
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

// lapiAllowlist reads the openpicket allowlist through the LAPI API, as a
// watcher.
func lapiAllowlist(t *testing.T, base string) map[string]allowsync.Item {
	t.Helper()
	ctx := context.Background()
	body, _ := json.Marshal(map[string]string{"machine_id": os.Getenv("OPENPICKET_TEST_LAPI_LOGIN"), "password": os.Getenv("OPENPICKET_TEST_LAPI_PASSWORD")})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/watchers/login", bytes.NewReader(body))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var login struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&login)
	res.Body.Close()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/allowlists/"+allowsync.Name+"?with_content=true", nil)
	req.Header.Set("Authorization", "Bearer "+login.Token)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var list struct {
		Items []struct {
			Value       string    `json:"value"`
			Description string    `json:"description"`
			Expiration  time.Time `json:"expiration"`
		} `json:"items"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&list) != nil {
		t.Fatalf("read the allowlist: %d", res.StatusCode)
	}
	out := map[string]allowsync.Item{}
	for _, it := range list.Items {
		item := allowsync.Item{Value: it.Value, Description: it.Description}
		if it.Expiration.Year() > 1 {
			exp := it.Expiration
			item.ExpiresAt = &exp
		}
		out[it.Value] = item
	}
	return out
}

// TestLAPIAllowlist pushes the central allowlist to a real LAPI through
// openpicket-crowdsec-sync (scripts/lapi-test.sh).
func TestLAPIAllowlist(t *testing.T) {
	base, syncURL := os.Getenv("OPENPICKET_TEST_LAPI_URL"), os.Getenv("OPENPICKET_TEST_SYNC_URL")
	if base == "" || syncURL == "" {
		t.Skip("OPENPICKET_TEST_LAPI_URL / OPENPICKET_TEST_SYNC_URL not set (scripts/lapi-test.sh)")
	}
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	c, err := lapi.New(lapi.Config{URL: base, Login: os.Getenv("OPENPICKET_TEST_LAPI_LOGIN"), Password: os.Getenv("OPENPICKET_TEST_LAPI_PASSWORD")})
	if err != nil {
		t.Fatal(err)
	}
	w, err := c.Watcher()
	if err != nil {
		t.Fatal(err)
	}
	active := func(ip string) int {
		t.Helper()
		alerts, err := w.Alerts(ctx, url.Values{"ip": {ip}, "has_active_decision": {"true"}})
		if err != nil {
			t.Fatal(err)
		}
		return len(alerts)
	}
	// A manual ban the allowlist will cover.
	if _, err := w.PushAlerts(ctx, []*lapi.Alert{lapi.ManualDecision("Ip", "192.0.2.50", "ban", "4h", "openpicket/manual", "test", "olga", time.Now())}); err != nil {
		t.Fatal(err)
	}
	if active("192.0.2.50") != 1 {
		t.Fatal("manual decision not active")
	}

	store := allowlist.New(pool, nil)
	exp := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	if err := store.Put(ctx, allowlist.Entry{Network: netip.MustParsePrefix("192.0.2.0/24"), Description: "office"}, false, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, allowlist.Entry{Network: netip.MustParsePrefix("198.51.100.210/32"), ExpiresAt: exp}, false, "alice"); err != nil {
		t.Fatal(err)
	}
	ls := &allowlist.LAPISync{Store: store, Targets: []allowlist.Target{{Instance: "default", URL: syncURL}},
		Header: "X-OpenPicket-Token", Token: os.Getenv("OPENPICKET_TEST_ACQUIS_TOKEN")}
	ls.Init()
	pass := func() allowlist.SyncStatus {
		t.Helper()
		if err := ls.Pass(ctx, nil); err != nil {
			t.Fatal(err)
		}
		st, err := store.SyncStatuses(ctx)
		if err != nil || st["default"].Error != "" {
			t.Fatalf("sync status: %+v %v", st, err)
		}
		return st["default"]
	}
	first := pass()
	got := lapiAllowlist(t, base)
	if len(got) != 2 || got["192.0.2.0/24"].Description != "office" || got["192.0.2.0/24"].ExpiresAt != nil {
		t.Fatalf("LAPI allowlist = %+v", got)
	}
	if e := got["198.51.100.210"].ExpiresAt; e == nil || e.Sub(exp).Abs() > allowsync.Tolerance {
		t.Fatalf("expiry = %v, want %v", e, exp)
	}
	// cscli applies the allowlist to existing decisions.
	if n := active("192.0.2.50"); n != 0 {
		t.Fatalf("covered decision still active (%d)", n)
	}

	// In sync: nothing changes.
	time.Sleep(10 * time.Millisecond)
	if again := pass(); !again.ChangedAt.Equal(first.ChangedAt) || again.Items != 2 {
		t.Fatalf("second push changed the allowlist: %+v", again)
	}

	// A new description, then a removed entry.
	if err := store.Put(ctx, allowlist.Entry{Network: netip.MustParsePrefix("192.0.2.0/24"), Description: "office LAN"}, false, "bob"); err != nil {
		t.Fatal(err)
	}
	pass()
	if got := lapiAllowlist(t, base); got["192.0.2.0/24"].Description != "office LAN" {
		t.Fatalf("description not updated: %+v", got)
	}
	if err := store.Delete(ctx, netip.MustParsePrefix("192.0.2.0/24")); err != nil {
		t.Fatal(err)
	}
	if st := pass(); st.Items != 1 {
		t.Fatalf("after delete: %+v", st)
	}
	if got := lapiAllowlist(t, base); len(got) != 1 {
		t.Fatalf("after delete: %+v", got)
	}
}
