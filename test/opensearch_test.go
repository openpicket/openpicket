package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/manager/registry"
	"github.com/openpicket/openpicket/manager/sinks/opensearch"
	"github.com/openpicket/openpicket/pkg/record"
)

func osGet(t *testing.T, base, path string, out any) {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("%s: %d %s", path, resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

// TestOpenSearchSink runs against a real OpenSearch (scripts/opensearch-test.sh).
func TestOpenSearchSink(t *testing.T) {
	base := os.Getenv("OPENPICKET_TEST_OPENSEARCH_URL")
	if base == "" {
		t.Skip("OPENPICKET_TEST_OPENSEARCH_URL not set (scripts/opensearch-test.sh)")
	}
	ctx := context.Background()
	c, err := opensearch.New(opensearch.Config{URL: base, Replicas: 0, Retention: 14 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := c.Setup(ctx); err != nil {
			t.Fatalf("setup %d: %v", i, err)
		}
	}
	now := time.Now().UTC()
	var records []*pipeline.Record
	for i := 0; i < 50; i++ {
		et := []string{"alert", "flow", "dns"}[i%3]
		line := fmt.Sprintf(`{"timestamp":%q,"event_type":%q,"src_ip":"198.51.100.%d","dest_ip":"192.168.1.10","dest_port":443}`, now.Format(time.RFC3339Nano), et, i)
		ev, _ := record.ParseEve([]byte(line))
		records = append(records, &pipeline.Record{Line: []byte(line), RID: fmt.Sprintf("rid-%d", i), Time: now, Eve: ev, EventType: et,
			SrcGeo: &pipeline.Geo{Country: "CN", ASN: 4134}})
	}
	// A retransmission (a new batch with the same records) must not
	// duplicate.
	for i := 0; i < 2; i++ {
		b := &pipeline.Batch{NodeID: "edge-01", BootID: "b1", Type: record.TypeEve, Received: now,
			Node: &registry.Node{ID: "edge-01", Labels: map[string]string{"site": "seoul"}}, Records: records}
		if err := c.Deliver(ctx, b); err != nil {
			t.Fatalf("deliver %d: %v", i, err)
		}
	}
	text := &pipeline.Batch{NodeID: "edge-01", BootID: "b1", Type: record.TypeSuricata, Received: now,
		Records: []*pipeline.Record{{Line: []byte("<Notice> engine started"), RID: "txt-1", Time: now}}}
	if err := c.Deliver(ctx, text); err != nil {
		t.Fatal(err)
	}

	// Alerts of the PostgreSQL copy.
	pool := pgtest.Pool(t)
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if _, err := pool.Exec(ctx, `INSERT INTO openpicket.alerts (instance, id, scenario, source_scope, source_value, created_at)
			VALUES ('default', $1, 'crowdsecurity/ssh-bf', 'Ip', '198.51.100.1', now())`, i); err != nil {
			t.Fatal(err)
		}
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	c.RunLeader(lctx, pool, slog.New(slog.DiscardHandler), time.Hour)
	cancel()

	var refresh any
	resp, _ := http.Post(base+"/openpicket-*/_refresh", "application/json", nil)
	_ = resp.Body.Close()
	_ = refresh
	counts := map[string]int{}
	for _, ds := range []string{"openpicket-eve-alert", "openpicket-eve-flow", "openpicket-eve-dns", "openpicket-suricata", "openpicket-crowdsec-alerts"} {
		var res struct {
			Count int `json:"count"`
		}
		osGet(t, base, "/"+ds+"/_count", &res)
		counts[ds] = res.Count
	}
	want := map[string]int{"openpicket-eve-alert": 17, "openpicket-eve-flow": 17, "openpicket-eve-dns": 16, "openpicket-suricata": 1, "openpicket-crowdsec-alerts": 3}
	for k, v := range want {
		if counts[k] != v {
			t.Fatalf("counts %v, want %v", counts, want)
		}
	}
	var hits struct {
		Hits struct {
			Hits []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	osGet(t, base, "/openpicket-eve-alert/_search?q=src_ip:%22198.51.100.0%2F24%22&size=1", &hits)
	if len(hits.Hits.Hits) != 1 {
		t.Fatalf("ip query: %+v", hits)
	}
	src := hits.Hits.Hits[0].Source
	meta, _ := src["openpicket_meta"].(map[string]any)
	if meta["site"] != "seoul" || src["@timestamp"] == nil || !strings.Contains(fmt.Sprint(meta["src_geo"]), "CN") {
		t.Fatalf("document: %v", src)
	}
	var ism map[string]any
	osGet(t, base, "/_plugins/_ism/policies/openpicket-retention", &ism)
	if !strings.Contains(fmt.Sprint(ism), "14d") {
		t.Fatalf("ism: %v", ism)
	}
}
