package csmetrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestScrapeRealMetrics(t *testing.T) {
	raw, err := os.ReadFile("testdata/crowdsec-1.8.1.txt")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(raw) }))
	defer srv.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer down.Close()
	s := New(Config{URLs: []string{srv.URL, srv.URL + "/metrics", down.URL}})
	res, err := s.Get(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partial || len(res.Endpoints) != 3 || res.Endpoints[0].Version != "v1.8.1-909b5157" {
		t.Fatalf("endpoints: %v", res.Endpoints)
	}
	tables := map[string][]string{}
	for _, tb := range res.Tables {
		for _, r := range tb.Rows {
			tables[tb.Name] = append(tables[tb.Name], strings.Join(r.Cells, "|"))
		}
	}
	// Two copies of the same endpoint: values double.
	want := map[string]string{
		"acquisition": "127.0.0.1|http|20|20|0|30",
		"scenarios":   "openpicket/dnat-miss-portscan|",
		"decisions":   "openpicket/dnat-miss-portscan|crowdsec|ban|2",
		"whitelists":  "openpicket/whitelists|OpenPicket: internal or non-routable|",
		"lapi":        "/v1/alerts|GET|",
		"parsers":     "openpicket/nflog|20|20|0",
	}
	for name, prefix := range want {
		found := false
		for _, row := range tables[name] {
			if strings.HasPrefix(row, prefix) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no row %q in %v", name, prefix, tables[name])
		}
	}
	if len(tables["lapi_latency"]) == 0 || len(tables["parsing_time"]) == 0 {
		t.Fatalf("histograms: %v", tables)
	}
	// Cached.
	again, _ := s.Get(context.Background(), "")
	if again != res {
		t.Fatal("not cached")
	}
}
