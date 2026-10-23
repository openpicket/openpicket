package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/openpicket/openpicket/pkg/hubitem"
)

// fakeHub serves an index, item files and a data file over https.
type fakeHub struct {
	srv   *httptest.Server
	files map[string]string // path -> content
	index map[string]map[string]map[string]any
	gets  map[string]int
}

func newFakeHub(t *testing.T) *fakeHub {
	t.Helper()
	f := &fakeHub{files: map[string]string{}, index: map[string]map[string]map[string]any{}, gets: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.gets[r.URL.Path]++
		if r.URL.Path == "/hub/.index.json" {
			if r.Header.Get("If-None-Match") == `"v1"` && f.files["etag"] == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", f.files["etag"])
			_ = json.NewEncoder(w).Encode(f.index)
			return
		}
		b, ok := f.files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(b))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// add publishes an item; members for collections.
func (f *fakeHub) add(typ, name, stage, content string, members map[string][]string) {
	path := typ + "/" + name + ".yaml"
	if stage != "" {
		path = typ + "/" + stage + "/" + name + ".yaml"
	}
	f.files["hub/"+path] = content
	e := map[string]any{"path": path, "version": "0.1", "description": name + " description",
		"versions": map[string]any{"0.1": map[string]string{"digest": digest([]byte(content))}}}
	if stage != "" {
		e["stage"] = stage
	}
	for t, m := range members {
		e[t] = m
	}
	if f.index[typ] == nil {
		f.index[typ] = map[string]map[string]any{}
	}
	f.index[typ][name] = e
}

func (f *fakeHub) hub(s *Store) *Hub {
	u, _ := url.Parse(f.srv.URL)
	return NewHub(s, Source{BaseURL: f.srv.URL + "/hub", DataHosts: []string{u.Host}, Client: f.srv.Client()})
}

func refs(rs []Ref) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Type + " " + r.Name
	}
	slices.Sort(out)
	return out
}

func TestInstallAndRemove(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.SeedBuiltin(ctx); err != nil {
		t.Fatal(err)
	}
	f := newFakeHub(t)
	f.files["etag"] = `"v1"`
	f.files["data/bad_ua.txt"] = "curl\n"
	f.add("parsers", "a/logs", "s01-parse", "name: a/logs\nfilter: evt.Parsed.program == 'a'\nstatics:\n  - meta: log_type\n    value: a_log\n", nil)
	f.add("scenarios", "a/scan", "", "type: leaky\nname: a/scan\nfilter: evt.Meta.log_type == 'a_log'\ndata:\n  - source_url: "+f.srv.URL+"/data/bad_ua.txt\n    dest_file: bad_ua.txt\n---\ntype: leaky\nname: a/scan-slow\nfilter: evt.Meta.log_type == 'a_log'\n", nil)
	f.add("scenarios", "b/http", "", "name: b/http\nfilter: evt.Meta.log_type == 'http_access-log'\n", nil)
	f.add("collections", "b/inner", "", "name: b/inner\nscenarios: [b/http]\n", map[string][]string{"scenarios": {"b/http"}})
	// The collection also lists a built-in item: kept as it is.
	f.add("parsers", "crowdsecurity/whitelists", "s02-enrich", "name: crowdsecurity/whitelists\n# hub version\n", nil)
	f.add("collections", "a/col", "", "name: a/col\n", map[string][]string{"parsers": {"a/logs", "crowdsecurity/whitelists"}, "scenarios": {"a/scan"}, "collections": {"b/inner"}})
	h := f.hub(s)
	if _, err := h.Install(ctx, Ref{hubitem.Collections, "a/col"}, "admin"); err == nil {
		t.Fatal("installed without an index")
	}
	if changed, err := h.RefreshIndex(ctx); err != nil || !changed {
		t.Fatalf("refresh: %v %v", changed, err)
	}
	if changed, _ := h.RefreshIndex(ctx); changed {
		t.Fatal("unchanged index (ETag) stored again")
	}
	got, err := h.Install(ctx, Ref{hubitem.Collections, "a/col"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"collections a/col", "collections b/inner", "parsers a/logs", "scenarios a/scan", "scenarios b/http"}; !slices.Equal(refs(got), want) {
		t.Fatalf("installed %v", refs(got))
	}
	items, _ := s.Items(ctx, "")
	byName := map[string]Item{}
	for _, it := range items {
		byName[it.Type+" "+it.Name] = it
	}
	if it := byName["scenarios a/scan"]; it.Source != hubitem.SourceHub || it.State != hubitem.Simulation || it.Explicit || !slices.Equal(it.Data, []string{"bad_ua.txt"}) {
		t.Fatalf("scenario: %+v", it)
	}
	if it := byName["parsers a/logs"]; it.State != hubitem.Enabled || it.Stage != "s01-parse" {
		t.Fatalf("parser: %+v", it)
	}
	if it := byName["parsers crowdsecurity/whitelists"]; it.Source != hubitem.SourceBuiltin {
		t.Fatalf("built-in item replaced: %+v", it)
	}
	b, err := s.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Both buckets of the scenario file are in simulation.
	if !slices.Contains(b.Simulation, "a/scan") || !slices.Contains(b.Simulation, "a/scan-slow") || len(b.Data) != 1 || string(b.Data[0].Content) != "curl\n" {
		t.Fatalf("bundle simulation=%v data=%v", b.Simulation, b.Data)
	}
	// The installed parser makes the scenario work; nothing sets http logs.
	compat, err := s.Compatibilities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if compat["a/scan"].Status != hubitem.CompatOK || compat["b/http"].Status != hubitem.CompatMissing ||
		compat["openpicket/suricata-inbound-major"].Status != hubitem.CompatOK {
		t.Fatalf("compat = %+v", compat)
	}

	// A member on its own stays when its collection goes; the rest go.
	if _, err := h.Install(ctx, Ref{hubitem.Scenarios, "a/scan"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, Ref{hubitem.Collections, "a/col"}, "admin"); err != nil {
		t.Fatal(err)
	}
	items, _ = s.Items(ctx, "")
	left := map[string]bool{}
	for _, it := range items {
		if it.Source == hubitem.SourceHub {
			left[it.Type+" "+it.Name] = true
		}
	}
	if !left["scenarios a/scan"] || len(left) != 1 {
		t.Fatalf("after removing the collection: %v", left)
	}
	if err := s.Remove(ctx, Ref{hubitem.Scenarios, "a/scan"}, "admin"); err != nil {
		t.Fatal(err)
	}
	var data int
	_ = s.db.QueryRow(ctx, `SELECT count(*) FROM openpicket.hub_data`).Scan(&data)
	if data != 0 {
		t.Fatal("data file of a removed item kept")
	}
	if err := s.Remove(ctx, Ref{hubitem.Scenarios, "openpicket/compromised-host"}, "admin"); err == nil {
		t.Fatal("removed a built-in item")
	}

	// The file changed after the index: refused.
	f.files["hub/scenarios/b/http.yaml"] = "name: b/http\n# changed\n"
	if _, err := h.Install(ctx, Ref{hubitem.Scenarios, "b/http"}, "admin"); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("digest mismatch: %v", err)
	}
	// Data only from the allowed hosts.
	f.add("scenarios", "c/evil", "", "name: c/evil\ndata:\n  - source_url: https://evil.example/x\n    dest_file: x.txt\n", nil)
	f.files["etag"] = `"v2"`
	if _, err := h.RefreshIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Install(ctx, Ref{hubitem.Scenarios, "c/evil"}, "admin"); err == nil || !strings.Contains(err.Error(), "allowed data host") {
		t.Fatalf("data host: %v", err)
	}
}
