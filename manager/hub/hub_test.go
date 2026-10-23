package hub

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	builtin "github.com/openpicket/openpicket/hub"
	"github.com/openpicket/openpicket/internal/crowdsecsync"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/pkg/hubitem"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	pool := pgtest.Pool(t)
	if err := schema.Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	return NewStore(pool, nil)
}

func TestSeedBuiltin(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.SeedBuiltin(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := s.Items(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := builtin.Builtin()
	if len(items) != len(want) {
		t.Fatalf("%d items, want %d", len(items), len(want))
	}
	m, _, _ := s.Status(ctx)
	if m.Revision == 0 {
		t.Fatal("no revision")
	}
	// A second start changes nothing.
	if err := s.SeedBuiltin(ctx); err != nil {
		t.Fatal(err)
	}
	if m2, _, _ := s.Status(ctx); m2.Revision != m.Revision {
		t.Fatalf("revision %d -> %d without a change", m.Revision, m2.Revision)
	}
	// The user's state survives a content change of a built-in item.
	ref := Ref{hubitem.Scenarios, "openpicket/wan-reject-portscan"}
	if err := s.SetState(ctx, ref, hubitem.Disabled, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `UPDATE openpicket.hub_items SET content = 'old', digest = 'old' WHERE name = $1`, ref.Name); err != nil {
		t.Fatal(err)
	}
	// A stale built-in item (dropped in this release) goes away.
	if _, err := s.db.Exec(ctx, `INSERT INTO openpicket.hub_items (type, name, source, content, digest) VALUES ('scenarios', 'openpicket/gone', 'builtin', 'x', 'x')`); err != nil {
		t.Fatal(err)
	}
	if err := s.SeedBuiltin(ctx); err != nil {
		t.Fatal(err)
	}
	items, _ = s.Items(ctx, hubitem.Scenarios)
	for _, it := range items {
		if it.Name == "openpicket/gone" {
			t.Fatal("stale built-in item kept")
		}
		if it.Ref == ref && (it.State != hubitem.Disabled || it.Digest == "old") {
			t.Fatalf("after reseed: %+v", it)
		}
	}
	// A newer manager's content is left alone.
	if _, err := s.db.Exec(ctx, `UPDATE openpicket.hub_meta SET builtin_revision = $1`, builtin.BuiltinRevision+1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(ctx, `UPDATE openpicket.hub_items SET digest = 'newer' WHERE name = $1`, ref.Name); err != nil {
		t.Fatal(err)
	}
	_ = s.SeedBuiltin(ctx)
	var d string
	_ = s.db.QueryRow(ctx, `SELECT digest FROM openpicket.hub_items WHERE name = $1`, ref.Name).Scan(&d)
	if d != "newer" {
		t.Fatal("an older manager rewrote newer built-in content")
	}
}

func TestBundleAndStates(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.SeedBuiltin(ctx); err != nil {
		t.Fatal(err)
	}
	// A hub collection with a scenario that reads a data file.
	for _, q := range []string{
		`INSERT INTO openpicket.hub_items (type, name, source, members) VALUES ('collections', 'a/col', 'hub', '[{"type":"scenarios","name":"a/scan"},{"type":"parsers","name":"a/logs"}]')`,
		`INSERT INTO openpicket.hub_items (type, name, source, content, digest, data, explicit) VALUES ('scenarios', 'a/scan', 'hub', 'name: a/scan', 'd', '["a/list.txt"]', false)`,
		`INSERT INTO openpicket.hub_items (type, name, source, stage, content, digest, explicit) VALUES ('parsers', 'a/logs', 'hub', 's01-parse', 'name: a/logs', 'd', false)`,
		`INSERT INTO openpicket.hub_data (dest_file, content, digest) VALUES ('a/list.txt', '1', 'd')`,
	} {
		if _, err := s.db.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetState(ctx, Ref{hubitem.Collections, "a/col"}, hubitem.Simulation, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, Ref{hubitem.Parsers, "openpicket/nflog"}, hubitem.Simulation, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("simulation of a parser: %v", err)
	}
	if err := s.SetState(ctx, Ref{hubitem.Scenarios, "openpicket/compromised-host"}, hubitem.Disabled, "admin"); err != nil {
		t.Fatal(err)
	}
	b, err := s.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, f := range b.Items {
		paths[f.Path] = true
	}
	if !paths["scenarios/a-scan.yaml"] || !paths["parsers/s01-parse/a-logs.yaml"] || !paths["parsers/s00-raw/crowdsecurity-syslog-logs.yaml"] ||
		paths["scenarios/openpicket-compromised-host.yaml"] {
		t.Fatalf("items = %v", paths)
	}
	if !slices.Equal(b.Simulation, []string{"a/scan"}) || len(b.Data) != 1 || b.Data[0].Path != "a/list.txt" {
		t.Fatalf("simulation=%v data=%v", b.Simulation, b.Data)
	}
	items, _ := s.Items(ctx, hubitem.Parsers)
	for _, it := range items {
		if it.Name == "a/logs" && (it.State != hubitem.Enabled || !slices.Equal(it.MemberOf, []string{"a/col"})) {
			t.Fatalf("collection member: %+v", it)
		}
	}
}

// fakeEngine plays CrowdSec on a log processor.
type fakeEngine struct {
	running bool
	refuse  string // refuse configurations containing this
}

func (f *fakeEngine) Test(_ context.Context, cfg string) (string, error) {
	if f.refuse == "" {
		return "", nil
	}
	found := false
	_ = filepath.WalkDir(filepath.Join(filepath.Dir(cfg), "scenarios"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			found = found || strings.Contains(string(b), f.refuse)
		}
		return nil
	})
	if found {
		return "fatal: invalid filter", errors.New("exit status 1")
	}
	return "", nil
}
func (f *fakeEngine) Start(context.Context) error  { f.running = true; return nil }
func (f *fakeEngine) Reload(context.Context) error { return nil }
func (f *fakeEngine) Running() bool                { return f.running }

type lp struct {
	srv *httptest.Server
	sy  *crowdsecsync.Syncer
	eng *fakeEngine
}

func newLP(t *testing.T) *lp {
	t.Helper()
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "etc", "config.yaml"), []byte("config_paths: {}\n"), 0o644)
	eng := &fakeEngine{}
	sy := crowdsecsync.New(crowdsecsync.Config{ConfigFile: filepath.Join(dir, "etc", "config.yaml"), DataDir: filepath.Join(dir, "data"), Engine: eng, WorkDir: t.TempDir()})
	srv := httptest.NewServer(crowdsecsync.Handler(sy, "X-OpenPicket-Token", "tok"))
	t.Cleanup(srv.Close)
	return &lp{srv: srv, sy: sy, eng: eng}
}

func TestRollout(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.SeedBuiltin(ctx); err != nil {
		t.Fatal(err)
	}
	lps := []*lp{newLP(t), newLP(t)}
	r := &Rollout{Store: s, Header: "X-OpenPicket-Token", Token: "tok",
		Targets: func() []string { return []string{lps[0].srv.URL, lps[1].srv.URL, "http://127.0.0.1:1"} }}
	r.Init()
	if err := r.pass(ctx, nil); err != nil {
		t.Fatal(err)
	}
	m, states, _ := s.Status(ctx)
	for _, l := range lps {
		if st := l.sy.Status(); st.Revision != m.Revision || !st.Running {
			t.Fatalf("log processor: %+v, revision %d", st, m.Revision)
		}
	}
	unreachable := slices.IndexFunc(states, func(l LPState) bool { return l.Endpoint == "http://127.0.0.1:1" })
	if m.GoodRevision != m.Revision || len(states) != 3 || unreachable < 0 || !strings.Contains(states[unreachable].Error, "unreachable") {
		t.Fatalf("meta=%+v states=%+v", m, states)
	}
	good := m.Revision

	// A revision CrowdSec refuses stops at the first log processor; a new
	// log processor gets the last good one.
	for _, l := range lps {
		l.eng.refuse = "BROKEN"
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO openpicket.hub_items (type, name, source, content, digest) VALUES ('scenarios', 'u/bad', 'custom', 'name: u/bad # BROKEN', 'x')`); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, Ref{hubitem.Scenarios, "u/bad"}, hubitem.Enabled, "admin"); err != nil {
		t.Fatal(err)
	}
	fresh := newLP(t)
	lps = append(lps, fresh)
	r.Targets = func() []string { return []string{lps[0].srv.URL, lps[1].srv.URL, fresh.srv.URL} }
	if err := r.pass(ctx, nil); err != nil {
		t.Fatal(err)
	}
	m, _, _ = s.Status(ctx)
	if m.FailedRevision != m.Revision || !strings.Contains(m.FailedError, "invalid filter") || m.GoodRevision != good {
		t.Fatalf("meta = %+v", m)
	}
	for i, l := range lps {
		if st := l.sy.Status(); st.Revision != good || !st.Running {
			t.Fatalf("log processor %d: %+v (good %d)", i, st, good)
		}
	}
	// Fixed: the next revision goes everywhere.
	if err := s.SetState(ctx, Ref{hubitem.Scenarios, "u/bad"}, hubitem.Disabled, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := r.pass(ctx, nil); err != nil {
		t.Fatal(err)
	}
	m, _, _ = s.Status(ctx)
	for i, l := range lps {
		if st := l.sy.Status(); st.Revision != m.Revision {
			t.Fatalf("log processor %d: %+v (revision %d)", i, st, m.Revision)
		}
	}
}
