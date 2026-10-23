package crowdsecsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openpicket/openpicket/pkg/hubitem"
)

type fakeEngine struct {
	running bool
	starts  int
	reloads int
	testErr string
	tested  []byte // the staged config tested
	stage   string
}

func (f *fakeEngine) Test(_ context.Context, cfg string) (string, error) {
	f.tested, _ = os.ReadFile(cfg)
	f.stage = filepath.Dir(cfg)
	if f.testErr != "" {
		return "level=fatal msg=\"" + f.testErr + " in " + f.stage + "/scenarios/x.yaml\"", errors.New("exit status 1")
	}
	return "", nil
}
func (f *fakeEngine) Start(context.Context) error  { f.running = true; f.starts++; return nil }
func (f *fakeEngine) Reload(context.Context) error { f.reloads++; return nil }
func (f *fakeEngine) Running() bool                { return f.running }

func setup(t *testing.T) (*Syncer, *fakeEngine, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg, data := filepath.Join(dir, "etc"), filepath.Join(dir, "data")
	for _, d := range []string{cfg, data, filepath.Join(cfg, "patterns"), filepath.Join(cfg, "scenarios")} {
		_ = os.MkdirAll(d, 0o755)
	}
	_ = os.WriteFile(filepath.Join(cfg, "config.yaml"), []byte("config_paths:\n  config_dir: /etc/crowdsec\n  data_dir: /var/lib/crowdsec/data\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cfg, "patterns", "p"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(cfg, "scenarios", "stale.yaml"), []byte("x"), 0o644)
	eng := &fakeEngine{}
	s := New(Config{ConfigFile: filepath.Join(cfg, "config.yaml"), DataDir: data, Engine: eng, WorkDir: t.TempDir()})
	return s, eng, cfg, data
}

func bundle(rev int64) *hubitem.Bundle {
	return &hubitem.Bundle{Revision: rev,
		Items: []hubitem.File{
			{Path: "parsers/s01-parse/a-p.yaml", Content: []byte("name: a/p\n")},
			{Path: "scenarios/a-b.yaml", Content: []byte("name: a/b\n")},
		},
		Data:       []hubitem.File{{Path: "x/list.txt", Content: []byte("1\n")}},
		Simulation: []string{"a/b"},
	}
}

func TestApplyStartsThenReloads(t *testing.T) {
	s, eng, cfg, data := setup(t)
	ctx := context.Background()
	if err := s.Apply(ctx, bundle(1)); err != nil {
		t.Fatal(err)
	}
	if eng.starts != 1 || eng.reloads != 0 || s.Status().Revision != 1 || !s.Status().Running {
		t.Fatalf("starts=%d reloads=%d status=%+v", eng.starts, eng.reloads, s.Status())
	}
	// The staged configuration pointed at the staged directories.
	if !bytes.Contains(eng.tested, []byte(eng.stage)) || bytes.Contains(eng.tested, []byte("config_dir: /etc/crowdsec")) {
		t.Fatalf("staged config:\n%s", eng.tested)
	}
	for p, want := range map[string]string{
		filepath.Join(cfg, "scenarios", "a-b.yaml"):            "name: a/b\n",
		filepath.Join(cfg, "parsers", "s01-parse", "a-p.yaml"): "name: a/p\n",
		filepath.Join(data, "x", "list.txt"):                   "1\n",
		filepath.Join(cfg, "patterns", "p"):                    "x",
	} {
		if b, err := os.ReadFile(p); err != nil || string(b) != want {
			t.Fatalf("%s = %q %v", p, b, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg, "scenarios", "stale.yaml")); !os.IsNotExist(err) {
		t.Fatal("a file the bundle does not have was kept")
	}
	if b, _ := os.ReadFile(filepath.Join(cfg, "simulation.yaml")); !strings.Contains(string(b), "simulation: off") || !strings.Contains(string(b), "- a/b") {
		t.Fatalf("simulation.yaml:\n%s", b)
	}
	// Same revision: nothing to do. Next one: reload, old data removed.
	_ = s.Apply(ctx, bundle(1))
	b2 := bundle(2)
	b2.Data, b2.Simulation = nil, nil
	if err := s.Apply(ctx, b2); err != nil || eng.reloads != 1 || eng.starts != 1 {
		t.Fatalf("second: %v reloads=%d", err, eng.reloads)
	}
	if _, err := os.Stat(filepath.Join(data, "x", "list.txt")); !os.IsNotExist(err) {
		t.Fatal("data file of an earlier bundle kept")
	}
}

func TestRefusedBundleKeepsContent(t *testing.T) {
	s, eng, cfg, _ := setup(t)
	ctx := context.Background()
	_ = s.Apply(ctx, bundle(1))
	eng.testErr = "invalid filter"
	b := bundle(2)
	b.Items[1].Content = []byte("name: a/b\nfilter: broken\n")
	err := s.Apply(ctx, b)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v", err)
	}
	st := s.Status()
	if st.Revision != 1 || st.ErrorRevision != 2 || !strings.Contains(st.Error, "invalid filter") || strings.Contains(st.Error, eng.stage) {
		t.Fatalf("status = %+v", st)
	}
	if got, _ := os.ReadFile(filepath.Join(cfg, "scenarios", "a-b.yaml")); string(got) != "name: a/b\n" || eng.reloads != 0 {
		t.Fatal("refused bundle changed the content")
	}
	// Unsafe paths never reach the disk.
	bad := bundle(3)
	bad.Items[0].Path = "../../etc/passwd.yaml"
	if err := s.Apply(ctx, bad); !errors.Is(err, ErrRefused) {
		t.Fatalf("unsafe path: %v", err)
	}
	bad = bundle(3)
	bad.Data[0].Path = "../x"
	if err := s.Apply(ctx, bad); !errors.Is(err, ErrRefused) {
		t.Fatalf("unsafe data path: %v", err)
	}
}

func TestHandlerAuth(t *testing.T) {
	s, _, _, _ := setup(t)
	h := Handler(s, "X-OpenPicket-Token", "secret")
	body, _ := json.Marshal(bundle(1))
	for _, c := range []struct {
		token string
		code  int
	}{{"", http.StatusUnauthorized}, {"wrong", http.StatusUnauthorized}, {"secret", http.StatusOK}} {
		req := httptest.NewRequest("PUT", hubitem.PathBundle, bytes.NewReader(body))
		req.Header.Set("X-OpenPicket-Token", c.token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.code {
			t.Fatalf("token %q: %d %s", c.token, rec.Code, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz %d", rec.Code)
	}
}
