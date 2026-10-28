package k8slogs

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openpicket/openpicket/agent/k8slogs/kubetest"
	"github.com/openpicket/openpicket/agent/logsrc"
)

func TestSelectorString(t *testing.T) {
	var s labelSelector
	_ = json.Unmarshal([]byte(`{"matchLabels":{"b":"2","a":"1"},"matchExpressions":[
		{"key":"tier","operator":"In","values":["web","api"]},{"key":"canary","operator":"DoesNotExist"},
		{"key":"zone","operator":"NotIn","values":["x"]},{"key":"team","operator":"Exists"}]}`), &s)
	got, err := s.String()
	if want := "a=1,b=2,tier in (web,api),!canary,zone notin (x),team"; err != nil || got != want {
		t.Fatalf("got %q %v, want %q", got, err, want)
	}
	if _, err := (labelSelector{}).String(); err == nil {
		t.Fatal("empty selector accepted")
	}
}

const testConfig = `node_id: k8s-logs
key_file: /k
openpicket:
  url: wss://openpicket.example.com/agent/data/v1/connect
  host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEbJ7Ld3PTb0mAbmKprCDwG2FpgnUevxH/w8x5hJYwEG openpicket-manager"
`

func TestConfig(t *testing.T) {
	c, err := Parse([]byte(testConfig + `targets:
  - { namespace: web, workload: deployment/web, containers: [nginx], program: nginx }
  - { namespace: web, service_account: api }
`))
	if err != nil || len(c.Targets) != 2 || c.ScanInterval != 10*time.Second || c.StateFile != "" {
		t.Fatalf("config %+v %v", c, err)
	}
	if p := c.Targets[1].ProgramOf("App_Server"); p != "app_server" {
		t.Fatalf("default program %q", p)
	}
	for name, extra := range map[string]string{
		"no targets":     "",
		"bad namespace":  "targets: [{namespace: Web}]",
		"bad workload":   "targets: [{namespace: web, workload: job/x}]",
		"bad program":    `targets: [{namespace: web, program: "My App"}]`,
		"unknown field":  "targets: [{namespace: web, labels: x}]",
		"bad container":  "targets: [{namespace: web, containers: [\"a b\"]}]",
		"short interval": "scan_interval: 10ms\ntargets: [{namespace: web}]",
	} {
		if _, err := Parse([]byte(testConfig + extra)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

type harness struct {
	t    *testing.T
	api  *kubetest.API
	col  *Collector
	stop func()
}

func start(t *testing.T, api *kubetest.API, stateFile string, targets ...Target) *harness {
	t.Helper()
	kube, err := NewKube(KubeConfig{APIURL: api.URL})
	if err != nil {
		t.Fatal(err)
	}
	col, err := New(CollectorConfig{Kube: kube, Targets: targets, StateFile: stateFile, ScanInterval: 50 * time.Millisecond, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { col.Run(ctx); close(done) }()
	h := &harness{t: t, api: api, col: col}
	h.stop = func() { cancel(); <-done; col.Flush() }
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			h.stop()
		}
	})
	return h
}

// take returns the next n lines ("program: line"), committing each batch
// unless commit is false; maxRecords bounds each batch.
func (h *harness) take(n, maxRecords int, commit bool) []string {
	h.t.Helper()
	var out []string
	deadline := time.Now().Add(5 * time.Second)
	for len(out) < n {
		if time.Now().After(deadline) {
			h.t.Fatalf("got %q, want %d lines", out, n)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		bs, _ := h.col.Next(ctx, maxRecords, 1<<20)
		cancel()
		for _, b := range bs {
			for _, r := range b.Records {
				if r.Key == "" {
					h.t.Fatalf("record without key: %+v", r)
				}
				out = append(out, b.Program+": "+string(r.Line))
			}
			if commit {
				h.col.Commit(b)
			}
		}
	}
	return out
}

// none checks that nothing comes for a while.
func (h *harness) none() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if bs, _ := h.col.Next(ctx, 100, 1<<20); len(bs) > 0 {
		h.t.Fatalf("unexpected batch %q", lines(bs))
	}
}

func lines(bs []*logsrc.Batch) []string {
	var out []string
	for _, b := range bs {
		for _, r := range b.Records {
			out = append(out, b.Program+": "+string(r.Line))
		}
	}
	return out
}

// waitFollowing waits for n followed containers in total.
func (h *harness) waitFollowing(n int) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		total := 0
		for _, s := range h.col.Status() {
			total += s.Followed
		}
		if total == n {
			time.Sleep(100 * time.Millisecond) // the streams open
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("following %d containers, want %d (%+v)", total, n, h.col.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

var base = time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)

func at(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }

func TestFollowAndResume(t *testing.T) {
	api := kubetest.New(t)
	api.SetWorkload("web", "deployment", "web", map[string]any{"matchLabels": map[string]string{"app": "web"}})
	api.AddPod(kubetest.Pod{Namespace: "web", Name: "web-1", UID: "u1", Labels: map[string]string{"app": "web"}, Containers: []string{"nginx", "sidecar"}})
	api.AddPod(kubetest.Pod{Namespace: "web", Name: "other", UID: "u9", Labels: map[string]string{"app": "other"}, Containers: []string{"nginx"}})
	api.Log("web", "web-1", "nginx", at(0), "backlog before the first start")
	stateFile := filepath.Join(t.TempDir(), "state", "positions.json")
	targets := []Target{
		{Namespace: "web", Workload: "deployment/web", Containers: []string{"nginx"}, Program: "nginx"},
		{Namespace: "web", ServiceAccount: "api"},
	}
	h := start(t, api, stateFile, targets...)
	h.waitFollowing(1)
	// First run without a state: the current end, no backlog.
	if q := api.LogRequests()[0]; q.Get("tailLines") != "0" || q.Get("timestamps") != "true" || q.Get("follow") != "true" {
		t.Fatalf("first request %v", q)
	}
	api.Log("web", "web-1", "nginx", at(1000), `GET /a 200`)
	api.Log("web", "web-1", "sidecar", at(1000), "not taken")
	if got := h.take(1, 100, true); got[0] != "nginx: GET /a 200" {
		t.Fatalf("got %q", got)
	}
	// A pod appearing later is read from its start, under the container
	// name.
	api.Log("web", "api-1", "app", at(1500), "api booted")
	api.AddPod(kubetest.Pod{Namespace: "web", Name: "api-1", UID: "u2", ServiceAccount: "api", Containers: []string{"app"}})
	if got := h.take(1, 100, true); got[0] != "app: api booted" {
		t.Fatalf("got %q", got)
	}
	// The stream ends (kubelet rotation): resumed after the last line,
	// without repeating it.
	api.EndStreams("web", "web-1", "nginx")
	api.Log("web", "web-1", "nginx", at(2000), "GET /b 200")
	if got := h.take(1, 100, true); got[0] != "nginx: GET /b 200" {
		t.Fatalf("after the stream ended: %q", got)
	}
	// Two lines of the same instant; only the first is acknowledged.
	api.Log("web", "web-1", "nginx", at(3000), "same instant 1")
	api.Log("web", "web-1", "nginx", at(3000), "same instant 2")
	h.take(1, 1, true)
	h.take(1, 1, false)
	h.stop()

	var st state
	b, _ := os.ReadFile(stateFile)
	if err := json.Unmarshal(b, &st); err != nil || st.SavedAt.IsZero() || !st.Containers["u1/nginx"].Time.Equal(at(3000)) || st.Containers["u1/nginx"].N != 1 {
		t.Fatalf("state %s %v", b, err)
	}

	// Meanwhile: a line, and a pod that starts while the collector is
	// down. Restarted, each container resumes after its acknowledged
	// position; the new pod from the last save.
	api.Log("web", "web-1", "nginx", at(4000), "GET /c 200")
	api.AddPod(kubetest.Pod{Namespace: "web", Name: "web-2", UID: "u3", Labels: map[string]string{"app": "web"}, Containers: []string{"nginx"}})
	api.Log("web", "web-2", "nginx", time.Now().Add(time.Second), "web-2 started while down")
	h2 := start(t, api, stateFile, targets...)
	got := h2.take(3, 100, true)
	want := map[string]bool{"nginx: same instant 2": true, "nginx: GET /c 200": true, "nginx: web-2 started while down": true}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("after restart: %q", got)
		}
	}
	h2.none()
	h2.stop()
}

func TestStateless(t *testing.T) {
	api := kubetest.New(t)
	api.AddPod(kubetest.Pod{Namespace: "db", Name: "pg-0", UID: "p0", Labels: map[string]string{"app": "pg"}, Containers: []string{"postgres"}})
	target := Target{Namespace: "db", Selector: "app in (pg,pgbouncer)", Program: "postgres"}
	h := start(t, api, "", target)
	h.waitFollowing(1)
	api.Log("db", "pg-0", "postgres", time.Now(), "FATAL:  password authentication failed for user \"x\"")
	if got := h.take(1, 100, true); !strings.HasPrefix(got[0], "postgres: FATAL:") {
		t.Fatalf("got %q", got)
	}
	h.stop()
	// Without a state, a restart starts at the current end again.
	h2 := start(t, api, "", target)
	h2.waitFollowing(1)
	reqs := api.LogRequests()
	if q := reqs[len(reqs)-1]; q.Get("tailLines") != "0" {
		t.Fatalf("stateless restart %v", q)
	}
	h2.none()
}

func TestTargetErrors(t *testing.T) {
	api := kubetest.New(t)
	h := start(t, api, "", Target{Namespace: "web", Workload: "deployment/missing"})
	deadline := time.Now().Add(5 * time.Second)
	for h.col.Status()[0].LastError == "" {
		if time.Now().After(deadline) {
			t.Fatal("no error for a missing workload")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st := h.col.Status()[0]; !strings.Contains(st.LastError, "404") || st.Path != "k8s web workload=deployment/missing" {
		t.Fatalf("status %+v", st)
	}
}
