package test

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/agent/platform"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent"
	"github.com/openpicket/openpicket/agent/config"
	"github.com/openpicket/openpicket/agent/nft"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/suristore"
)

// envelopeLP records the generic log envelopes CrowdSec receives.
type envelopeLP struct {
	mu   sync.Mutex
	got  []crowdsec.LogEnvelope
	meta []map[string]any
}

func (f *envelopeLP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zr, _ := gzip.NewReader(r.Body)
	sc := bufio.NewScanner(zr)
	f.mu.Lock()
	defer f.mu.Unlock()
	for sc.Scan() {
		var e crowdsec.LogEnvelope
		var raw struct {
			Meta map[string]any `json:"openpicket_meta"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil || json.Unmarshal(sc.Bytes(), &raw) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.got = append(f.got, e)
		f.meta = append(f.meta, raw.Meta)
	}
}

func (f *envelopeLP) lines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.got {
		out = append(out, e.Log.Program+": "+e.Log.Message)
	}
	return out
}

// lokiLabels records the stream labels pushed to Loki.
type lokiLabels struct {
	mu      sync.Mutex
	streams []map[string]string
}

func (f *lokiLabels) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zr, _ := gzip.NewReader(r.Body)
	var p struct {
		Streams []struct {
			Stream map[string]string `json:"stream"`
		} `json:"streams"`
	}
	_ = json.NewDecoder(zr).Decode(&p)
	f.mu.Lock()
	for _, s := range p.Streams {
		f.streams = append(f.streams, s.Stream)
	}
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// TestAgentWithoutSuricataShipsLogs runs the real agent without Suricata
// (no suricontroller agent): it tails a log file and an auth.log, and the
// manager hands the lines to CrowdSec wrapped (the auth.log line under its
// own program) and to Loki labelled by program.
func TestAgentWithoutSuricataShipsLogs(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	lk := &lokiLabels{}
	lokiSrv := httptest.NewServer(lk)
	defer lokiSrv.Close()
	lp := &envelopeLP{}
	lpSrv := httptest.NewServer(lp)
	defer lpSrv.Close()
	hostKey, _ := sshkey.Generate()
	r := startReplica(t, pool, hostKey, lokiSrv.URL, lpSrv.URL, "replica-a")
	defer r.stop()

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "agent_ed25519")
	agentKey, _, err := sshkey.LoadOrGenerate(keyFile, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	line := agentKey.Public("web-01").String()
	x, _ := suristore.X25519(line)
	pk, _ := sshkey.ParsePublicKey(line)
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint, labels) VALUES ('web-01',$1,$2,$3,'{"site":"seoul"}')`, line, x, pk.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(dir, "logs")
	_ = os.MkdirAll(logs, 0o755)
	access, auth := filepath.Join(logs, "access.log"), filepath.Join(logs, "auth.log")
	_ = os.WriteFile(access, []byte("backlog, not shipped\n"), 0o644)
	_ = os.WriteFile(auth, nil, 0o644)
	free, _ := net.ListenPacket("udp", "127.0.0.1:0")
	listen := free.LocalAddr().String()
	free.Close()
	yaml := fmt.Sprintf(`node_id: web-01
key_file: %s
state_dir: %s
openpicket:
  url: %s
  host_key: %q
  suricata: { enabled: false }
  log_sources:
    - { program: nginx, path: %q }
    - { program: syslog, path: %q }
    - { listen: %q }
`, keyFile, filepath.Join(dir, "state"), "ws"+strings.TrimPrefix(r.srv.URL, "http")+"/agent/data/v1/connect",
		hostKey.Public(manager.HostKeyComment).String(), filepath.Join(logs, "*access.log"), auth, listen)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Suri != nil || cfg.Node.NodeID != "web-01" {
		t.Fatalf("config: suri=%v node=%+v", cfg.Suri, cfg.Node)
	}
	noFw4 := false
	a, err := agent.New(ctx, cfg, agent.Options{Logger: slog.New(slog.DiscardHandler), Host: fakeHost(t), Fw4: &noFw4})
	if err != nil {
		t.Fatal(err)
	}
	actx, acancel := context.WithCancel(ctx)
	adone := make(chan struct{})
	go func() { _ = a.Run(actx); close(adone) }()
	defer func() { acancel(); <-adone }()

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timeout: %s (CrowdSec got %q)", what, lp.lines())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	// The agent connects and reads the files' current ends first.
	waitFor("node online", func() bool { return r.m.Gateway().Session("web-01") != nil })
	time.Sleep(1500 * time.Millisecond)
	appendTo := func(path, s string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(s)
		f.Close()
	}
	appendTo(access, `198.51.100.67 - - [23/Oct/2026:12:00:00 +0000] "GET /x HTTP/1.1" 404 0 "-" "curl"`+"\n")
	appendTo(auth, "Oct 23 12:00:01 web-01 sshd[812]: Failed password for root from 198.51.100.66 port 4000 ssh2\n")
	waitFor("both lines at CrowdSec", func() bool { return len(lp.lines()) >= 2 })
	// A datagram to the local listener (OpenWrt's logd), sent again until
	// the listener is up.
	dropbear := "dropbear: Bad password attempt for 'root' from 198.51.100.7:4000"
	waitFor("listener line at CrowdSec", func() bool {
		if c, err := net.Dial("udp", listen); err == nil {
			_, _ = c.Write([]byte("<38>Oct 23 12:00:02 dropbear[1234]: Bad password attempt for 'root' from 198.51.100.7:4000"))
			c.Close()
		}
		for _, l := range lp.lines() {
			if l == dropbear {
				return true
			}
		}
		return false
	})
	got := lp.lines()
	want := []string{`nginx: 198.51.100.67 - - [23/Oct/2026:12:00:00 +0000] "GET /x HTTP/1.1" 404 0 "-" "curl"`,
		"sshd: Failed password for root from 198.51.100.66 port 4000 ssh2"}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			t.Fatalf("CrowdSec lacks %q: %q", w, got)
		}
	}
	for _, g := range got {
		if strings.Contains(g, "backlog") {
			t.Fatal("the backlog was shipped")
		}
	}
	lp.mu.Lock()
	m := lp.meta[0]
	lp.mu.Unlock()
	if m["node_id"] != "web-01" || m["site"] != "seoul" {
		t.Fatalf("meta = %v", m)
	}
	waitFor("Loki streams", func() bool {
		lk.mu.Lock()
		defer lk.mu.Unlock()
		progs := map[string]bool{}
		for _, s := range lk.streams {
			if s["type"] == "log" {
				progs[s["program"]] = true
			}
		}
		return progs["nginx"] && progs["syslog"]
	})
	// The programs seen are counted for the UI (flushed on stop).
	acancel()
	<-adone
	r.stop()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM openpicket.log_programs WHERE node_id = 'web-01' AND program IN ('nginx', 'sshd')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("log_programs: %d %v", n, err)
	}
}

// fakeHost stands in for nft and the host files (no WAN: nothing applied).
func fakeHost(t *testing.T) *nft.Host {
	return &nft.Host{Exec: fakeNft{}, FS: platform.HostFS{Root: t.TempDir()}}
}
