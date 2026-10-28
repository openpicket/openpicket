package crowdsec

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/manager/registry"
	"github.com/openpicket/openpicket/pkg/record"
	"github.com/openpicket/openpicket/pkg/syslogfmt"
)

type lp struct {
	srv  *httptest.Server
	mu   sync.Mutex
	down bool
	got  map[string][]map[string]any // path -> records
}

func newLP(t *testing.T) *lp {
	l := &lp{got: map[string][]map[string]any{}}
	l.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("X-OpenPicket-Token") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		zr, _ := gzip.NewReader(r.Body)
		sc := bufio.NewScanner(zr)
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			l.got[r.URL.Path] = append(l.got[r.URL.Path], m)
		}
	}))
	t.Cleanup(l.srv.Close)
	return l
}

func (l *lp) count(path string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.got[path])
}

func rec(t *testing.T, line string) *pipeline.Record {
	e, err := record.ParseEve([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return &pipeline.Record{Line: []byte(line), Eve: e, EventType: e.EventType}
}

func TestFilterShardAndRetry(t *testing.T) {
	a, b := newLP(t), newLP(t)
	now := time.Unix(1000, 0)
	s, err := New(Config{Endpoints: []string{a.srv.URL, b.srv.URL}, AuthValue: "secret", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	var recs []*pipeline.Record
	for i := 0; i < 40; i++ {
		recs = append(recs, rec(t, fmt.Sprintf(`{"event_type":"alert","src_ip":"10.0.0.1","openpicket":{"rid":"r%d","remote_ip":"198.51.100.%d"}}`, i, i)))
	}
	recs = append(recs, rec(t, `{"event_type":"flow","src_ip":"198.51.100.1"}`))
	batch := &pipeline.Batch{NodeID: "r1", Type: "eve", Received: now, Node: &registry.Node{ID: "r1", Labels: map[string]string{"site": "seoul"}}, Records: recs}

	// One log processor is down: the first attempt delivers the healthy
	// shard only; the retry moves the rest to the healthy one.
	b.mu.Lock()
	b.down = true
	b.mu.Unlock()
	if err := s.Deliver(context.Background(), batch); err == nil {
		t.Fatal("expected an error while one endpoint is down")
	}
	first := a.count("/openpicket")
	if first == 0 || first == 40 {
		t.Fatalf("expected a partial delivery, got %d", first)
	}
	if err := s.Deliver(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if a.count("/openpicket") != 40 || b.count("/openpicket") != 0 {
		t.Fatalf("a=%d b=%d", a.count("/openpicket"), b.count("/openpicket"))
	}
	m := a.got["/openpicket"][0]["openpicket_meta"].(map[string]any)
	if m["node_id"] != "r1" || m["site"] != "seoul" {
		t.Fatalf("meta = %v", m)
	}
}

func TestPickIsStableAndMovesOnlyTheLostShare(t *testing.T) {
	eps := []string{"http://a", "http://b", "http://c"}
	moved := 0
	for i := 0; i < 300; i++ {
		k := fmt.Sprintf("198.51.100.%d", i)
		before := Pick(k, eps)
		if Pick(k, eps) != before {
			t.Fatal("unstable")
		}
		after := Pick(k, []string{"http://a", "http://c"})
		if before != "http://b" && after != before {
			t.Fatalf("%s moved from %s to %s although its endpoint stayed", k, before, after)
		}
		if before == "http://b" {
			moved++
		}
	}
	if moved == 0 {
		t.Fatal("no key mapped to b")
	}
}

func TestNflogPrefixFilter(t *testing.T) {
	a := newLP(t)
	s, _ := New(Config{Endpoints: []string{a.srv.URL}, AuthValue: "secret"})
	batch := &pipeline.Batch{NodeID: "r1", Type: "nflog", Node: &registry.Node{ID: "r1"}, Records: []*pipeline.Record{
		rec(t, `{"event_type":"nflog","prefix":"WAN-REJECT","src_ip":"198.51.100.4"}`),
		rec(t, `{"event_type":"nflog","prefix":"BAN-EGRESS","src_ip":"192.168.1.5"}`),
	}}
	if err := s.Deliver(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if a.count("/openpicket") != 1 {
		t.Fatalf("nflog = %d", a.count("/openpicket"))
	}
}

// TestGenericLogs: generic log lines go out wrapped (program, message,
// node) and all lines of a node to one log processor.
func TestGenericLogs(t *testing.T) {
	a, b := newLP(t), newLP(t)
	now := time.Unix(1000, 0)
	s, err := New(Config{Endpoints: []string{a.srv.URL, b.srv.URL}, AuthValue: "secret", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"web-01", "web-02", "web-03", "web-04"} {
		var recs []*pipeline.Record
		for i := 0; i < 10; i++ {
			line := fmt.Sprintf(`198.51.100.%d - - [x] "GET / HTTP/1.1" 404 0`, i)
			recs = append(recs, &pipeline.Record{Line: []byte(line), Time: now, Program: "nginx"})
		}
		batch := &pipeline.Batch{NodeID: node, Type: record.TypeLog, Program: "nginx", Received: now, Node: &registry.Node{ID: node}, Records: recs}
		if err := s.Deliver(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
	}
	if a.count("/openpicket")+b.count("/openpicket") != 40 || a.count("/openpicket")%10 != 0 {
		t.Fatalf("a=%d b=%d: a node's lines were split", a.count("/openpicket"), b.count("/openpicket"))
	}
	got := append(a.got["/openpicket"], b.got["/openpicket"]...)
	l := got[0]["openpicket_log"].(map[string]any)
	m := got[0]["openpicket_meta"].(map[string]any)
	if l["program"] != "nginx" || !strings.HasPrefix(l["message"].(string), "198.51.100.") || !strings.HasPrefix(m["node_id"].(string), "web-0") {
		t.Fatalf("envelope = %v", got[0])
	}
}

// Syslog lines go split, with the fields crowdsecurity/syslog-logs names
// (the tag as written, the device's program for a renamed one).
func TestSyslogEnvelope(t *testing.T) {
	now := time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC)
	b := &pipeline.Batch{NodeID: "fw-01", Type: record.TypeLog, Program: pipeline.ProgramSyslog, Received: now}
	rec := func(line, override string) *pipeline.Record {
		r := &pipeline.Record{Line: []byte(line), Time: now, ProgramOverride: override}
		if m, ok := syslogfmt.Parse(line, now); ok {
			r.Syslog = &m
		}
		return r
	}
	pw := "Failed password for root from 198.51.100.66 port 4000 ssh2"
	for r, want := range map[*pipeline.Record]LogLine{
		rec("<38>Oct 27 10:00:00 fw sshd[42]: "+pw, ""): {Program: "sshd", Message: pw, Format: "syslog", Host: "fw", PID: "42",
			Timestamp: "Oct 27 10:00:00", SyslogPriority: "38"},
		rec("<38>Oct 27 10:00:00 fw auth[42]: "+pw, "sshd"): {Program: "sshd", Message: pw, Format: "syslog", Host: "fw", PID: "42",
			Timestamp: "Oct 27 10:00:00", SyslogPriority: "38"},
		rec("2026-10-26 19:27:55 info postfix/smtpd[56825]: connect from unknown[178.16.53.230]", ""): {Program: "postfix/smtpd",
			Message: "connect from unknown[178.16.53.230]", Format: "syslog", PID: "56825", Timestamp8601: "2026-10-26 19:27:55"},
		{Line: []byte("no header"), Time: now, Program: "unknown"}: {Program: "unknown", Message: "no header"},
	} {
		var got LogEnvelope
		if err := json.Unmarshal(Line(b, r), &got); err != nil || got.Log != want || got.Meta.NodeID != "fw-01" {
			t.Errorf("%s: %+v %v", r.Line, got, err)
		}
	}
}
