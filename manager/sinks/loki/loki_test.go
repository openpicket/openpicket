package loki

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/manager/registry"
	"github.com/openpicket/openpicket/pkg/record"
	"github.com/openpicket/openpicket/pkg/syslogfmt"
)

type push struct {
	Streams []struct {
		Stream map[string]string `json:"stream"`
		Values [][]any           `json:"values"`
	} `json:"streams"`
}

func TestDeliver(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	var got push
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/push" || r.Header.Get("X-Scope-OrgID") != "openpicket" || r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("request %s %v", r.URL.Path, r.Header)
		}
		zr, _ := gzip.NewReader(r.Body)
		got = push{}
		_ = json.NewDecoder(zr).Decode(&got)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	s, err := New(Config{URL: srv.URL, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	alert := []byte(`{"event_type":"alert","src_ip":"198.51.100.9","dest_ip":"192.168.1.5","dest_port":443,"alert":{"signature_id":2001}}`)
	e, _ := record.ParseEve(alert)
	b := &pipeline.Batch{NodeID: "r1", Type: "eve", Instance: "ids", Received: now, Node: &registry.Node{ID: "r1", Labels: map[string]string{"site": "seoul"}},
		Records: []*pipeline.Record{
			{Line: alert, RID: "rid1", Time: now.Add(-time.Minute), Eve: e, EventType: "alert", SrcGeo: &pipeline.Geo{Country: "CN", ASN: 4134}},
			{Line: []byte(`{"event_type":"flow"}`), RID: "rid2", Time: now, EventType: "flow"},
			{Line: []byte(`{"event_type":"flow"}`), RID: "old", Time: now.Add(-8 * 24 * time.Hour), EventType: "flow"},
			{Line: []byte(`{"event_type":"flow"}`), RID: "future", Time: now.Add(time.Hour), EventType: "flow"},
		}}
	if err := s.Deliver(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if len(got.Streams) != 2 {
		t.Fatalf("streams = %+v", got.Streams)
	}
	st := got.Streams[0]
	if st.Stream["event_type"] != "alert" || st.Stream["node"] != "r1" || st.Stream["instance"] != "ids" || st.Stream["site"] != "" {
		t.Fatalf("labels = %v", st.Stream)
	}
	v := st.Values[0]
	md := v[2].(map[string]any)
	if v[1] != string(alert) || md["site"] != "seoul" || md["src_cc"] != "CN" || md["src_asn"] != "4134" || md["dest_port"] != "443" ||
		md["signature_id"] != "2001" || md["rid"] != "rid1" {
		t.Fatalf("value = %v", v)
	}
	if n := len(got.Streams[1].Values); n != 1 {
		t.Fatalf("out-of-window records sent: %d flow values", n)
	}

	status = http.StatusBadRequest
	if err := s.Deliver(context.Background(), b); !errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("400: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := s.Deliver(context.Background(), b); err == nil || errors.Is(err, pipeline.ErrPermanent) {
		t.Fatalf("503 must be retryable: %v", err)
	}
}

// TestGenericLogLabelsAndSkip: generic logs are labelled by program; a
// program kept out of Loki is acknowledged without a push.
func TestGenericLogLabelsAndSkip(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	var got push
	pushes := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushes++
		zr, _ := gzip.NewReader(r.Body)
		got = push{}
		_ = json.NewDecoder(zr).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s, err := New(Config{URL: srv.URL, Now: func() time.Time { return now }, Skip: func(p string) bool { return p == "nginx" }})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(program string) *pipeline.Batch {
		return &pipeline.Batch{NodeID: "web-01", Type: record.TypeLog, Program: program, Received: now, Node: &registry.Node{ID: "web-01"},
			Records: []*pipeline.Record{{Line: []byte("a line"), Time: now, Program: program}}}
	}
	if err := s.Deliver(context.Background(), mk("nginx")); err != nil || pushes != 0 {
		t.Fatalf("skipped program pushed: %v %d", err, pushes)
	}
	if err := s.Deliver(context.Background(), mk("postgres")); err != nil || pushes != 1 {
		t.Fatalf("push: %v %d", err, pushes)
	}
	if l := got.Streams[0].Stream; l["type"] != "log" || l["program"] != "postgres" || l["node"] != "web-01" {
		t.Fatalf("labels = %v", l)
	}
	// Syslog lines: each under the program of its header, the source in
	// the metadata; a skipped one is left out.
	b := mk("syslog")
	b.Records = []*pipeline.Record{
		{Line: []byte("dovecot line"), Time: now, Program: "dovecot", Syslog: &syslogfmt.Message{}},
		{Line: []byte("smtpd line"), Time: now, Program: "postfix/smtpd", Syslog: &syslogfmt.Message{}},
		{Line: []byte("nginx line"), Time: now, Program: "nginx", Syslog: &syslogfmt.Message{}},
	}
	if err := s.Deliver(context.Background(), b); err != nil || pushes != 2 || len(got.Streams) != 2 {
		t.Fatalf("syslog push: %v %d %+v", err, pushes, got.Streams)
	}
	for i, want := range []string{"dovecot", "postfix/smtpd"} {
		st := got.Streams[i]
		if st.Stream["program"] != want || st.Values[0][2].(map[string]any)["source_program"] != "syslog" {
			t.Fatalf("stream %d: %+v", i, st)
		}
	}
}
