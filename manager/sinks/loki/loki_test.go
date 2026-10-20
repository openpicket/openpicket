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
