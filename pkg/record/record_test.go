package record

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAppendTag(t *testing.T) {
	line := []byte(`{"event_type":"alert","src_ip":"1.2.3.4"}`)
	out := AppendTag(line, Tag{RID: "abc", Direction: "inbound", RemoteIP: "1.2.3.4"})
	var e Eve
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	if e.OpenPicket == nil || e.OpenPicket.RID != "abc" || e.EventType != "alert" || e.OpenPicket.LocalIP != "" {
		t.Fatalf("decoded %+v from %s", e.OpenPicket, out)
	}
	if string(AppendTag([]byte(`not json`), Tag{RID: "x"})) != "not json" {
		t.Fatal("non-object changed")
	}
	if got := string(AppendField([]byte(`{}`), "a", 1)); got != `{"a":1}` {
		t.Fatalf("empty object: %s", got)
	}
}

func TestRIDAndTime(t *testing.T) {
	a := FileRID("n1", "/var/log/eve.json", 7, 100)
	if a != FileRID("n1", "/var/log/eve.json", 7, 100) || a == FileRID("n1", "/var/log/eve.json", 7, 101) || len(a) != 32 {
		t.Fatal("file rid not stable/unique")
	}
	ts, ok := ParseTime("2026-10-20T10:59:01.123456+0900")
	if !ok || !ts.Equal(time.Date(2026, 10, 20, 1, 59, 1, 123456000, time.UTC)) {
		t.Fatalf("suricata time = %v", ts)
	}
	if _, ok := ParseTime("2026-10-20T10:59:01.123+09:00"); !ok {
		t.Fatal("rfc3339")
	}
	if StringField([]byte(`{"timestamp": "x", "event_type":"dns"}`), "event_type") != "dns" {
		t.Fatal("string field")
	}
}
