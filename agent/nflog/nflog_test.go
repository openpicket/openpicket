package nflog

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/direction"
	"github.com/openpicket/openpicket/pkg/record"
)

type fakeOutput struct {
	mu   sync.Mutex
	recs []*dataplanev1.Record
	n    int
}

func (f *fakeOutput) Push(_ context.Context, typ string, recs []*dataplanev1.Record, _ uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if typ != record.TypeNflog {
		panic(typ)
	}
	f.recs = append(f.recs, recs...)
	return true
}

func (f *fakeOutput) NextMemoryRID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return record.MemoryRID("boot", uint64(f.n))
}

func (f *fakeOutput) records() []*dataplanev1.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*dataplanev1.Record(nil), f.recs...)
}

type fakeReceiver struct{ events []Event }

func (r *fakeReceiver) Receive(ctx context.Context, fn func(Event)) error {
	for _, ev := range r.events {
		fn(ev)
	}
	<-ctx.Done()
	return nil
}
func (r *fakeReceiver) Close() error { return nil }

func tcpEvent(prefix, src, dst string, dport int) Event {
	return Event{Time: time.Date(2026, 10, 20, 1, 59, 1, 0, time.UTC), Group: GroupDNATMiss, Prefix: prefix, InIface: "wan",
		Packet: &Packet{IPVersion: 4, Proto: "TCP", Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), SrcPort: 40000, DstPort: dport, TCPFlags: "S", TTL: 50, Length: 60}}
}

func run(t *testing.T, cfg Config, events ...Event) []*dataplanev1.Record {
	t.Helper()
	out := &fakeOutput{}
	cfg.Output = out
	cfg.Groups = []uint16{GroupDNATMiss}
	cfg.Open = func(uint16) (Receiver, error) { return &fakeReceiver{events: events}, nil }
	s := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(out.records()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	return out.records()
}

func TestRecords(t *testing.T) {
	nets, _ := direction.NewNets([]string{"203.0.113.10", "192.168.1.0/24"})
	recs := run(t, Config{Nets: func() *direction.Nets { return nets }},
		tcpEvent("DNAT-MISS: ", "198.51.100.4", "203.0.113.10", 3389),
		tcpEvent("BAN-EGRESS: ", "192.168.1.50", "198.51.100.9", 443))
	if len(recs) != 2 {
		t.Fatalf("records = %d", len(recs))
	}
	var e record.Eve
	if err := json.Unmarshal(recs[0].Line, &e); err != nil {
		t.Fatal(err)
	}
	if e.EventType != "nflog" || e.Prefix != "DNAT-MISS" || e.DestPort != 3389 || e.OpenPicket.RID != recs[0].Rid ||
		e.OpenPicket.Direction != direction.Inbound || e.OpenPicket.RemoteIP != "198.51.100.4" {
		t.Fatalf("record = %s", recs[0].Line)
	}
	if ts, ok := record.ParseTime(e.Timestamp); !ok || ts.UnixNano() != recs[0].TimeUnixNano {
		t.Fatalf("timestamp %q", e.Timestamp)
	}
	_ = json.Unmarshal(recs[1].Line, &e)
	if e.Prefix != "BAN-EGRESS" || e.OpenPicket.Direction != direction.Outbound || e.OpenPicket.RemoteIP != "198.51.100.9" || e.OpenPicket.LocalIP != "192.168.1.50" {
		t.Fatalf("egress record = %s", recs[1].Line)
	}
}

func TestAggregation(t *testing.T) {
	var evs []Event
	for i := 0; i < 5; i++ {
		evs = append(evs, tcpEvent("DNAT-MISS: ", "198.51.100.4", "203.0.113.10", 22))
	}
	evs = append(evs, tcpEvent("DNAT-MISS: ", "198.51.100.4", "203.0.113.10", 23))
	recs := run(t, Config{AggregateWindow: 10 * time.Millisecond}, evs...)
	counts := map[int]int{}
	for _, r := range recs {
		var l struct {
			DestPort int `json:"dest_port"`
			Count    int `json:"count"`
		}
		_ = json.Unmarshal(r.Line, &l)
		counts[l.DestPort] += l.Count
	}
	if counts[22] != 5 || counts[23] != 1 || len(recs) != 2 {
		t.Fatalf("counts = %v (%d records)", counts, len(recs))
	}
}

func TestSplitPrefix(t *testing.T) {
	if k, d := SplitPrefix("POLICY-DROP: smtp-submission "); k != "POLICY-DROP" || d != "smtp-submission" {
		t.Fatalf("%q %q", k, d)
	}
}
