package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/manager/registry"
	"github.com/openpicket/openpicket/pkg/record"
)

type fakeSink struct {
	name string
	mu   sync.Mutex
	// fail makes the next n deliveries fail.
	fail     int
	err      error
	got      []uint64
	attempts int
}

func (f *fakeSink) Name() string { return f.name }
func (f *fakeSink) Deliver(_ context.Context, b *Batch) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.fail > 0 {
		f.fail--
		if f.err != nil {
			return f.err
		}
		return errors.New("unavailable")
	}
	f.got = append(f.got, b.Seq)
	return nil
}

func (f *fakeSink) delivered() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.got...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func batch(seq uint64) *Batch {
	return &Batch{NodeID: "n1", BootID: "b1", Seq: seq, Type: "eve", Node: &registry.Node{ID: "n1"}, Records: []*Record{{Line: []byte("{}")}}}
}

// A failing sink is retried alone; the sink that already has the batch does
// not get it again (no duplicate CrowdSec events from Loki retries).
func TestRetryOnlyFailedSink(t *testing.T) {
	loki := &fakeSink{name: "loki", fail: 2}
	cs := &fakeSink{name: "crowdsec"}
	p := New(Config{AckSinks: []Sink{loki, cs}, RetryMin: time.Millisecond, RetryMax: time.Millisecond})
	if err := p.Process(context.Background(), batch(1)); err != nil {
		t.Fatal(err)
	}
	if got := cs.delivered(); len(got) != 1 || cs.attempts != 1 {
		t.Fatalf("crowdsec got %v in %d attempts", got, cs.attempts)
	}
	if got := loki.delivered(); len(got) != 1 || loki.attempts != 3 {
		t.Fatalf("loki got %v in %d attempts", got, loki.attempts)
	}
}

// After OpenAfter of failures the circuit opens and batches are
// acknowledged without the sink; a later probe closes it again.
func TestCircuitOpensAndRecovers(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	loki := &fakeSink{name: "loki", fail: 1 << 30}
	cs := &fakeSink{name: "crowdsec"}
	p := New(Config{AckSinks: []Sink{loki, cs}, OpenAfter: 30 * time.Second, ProbeInterval: 5 * time.Second,
		RetryMin: time.Millisecond, RetryMax: time.Millisecond, Now: c.now})
	done := make(chan error, 1)
	go func() { done <- p.Process(context.Background(), batch(1)) }()
	// Advance the clock while the pipeline retries.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			goto opened
		case <-deadline:
			t.Fatal("circuit did not open")
		case <-time.After(time.Millisecond):
			c.add(time.Second)
		}
	}
opened:
	if !p.Breaker("loki").Open() || len(cs.delivered()) != 1 {
		t.Fatal("expected open circuit and crowdsec delivery")
	}
	// While open (and not probing) batches pass without Loki.
	if err := p.Process(context.Background(), batch(2)); err != nil {
		t.Fatal(err)
	}
	loki.mu.Lock()
	loki.fail = 0
	attempts := loki.attempts
	loki.mu.Unlock()
	if err := p.Process(context.Background(), batch(3)); err != nil {
		t.Fatal(err)
	}
	if loki.attempts != attempts {
		t.Fatal("open circuit must not be tried before the probe interval")
	}
	c.add(6 * time.Second)
	if err := p.Process(context.Background(), batch(4)); err != nil {
		t.Fatal(err)
	}
	if p.Breaker("loki").Open() || len(loki.delivered()) != 1 {
		t.Fatalf("probe should close the circuit: open=%v delivered=%v", p.Breaker("loki").Open(), loki.delivered())
	}
}

func TestPermanentErrorIsNotRetried(t *testing.T) {
	loki := &fakeSink{name: "loki", fail: 1, err: ErrPermanent}
	p := New(Config{AckSinks: []Sink{loki}, RetryMin: time.Millisecond})
	if err := p.Process(context.Background(), batch(1)); err != nil {
		t.Fatal(err)
	}
	if loki.attempts != 1 {
		t.Fatalf("attempts = %d", loki.attempts)
	}
}

func TestWatermarkSkipsDeliveredSinks(t *testing.T) {
	w := NewWatermarks(nil, nil)
	w.Set("n1", "b1", "crowdsec", 5)
	cs := &fakeSink{name: "crowdsec"}
	loki := &fakeSink{name: "loki"}
	p := New(Config{AckSinks: []Sink{loki, cs}, Watermarks: w})
	for seq := uint64(4); seq <= 6; seq++ {
		if err := p.Process(context.Background(), batch(seq)); err != nil {
			t.Fatal(err)
		}
	}
	if got := cs.delivered(); len(got) != 1 || got[0] != 6 {
		t.Fatalf("crowdsec got %v", got)
	}
	if got := loki.delivered(); len(got) != 3 {
		t.Fatalf("loki got %v", got)
	}
	if w.Get(context.Background(), "n1", "b1", "loki") != 6 {
		t.Fatal("watermark not advanced")
	}
}

func TestProcessStopsWithContext(t *testing.T) {
	loki := &fakeSink{name: "loki", fail: 1 << 30}
	p := New(Config{AckSinks: []Sink{loki}, RetryMin: time.Millisecond, RetryMax: time.Millisecond, OpenAfter: time.Hour})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.Process(ctx, batch(1)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestAsyncQueueDropsOldestWhenFull(t *testing.T) {
	os := &fakeSink{name: "opensearch"}
	p := New(Config{AsyncSinks: []Sink{os}, AsyncQueue: 2})
	for seq := uint64(1); seq <= 3; seq++ {
		if err := p.Process(context.Background(), batch(seq)); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(os.delivered()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if got := os.delivered(); len(got) != 2 || got[0] != 2 || got[1] != 3 {
		t.Fatalf("opensearch got %v", got)
	}
}

// Draining abandons the batch in progress without acknowledging it and
// returns once its deliveries are recorded.
func TestDrain(t *testing.T) {
	w := NewWatermarks(nil, nil)
	loki := &fakeSink{name: "loki", fail: 1 << 30}
	cs := &fakeSink{name: "crowdsec"}
	p := New(Config{AckSinks: []Sink{loki, cs}, Watermarks: w, RetryMin: time.Millisecond, RetryMax: 5 * time.Millisecond, OpenAfter: time.Hour})
	ctx := context.Background()
	handled := make(chan bool, 1)
	go func() {
		ok, err := p.handle(ctx, &registry.Node{ID: "n1"}, &dataplanev1.LogBatch{BootId: "b1", Seq: 1, Type: "nflog", ZstdRecords: mustRecords(t)})
		if err != nil {
			t.Error(err)
		}
		handled <- ok
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(cs.delivered()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	p.Drain()
	if ok := <-handled; ok {
		t.Fatal("a drained batch must not be acknowledged")
	}
	if w.Get(ctx, "n1", "b1", "crowdsec") != 1 || w.Get(ctx, "n1", "b1", "loki") != 0 {
		t.Fatal("watermarks must reflect the deliveries made before draining")
	}
	if ok, _ := p.handle(ctx, &registry.Node{ID: "n1"}, &dataplanev1.LogBatch{BootId: "b1", Seq: 2}); ok {
		t.Fatal("no batch is taken after draining")
	}
}

func mustRecords(t *testing.T) []byte {
	t.Helper()
	raw, err := proto.Marshal(&dataplanev1.RecordList{Records: []*dataplanev1.Record{{Line: []byte(`{"event_type":"nflog"}`), Rid: "r1"}}})
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := zstd.NewWriter(nil)
	defer enc.Close()
	return enc.EncodeAll(raw, nil)
}

type programCounts map[string]int

func (c programCounts) Seen(node, program string, n int) { c[node+"/"+program] += n }

// TestDecodeGenericLog: a generic log batch gets its program normalized;
// syslog lines get the program and message of their header.
func TestDecodeGenericLog(t *testing.T) {
	counts := programCounts{}
	p := New(Config{Programs: counts})
	enc, _ := zstd.NewWriter(nil)
	mk := func(program string, lines ...string) *dataplanev1.LogBatch {
		var l dataplanev1.RecordList
		for i, line := range lines {
			l.Records = append(l.Records, &dataplanev1.Record{Line: []byte(line), Rid: fmt.Sprint(i), TimeUnixNano: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC).UnixNano()})
		}
		raw, _ := proto.Marshal(&l)
		return &dataplanev1.LogBatch{BootId: "b", Seq: 1, Type: record.TypeLog, Program: program, ZstdRecords: enc.EncodeAll(raw, nil), RecordCount: uint32(len(lines))}
	}
	node := &registry.Node{ID: "web-01"}
	b, err := p.decode(node, mk(" NGINX ", `198.51.100.7 - - [23/Oct/2026:12:00:00 +0000] "GET /x HTTP/1.1" 404 0 "-" "curl"`))
	if err != nil {
		t.Fatal(err)
	}
	if b.Program != "nginx" || b.Records[0].Program != "nginx" || !strings.HasPrefix(b.Records[0].Message, "198.51.100.7 - -") {
		t.Fatalf("nginx: %s %+v", b.Program, b.Records[0])
	}
	b, err = p.decode(node, mk("syslog", "Oct 23 11:59:59 web-01 sshd[812]: Failed password for root from 198.51.100.66 port 4000 ssh2", "not a syslog line"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Program != "syslog" || b.Records[0].Program != "sshd" || b.Records[0].Message != "Failed password for root from 198.51.100.66 port 4000 ssh2" ||
		b.Records[1].Program != "syslog" || b.Records[1].Message != "not a syslog line" {
		t.Fatalf("syslog: %+v %+v", b.Records[0], b.Records[1])
	}
	if counts["web-01/nginx"] != 1 || counts["web-01/sshd"] != 1 || counts["web-01/syslog"] != 1 {
		t.Fatalf("counts = %v", counts)
	}
	// Eve batches have no program.
	if b, _ := p.decode(node, &dataplanev1.LogBatch{Type: record.TypeEve, ZstdRecords: enc.EncodeAll(nil, nil)}); b.Program != "" {
		t.Fatal("eve batch with a program")
	}
}
