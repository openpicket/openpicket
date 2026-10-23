package syslog

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/manager/registry"
)

func TestReadFrames(t *testing.T) {
	long := strings.Repeat("x", MaxLine+10)
	counted := "<13>Oct 23 10:00:00 sw1 b:"
	in := "<13>Oct 23 10:00:00 sw1 a: one\n" +
		fmt.Sprintf("%d %s", len(counted), counted) + // octet counting, then newline framing again
		"2026-10-23T10:00:00Z sw1 c: iso\r\n" +
		"5 hello" +
		long + "\n" +
		"last without newline"
	var got []string
	err := ReadFrames(bufio.NewReaderSize(strings.NewReader(in), MaxLine+16), func(b []byte) { got = append(got, string(b)) })
	if err == nil {
		t.Fatal("no EOF")
	}
	want := []string{"<13>Oct 23 10:00:00 sw1 a: one\n", "<13>Oct 23 10:00:00 sw1 b:", "2026-10-23T10:00:00Z sw1 c: iso\r\n", "hello",
		long[:MaxLine], "last without newline"}
	if len(got) != len(want) {
		t.Fatalf("got %d frames: %.80q", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("frame %d = %.80q (%d bytes), want %.80q (%d bytes)", i, got[i], len(got[i]), want[i], len(want[i]))
		}
	}
}

func TestDeviceProgramAndTempID(t *testing.T) {
	d := &Device{Programs: map[string]string{"%ASA-4-106023": "cisco-asa", ProgramDefault: "switch"}}
	for tag, want := range map[string]string{"%ASA-4-106023": "cisco-asa", "": "switch", "SSHD": "sshd", "%%%": "unknown"} {
		if got := d.Program(tag); got != want {
			t.Errorf("Program(%q) = %q, want %q", tag, got, want)
		}
	}
	if got := (&Device{}).Program(""); got != "unknown" {
		t.Errorf("no default: %q", got)
	}
	if got := TempID(netip.MustParseAddr("::ffff:192.0.2.7")); got != "192.0.2.7" {
		t.Errorf("TempID v4 = %q", got)
	}
	if got := TempID(netip.MustParseAddr("2001:db8::1")); got != "ip6-2001-db8--1" {
		t.Errorf("TempID v6 = %q", got)
	}
}

func testDevices(mode string, devs ...*Device) *Devices {
	d := &Devices{def: mode, log: slog.New(slog.DiscardHandler)}
	var tb table
	for _, dev := range devs {
		dev.Registered = true
		dev.node = &registry.Node{ID: dev.ID, Enabled: dev.Enabled, Labels: dev.Labels}
		for _, p := range dev.Sources {
			tb = append(tb, entry{prefix: p, dev: dev})
		}
	}
	// Longest prefix first.
	for i := range tb {
		for j := i + 1; j < len(tb); j++ {
			if tb[j].prefix.Bits() > tb[i].prefix.Bits() {
				tb[i], tb[j] = tb[j], tb[i]
			}
		}
	}
	d.table.Store(&tb)
	d.mode.Store(mode)
	return d
}

func TestServerReceives(t *testing.T) {
	for _, mode := range []string{ModeDrop, ModeAccept} {
		t.Run(mode, func(t *testing.T) {
			devs := testDevices(mode,
				&Device{ID: "lan-switches", Enabled: true, Sources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Labels: map[string]string{"site": "seoul"}},
				&Device{ID: "fw-01", Enabled: true, Sources: []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")},
					Programs: map[string]string{"%ASA-4-106023": "cisco-asa"}},
				&Device{ID: "off", Enabled: false, Sources: []netip.Prefix{netip.MustParsePrefix("127.0.0.3/32")}},
			)
			src := NewSources(nil, slog.New(slog.DiscardHandler))
			var mu sync.Mutex
			var batches []*pipeline.Batch
			srv, err := New(Config{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0", Devices: devs, Sources: src, FlushInterval: 20 * time.Millisecond,
				Ingest: func(_ context.Context, b *pipeline.Batch) (bool, error) {
					mu.Lock()
					batches = append(batches, b)
					mu.Unlock()
					return true, nil
				}, Logger: slog.New(slog.DiscardHandler)})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { srv.Run(ctx); close(done) }()
			defer func() { cancel(); <-done }()

			send := func(network, from, msg string) {
				t.Helper()
				addr := srv.udp.LocalAddr().String()
				if network == "tcp" {
					addr = srv.tcp.Addr().String()
				}
				d := net.Dialer{LocalAddr: map[string]net.Addr{"udp": &net.UDPAddr{IP: net.ParseIP(from)}, "tcp": &net.TCPAddr{IP: net.ParseIP(from)}}[network]}
				c, err := d.Dial(network, addr)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = c.Write([]byte(msg))
				c.Close()
			}
			send("udp", "127.0.0.1", "<34>Oct 23 10:00:00 sw1 sshd[42]: Failed password for root from 198.51.100.66 port 4000 ssh2")
			send("tcp", "127.0.0.2", "<164>Oct 23 10:00:01 fw %ASA-4-106023: Deny tcp src outside:198.51.100.7/4444 dst inside:10.0.0.5/22\n14 no header here")
			send("udp", "127.0.0.3", "<13>Oct 23 10:00:02 off x: disabled device")
			send("udp", "127.0.0.4", "") // empty: ignored

			var got map[string][]string
			deadline := time.Now().Add(5 * time.Second)
			for {
				mu.Lock()
				got = map[string][]string{}
				for _, b := range batches {
					for _, r := range b.Records {
						got[b.NodeID] = append(got[b.NodeID], fmt.Sprintf("%s %v %q", r.Program, r.Syslog, r.ProgramOverride))
					}
				}
				mu.Unlock()
				if len(got["lan-switches"]) == 1 && len(got["fw-01"]) == 2 || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			want := map[string][]string{
				// The renamed tag goes to CrowdSec with its program; a line
				// without a header as a plain line.
				"lan-switches": {`sshd true ""`},
				"fw-01":        {`cisco-asa true "cisco-asa"`, `unknown false ""`},
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("got %v", got)
			}
			mu.Lock()
			for _, b := range batches {
				if b.Program != pipeline.ProgramSyslog || b.Type != "log" || b.Node == nil || b.Node.ID != b.NodeID {
					t.Errorf("batch %+v", b)
				}
				if b.NodeID == "lan-switches" && b.Node.Site() != "seoul" {
					t.Errorf("labels %v", b.Node.Labels)
				}
			}
			mu.Unlock()
			src.mu.Lock()
			defer src.mu.Unlock()
			if c := src.pending[netip.MustParseAddr("127.0.0.3")]; c == nil || c.dropped != 1 || c.device != "off" {
				t.Errorf("disabled device count %+v", c)
			}
			if c := src.pending[netip.MustParseAddr("127.0.0.2")]; c == nil || c.messages != 2 || c.device != "fw-01" || c.sample != "no header here" {
				t.Errorf("fw count %+v", c)
			}
		})
	}
}

func TestUnregisteredSenders(t *testing.T) {
	for _, mode := range []string{ModeDrop, ModeAccept} {
		devs := testDevices(mode, &Device{ID: "sw", Enabled: true, Sources: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}})
		src := NewSources(nil, slog.New(slog.DiscardHandler))
		srv := &Server{cfg: Config{Devices: devs, Sources: src, BatchLines: 1000, Now: time.Now}, pending: map[string]*pipeline.Batch{}, queue: make(chan *pipeline.Batch, 4)}
		srv.messages = newMessages()
		srv.receive(netip.MustParseAddr("192.0.2.9"), []byte("<13>Oct 23 10:00:00 h app: hello"))
		srv.Flush()
		c := src.pending[netip.MustParseAddr("192.0.2.9")]
		switch mode {
		case ModeDrop:
			if len(srv.queue) != 0 || c.dropped != 1 || c.device != "" {
				t.Errorf("drop: queued %d, count %+v", len(srv.queue), c)
			}
		case ModeAccept:
			b := <-srv.queue
			if b.NodeID != "192.0.2.9" || b.Records[0].Program != "app" || c.messages != 1 || c.device != "" {
				t.Errorf("accept: batch %s %+v, count %+v", b.NodeID, b.Records[0], c)
			}
		}
	}
}
