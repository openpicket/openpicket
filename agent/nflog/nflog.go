// Package nflog receives packets the node's nftables rules log to NFLOG
// groups (DNAT-MISS, POLICY-DROP, BAN-EGRESS; docs/ARCHITECTURE.md §4.5)
// and turns them into "nflog" records for the data plane.
package nflog

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	gonflog "github.com/florianl/go-nflog/v2"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/direction"
	"github.com/openpicket/openpicket/pkg/record"
)

// Groups used by OpenPicket rules.
const (
	GroupDNATMiss   = 100
	GroupPolicyDrop = 101
	GroupBanEgress  = 102
)

// Prefixes (the rule prefix without the trailing ": ").
const (
	PrefixDNATMiss   = "DNAT-MISS"
	PrefixPolicyDrop = "POLICY-DROP"
	PrefixBanEgress  = "BAN-EGRESS"
)

// Event is one logged packet (or an aggregate of identical ones).
type Event struct {
	Time     time.Time
	Group    int
	Prefix   string
	InIface  string
	OutIface string
	Packet   *Packet
	// Count is set for aggregated events.
	Count int
}

// line is the JSON layout of an nflog record (field names follow eve).
type line struct {
	Timestamp string      `json:"timestamp"`
	EventType string      `json:"event_type"`
	Prefix    string      `json:"prefix"`
	Detail    string      `json:"prefix_detail,omitempty"`
	Group     int         `json:"group"`
	InIface   string      `json:"in_iface,omitempty"`
	OutIface  string      `json:"out_iface,omitempty"`
	IPVersion int         `json:"ip_version"`
	Proto     string      `json:"proto"`
	SrcIP     string      `json:"src_ip"`
	SrcPort   int         `json:"src_port,omitempty"`
	DestIP    string      `json:"dest_ip"`
	DestPort  int         `json:"dest_port,omitempty"`
	TCPFlags  string      `json:"tcp_flags,omitempty"`
	ICMPType  *int        `json:"icmp_type,omitempty"`
	TTL       int         `json:"ttl"`
	PktLen    int         `json:"pkt_len"`
	Count     int         `json:"count,omitempty"`
	Tag       *record.Tag `json:"openpicket"`
}

// SplitPrefix separates the kind from the rest of a rule prefix
// ("POLICY-DROP: smtp " -> "POLICY-DROP", "smtp").
func SplitPrefix(p string) (kind, detail string) {
	p = strings.TrimSpace(p)
	kind, detail, _ = strings.Cut(p, ":")
	return strings.TrimSpace(kind), strings.TrimSpace(detail)
}

// BuildRecord renders an event. The connection initiator is the packet
// source for every OpenPicket log rule: DNAT misses and policy drops are
// new inbound connections, egress logs are new outbound ones.
func BuildRecord(ev Event, rid string, nets *direction.Nets) []byte {
	p := ev.Packet
	kind, detail := SplitPrefix(ev.Prefix)
	res := direction.Judge(nets, direction.Packet{SrcIP: p.Src.String(), DestIP: p.Dst.String(), SrcIsInitiator: true})
	l := line{
		Timestamp: ev.Time.Format("2006-01-02T15:04:05.000000-0700"), EventType: record.TypeNflog,
		Prefix: kind, Detail: detail, Group: ev.Group, InIface: ev.InIface, OutIface: ev.OutIface,
		IPVersion: p.IPVersion, Proto: p.Proto, SrcIP: p.Src.String(), SrcPort: p.SrcPort, DestIP: p.Dst.String(), DestPort: p.DstPort,
		TCPFlags: p.TCPFlags, TTL: p.TTL, PktLen: p.Length, Count: ev.Count,
		Tag: &record.Tag{RID: rid, Direction: res.Direction, Confidence: res.Confidence, RemoteIP: res.RemoteIP, LocalIP: res.LocalIP},
	}
	if p.Proto == "ICMP" || p.Proto == "IPv6-ICMP" {
		t := p.ICMPType
		l.ICMPType = &t
	}
	b, _ := json.Marshal(l)
	return b
}

// Output receives records (the data plane shipper).
type Output interface {
	Push(ctx context.Context, typ string, recs []*dataplanev1.Record, dropped uint64) bool
	NextMemoryRID() string
}

// Config configures a Source.
type Config struct {
	Groups []uint16
	// AggregateWindow merges events with the same prefix, source, protocol
	// and destination port; 0 sends every event.
	AggregateWindow time.Duration
	Nets            func() *direction.Nets
	Output          Output
	Logger          *slog.Logger
	// Open opens a group (tests); default netlink.
	Open func(group uint16) (Receiver, error)
}

// Receiver delivers the events of one group until ctx is cancelled.
type Receiver interface {
	Receive(ctx context.Context, fn func(Event)) error
	Close() error
}

// Source collects NFLOG events.
type Source struct {
	cfg    Config
	log    *slog.Logger
	events chan Event

	mu      sync.Mutex
	dropped uint64
	counts  map[string]uint64
	lastErr string
}

// New creates a source.
func New(cfg Config) *Source {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Nets == nil {
		cfg.Nets = func() *direction.Nets { return nil }
	}
	s := &Source{cfg: cfg, log: cfg.Logger.With("component", "nflog"), events: make(chan Event, 4096), counts: map[string]uint64{}}
	if s.cfg.Open == nil {
		s.cfg.Open = func(group uint16) (Receiver, error) { return openNetlink(group, s.countDrop) }
	}
	return s
}

func (s *Source) countDrop() {
	s.mu.Lock()
	s.dropped++
	s.mu.Unlock()
}

// Status returns per-prefix counters and the last error.
func (s *Source) Status() *dataplanev1.NflogStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &dataplanev1.NflogStatus{Enabled: true, Records: map[string]uint64{}, LastError: s.lastErr}
	for k, v := range s.counts {
		st.Records[k] = v
	}
	return st
}

func (s *Source) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.lastErr = ""
	} else {
		s.lastErr = err.Error()
	}
}

// Run receives on every group and ships records until ctx is cancelled.
func (s *Source) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, g := range s.cfg.Groups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.receive(ctx, g)
		}()
	}
	s.ship(ctx)
	wg.Wait()
}

func (s *Source) receive(ctx context.Context, group uint16) {
	for ctx.Err() == nil {
		r, err := s.cfg.Open(group)
		if err != nil {
			s.setErr(err)
			s.log.Warn("cannot open NFLOG group (kmod-nfnetlink-log missing, or the group is used by another program)", "group", group, "err", err)
		} else {
			s.setErr(nil)
			err = r.Receive(ctx, func(ev Event) {
				select {
				case s.events <- ev:
				default:
					s.mu.Lock()
					s.dropped++
					s.mu.Unlock()
				}
			})
			r.Close()
			if err != nil && ctx.Err() == nil {
				s.setErr(err)
				s.log.Warn("NFLOG receive", "group", group, "err", err)
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
		}
	}
}

type aggKey struct {
	prefix, src, proto string
	dport              int
}

// ship batches events (every second, or 500 events) and pushes them.
func (s *Source) ship(ctx context.Context) {
	var pending []Event
	agg := map[aggKey]*Event{}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	windowEnd := time.Now().Add(s.cfg.AggregateWindow)
	flush := func() {
		if len(agg) > 0 && !time.Now().Before(windowEnd) {
			for _, ev := range agg {
				pending = append(pending, *ev)
			}
			clear(agg)
			windowEnd = time.Now().Add(s.cfg.AggregateWindow)
		}
		if len(pending) == 0 {
			return
		}
		nets := s.cfg.Nets()
		recs := make([]*dataplanev1.Record, 0, len(pending))
		s.mu.Lock()
		for _, ev := range pending {
			kind, _ := SplitPrefix(ev.Prefix)
			s.counts[kind] += uint64(max(ev.Count, 1))
		}
		dropped := s.dropped
		s.dropped = 0
		s.mu.Unlock()
		for _, ev := range pending {
			rid := s.cfg.Output.NextMemoryRID()
			recs = append(recs, &dataplanev1.Record{Line: BuildRecord(ev, rid, nets), Rid: rid, TimeUnixNano: ev.Time.UnixNano()})
		}
		pending = pending[:0]
		if !s.cfg.Output.Push(ctx, record.TypeNflog, recs, dropped) && ctx.Err() == nil {
			s.log.Warn("nflog records dropped: data plane window full", "records", len(recs))
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-s.events:
			if s.cfg.AggregateWindow > 0 {
				k := aggKey{ev.Prefix, ev.Packet.Src.String(), ev.Packet.Proto, ev.Packet.DstPort}
				if a, ok := agg[k]; ok {
					a.Count++
				} else {
					ev.Count = 1
					agg[k] = &ev
				}
				continue
			}
			pending = append(pending, ev)
			if len(pending) >= 500 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// netlinkReceiver reads one NFLOG group.
type netlinkReceiver struct {
	nf     *gonflog.Nflog
	group  uint16
	onDrop func()
}

func openNetlink(group uint16, onDrop func()) (Receiver, error) {
	nf, err := gonflog.Open(&gonflog.Config{Group: group, Copymode: gonflog.CopyPacket, Bufsize: 128})
	if err != nil {
		return nil, err
	}
	_ = nf.Con.SetReadBuffer(1 << 20)
	return &netlinkReceiver{nf: nf, group: group, onDrop: onDrop}, nil
}

func ifName(idx *uint32) string {
	if idx == nil {
		return ""
	}
	ifc, err := net.InterfaceByIndex(int(*idx))
	if err != nil {
		return ""
	}
	return ifc.Name
}

func (r *netlinkReceiver) Receive(ctx context.Context, fn func(Event)) error {
	errc := make(chan error, 1)
	hook := func(a gonflog.Attribute) int {
		if a.Payload == nil {
			return 0
		}
		p, err := ParsePacket(*a.Payload)
		if err != nil {
			return 0
		}
		ev := Event{Time: time.Now(), Group: int(r.group), Packet: p, InIface: ifName(a.InDev), OutIface: ifName(a.OutDev)}
		if a.Timestamp != nil && !a.Timestamp.IsZero() {
			ev.Time = *a.Timestamp
		}
		if a.Prefix != nil {
			ev.Prefix = *a.Prefix
		}
		fn(ev)
		return 0
	}
	onErr := func(err error) int {
		// The socket buffer overflowed during a burst: packets were lost,
		// the socket still works.
		if errors.Is(err, syscall.ENOBUFS) {
			if r.onDrop != nil {
				r.onDrop()
			}
			return 0
		}
		select {
		case errc <- err:
		default:
		}
		return 1
	}
	if err := r.nf.RegisterWithErrorFunc(ctx, hook, onErr); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

func (r *netlinkReceiver) Close() error { return r.nf.Close() }
