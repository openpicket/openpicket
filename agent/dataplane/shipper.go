package dataplane

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/jc-lab/suricontroller/agent/collector"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/direction"
	"github.com/openpicket/openpicket/pkg/record"
)

// Shipper moves log records to the manager with at-least-once delivery
// (docs/ARCHITECTURE.md §4.2).
//
// Batches stay in an in-flight window until the manager acknowledges them;
// only then are file positions committed in the collector. While a session
// is alive a batch is sent once; a new session resends the unacknowledged
// batches oldest first. When the window is full, the producers stop and the
// collector queue drops its oldest records.
type Shipper struct {
	nodeID      string
	bootID      string
	maxInflight int64
	log         *slog.Logger
	nets        func() *direction.Nets
	now         func() time.Time

	mu            sync.Mutex
	changed       chan struct{} // closed and replaced on every state change
	seq           uint64
	inflight      []*pending
	inflightBytes int64
	memCounter    uint64
	col           *collector.Collector
	policy        *agentv1.LogCollectionPolicy
	sent          uint64
	extraDropped  uint64

	enc *zstd.Encoder
}

type pending struct {
	seq   uint64
	msg   *dataplanev1.LogBatch
	batch *collector.Batch // nil for records not from the collector
	size  int64
}

// ShipperConfig configures a Shipper.
type ShipperConfig struct {
	NodeID string
	BootID string
	// MaxInflightBytes bounds the unacknowledged compressed batches.
	MaxInflightBytes int64
	// Nets returns the node's inside networks for direction judgement.
	Nets   func() *direction.Nets
	Logger *slog.Logger
}

// NewShipper creates a shipper.
func NewShipper(cfg ShipperConfig) *Shipper {
	if cfg.MaxInflightBytes <= 0 {
		cfg.MaxInflightBytes = 4 << 20
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Nets == nil {
		cfg.Nets = func() *direction.Nets { return nil }
	}
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest))
	return &Shipper{
		nodeID: cfg.NodeID, bootID: cfg.BootID, maxInflight: cfg.MaxInflightBytes,
		log: cfg.Logger.With("component", "shipper"), nets: cfg.Nets, now: time.Now,
		changed: make(chan struct{}), enc: enc,
	}
}

// BootID returns the id scoping this process's batch sequence numbers.
func (s *Shipper) BootID() string { return s.bootID }

func (s *Shipper) signalLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// SetPolicy sets the collection policy received from the manager.
func (s *Shipper) SetPolicy(p *agentv1.LogCollectionPolicy) {
	s.mu.Lock()
	s.policy = p
	col := s.col
	s.mu.Unlock()
	if col != nil {
		col.SetPolicy(p)
	}
}

// waitRoom blocks until the window has room or ctx ends.
func (s *Shipper) waitRoom(ctx context.Context) error {
	for {
		s.mu.Lock()
		room := s.inflightBytes < s.maxInflight
		ch := s.changed
		s.mu.Unlock()
		if room {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		}
	}
}

// ShipLogs implements agent.LogOutput: it moves collector batches into the
// window until ctx is cancelled.
func (s *Shipper) ShipLogs(ctx context.Context, c *collector.Collector) error {
	s.mu.Lock()
	s.col = c
	p := s.policy
	s.mu.Unlock()
	if p != nil {
		c.SetPolicy(p)
	}
	for {
		if err := s.waitRoom(ctx); err != nil {
			return nil
		}
		batches, err := c.Next(ctx, 2000, 512<<10)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		for _, b := range batches {
			if err := s.add(record.TypeName(b.Type), b.Instance, s.convert(b), b.Dropped, b); err != nil {
				s.log.Warn("drop batch", "err", err)
				c.Commit(b) // cannot be encoded; do not re-read it forever
			}
		}
	}
}

// Push queues records of an in-memory source (nflog). It blocks while the
// window is full and returns false if ctx ended first.
func (s *Shipper) Push(ctx context.Context, typ string, recs []*dataplanev1.Record, dropped uint64) bool {
	if err := s.waitRoom(ctx); err != nil {
		s.mu.Lock()
		s.extraDropped += uint64(len(recs))
		s.mu.Unlock()
		return false
	}
	if err := s.add(typ, "", recs, dropped, nil); err != nil {
		s.log.Warn("drop records", "type", typ, "err", err)
		return false
	}
	return true
}

// NextMemoryRID returns a record id for an in-memory source.
func (s *Shipper) NextMemoryRID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.memCounter++
	return record.MemoryRID(s.bootID, s.memCounter)
}

func (s *Shipper) add(typ, instance string, recs []*dataplanev1.Record, dropped uint64, b *collector.Batch) error {
	raw, err := proto.Marshal(&dataplanev1.RecordList{Records: recs})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z := s.enc.EncodeAll(raw, nil)
	s.seq++
	p := &pending{seq: s.seq, batch: b, size: int64(len(z)) + 64, msg: &dataplanev1.LogBatch{
		BootId: s.bootID, Seq: s.seq, Type: typ, Instance: instance, ZstdRecords: z,
		RecordCount: uint32(len(recs)), DroppedSinceLast: dropped,
	}}
	s.inflight = append(s.inflight, p)
	s.inflightBytes += p.size
	s.signalLocked()
	return nil
}

// convert turns collector records into wire records: record id, event time
// and, for eve alert/anomaly lines, the fixed direction tag.
func (s *Shipper) convert(b *collector.Batch) []*dataplanev1.Record {
	typ := record.TypeName(b.Type)
	now := s.now()
	nets := s.nets()
	out := make([]*dataplanev1.Record, 0, len(b.Records))
	for _, r := range b.Records {
		rec := &dataplanev1.Record{Line: r.Line, TimeUnixNano: now.UnixNano()}
		if r.Path != "" {
			rec.Rid = record.FileRID(s.nodeID, r.Path, r.Inode, r.Offset)
		} else {
			rec.Rid = s.NextMemoryRID()
		}
		if typ == record.TypeEve {
			if ts, ok := record.ParseTime(record.StringField(r.Line, "timestamp")); ok {
				rec.TimeUnixNano = ts.UnixNano()
			}
			switch record.StringField(r.Line, "event_type") {
			case "alert", "anomaly":
				rec.Line = tagEve(r.Line, rec.Rid, nets)
			}
		}
		out = append(out, rec)
	}
	return out
}

// tagEve appends the direction tag to an eve alert/anomaly line.
func tagEve(line []byte, rid string, nets *direction.Nets) []byte {
	e, err := record.ParseEve(line)
	if err != nil || e.OpenPicket != nil {
		return line
	}
	p := direction.Packet{SrcIP: e.SrcIP, DestIP: e.DestIP, PacketDirection: e.Direction}
	if e.Flow != nil {
		p.FlowSrcIP = e.Flow.SrcIP
	}
	res := direction.Judge(nets, p)
	return record.AppendTag(line, record.Tag{RID: rid, Direction: res.Direction, Confidence: res.Confidence, RemoteIP: res.RemoteIP, LocalIP: res.LocalIP})
}

// ack releases every batch with seq <= upTo and commits collector batches.
func (s *Shipper) ack(bootID string, upTo uint64) {
	if bootID != s.bootID {
		return
	}
	s.mu.Lock()
	n := 0
	var commit []*collector.Batch
	for n < len(s.inflight) && s.inflight[n].seq <= upTo {
		p := s.inflight[n]
		s.inflightBytes -= p.size
		s.sent += uint64(p.msg.RecordCount)
		if p.batch != nil {
			commit = append(commit, p.batch)
		}
		n++
	}
	if n == 0 {
		s.mu.Unlock()
		return
	}
	s.inflight = slices.Delete(s.inflight, 0, n)
	col := s.col
	s.signalLocked()
	s.mu.Unlock()
	for _, b := range commit {
		col.Commit(b)
	}
}

// Serve runs the log stream of one session: it sends every unacknowledged
// batch (oldest first, once per session) and processes acknowledgements.
func (s *Shipper) Serve(ctx context.Context, ms *wire.MsgStream) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { ms.Close() })
	defer stop()
	errc := make(chan error, 1)
	go func() {
		for {
			a := &dataplanev1.LogAck{}
			if err := ms.Recv(a); err != nil {
				errc <- err
				cancel()
				return
			}
			s.ack(a.BootId, a.Seq)
		}
	}()
	var lastSent uint64
	for {
		s.mu.Lock()
		var next *pending
		for _, p := range s.inflight {
			if p.seq > lastSent {
				next = p
				break
			}
		}
		ch := s.changed
		s.mu.Unlock()
		if next == nil {
			select {
			case <-ctx.Done():
				select {
				case err := <-errc:
					return err
				default:
					return ctx.Err()
				}
			case <-ch:
			}
			continue
		}
		if err := ms.Send(next.msg); err != nil {
			return err
		}
		lastSent = next.seq
	}
}

// Stats returns the window state for status reports.
func (s *Shipper) Stats() *dataplanev1.LogStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &dataplanev1.LogStats{
		InflightBatches: uint64(len(s.inflight)), InflightBytes: uint64(s.inflightBytes),
		SentRecords: s.sent, DroppedRecords: s.extraDropped,
	}
	if s.col != nil {
		cs := s.col.Stats()
		st.QueueBytes, st.QueueCapacityBytes = cs.Bytes, cs.CapacityBytes
		st.DroppedRecords += cs.DroppedRecords
	}
	return st
}
