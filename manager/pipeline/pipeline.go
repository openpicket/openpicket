// Package pipeline delivers agent log batches to the sinks
// (docs/ARCHITECTURE.md §4.2).
//
// Each session's batches are processed in order. A batch is acknowledged to
// the agent once every acknowledgement sink (Loki, CrowdSec) has it, or has
// an open circuit. While the session lives the pipeline itself retries only
// the sinks that failed, so a batch never reaches a sink twice; after a
// replica change, per-sink watermarks skip what the previous replica had
// delivered. Asynchronous sinks (OpenSearch) get the batch after the ack.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"

	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/manager/registry"
	"github.com/openpicket/openpicket/pkg/record"
	"github.com/openpicket/openpicket/pkg/syslogfmt"
)

// ErrPermanent marks a delivery error that retrying cannot fix (the sink
// rejected the data). The batch counts as done for that sink.
var ErrPermanent = errors.New("pipeline: permanent delivery failure")

// Geo is the location of an address (from the uploaded MaxMind databases).
type Geo struct {
	Country string `json:"cc,omitempty"`
	ASN     uint32 `json:"asn,omitempty"`
	ASOrg   string `json:"as_org,omitempty"`
}

// GeoLookup resolves addresses; it may be nil or return nil.
type GeoLookup interface {
	Lookup(ip string) *Geo
}

// Record is one log line of a batch.
type Record struct {
	Line []byte
	RID  string
	Time time.Time
	// Eve is the decoded line for JSON types (nil otherwise or when the
	// line is not valid JSON).
	Eve *record.Eve
	// EventType is the eve event_type (or "nflog").
	EventType       string
	SrcGeo, DestGeo *Geo
	// Program and Message of a generic log line: the batch's program, or
	// for syslog lines (program "syslog": auth.log, received messages)
	// the one in the line's header and the text after it.
	Program, Message string
}

// ProgramSyslog marks generic log lines in syslog format.
const ProgramSyslog = "syslog"

// Batch is a decoded LogBatch with its manager-side enrichment.
type Batch struct {
	NodeID, BootID string
	Seq            uint64
	Type, Instance string
	// Program wrote the lines of a generic log (type "log"), normalized.
	Program  string
	Node     *registry.Node
	Received time.Time
	Records  []*Record
	Dropped  uint64
	// NoWatermarks marks a batch without an agent behind it (syslog): it
	// is delivered at most once, nothing records its sequence.
	NoWatermarks bool

	state sync.Map
}

// State returns per-sink scratch data that survives retries of the batch
// (e.g. which shards were already delivered).
func (b *Batch) State(sink string, init func() any) any {
	v, _ := b.state.LoadOrStore(sink, init())
	return v
}

// ProgramCounter records the programs of generic logs.
type ProgramCounter interface {
	Seen(nodeID, program string, lines int)
}

// Sink delivers batches.
type Sink interface {
	Name() string
	// Deliver sends the batch. Errors are retried unless they wrap
	// ErrPermanent.
	Deliver(ctx context.Context, b *Batch) error
}

// Config configures a Pipeline.
type Config struct {
	// AckSinks must have a batch before it is acknowledged.
	AckSinks []Sink
	// AsyncSinks get batches after the acknowledgement (best effort).
	AsyncSinks []Sink
	// AsyncQueue bounds each async sink's queue (batches).
	AsyncQueue int
	Watermarks *Watermarks
	Geo        GeoLookup
	// Programs counts the generic log lines per node and program.
	Programs   ProgramCounter
	Logger     *slog.Logger
	Registerer prometheus.Registerer
	// OpenAfter opens a sink's circuit after this much continuous failure
	// (default 30s). An open circuit no longer holds acknowledgements.
	OpenAfter time.Duration
	// ProbeInterval is how often an open circuit is probed (default 5s).
	ProbeInterval time.Duration
	RetryMin      time.Duration
	RetryMax      time.Duration
	Now           func() time.Time
}

// Pipeline processes log streams.
type Pipeline struct {
	cfg      Config
	log      *slog.Logger
	breakers map[string]*Breaker
	async    []*asyncQueue
	m        *metrics
	dec      *zstd.Decoder

	// drainCtx is cancelled by Drain; active counts batches in Process.
	drainCtx context.Context
	drain    context.CancelFunc
	active   sync.WaitGroup
}

// New creates a pipeline. Start the async sinks with Run.
func New(cfg Config) *Pipeline {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.OpenAfter <= 0 {
		cfg.OpenAfter = 30 * time.Second
	}
	if cfg.ProbeInterval <= 0 {
		cfg.ProbeInterval = 5 * time.Second
	}
	if cfg.RetryMin <= 0 {
		cfg.RetryMin = 500 * time.Millisecond
	}
	if cfg.RetryMax <= 0 {
		cfg.RetryMax = 10 * time.Second
	}
	if cfg.AsyncQueue <= 0 {
		cfg.AsyncQueue = 1000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	dec, _ := zstd.NewReader(nil, zstd.WithDecoderConcurrency(0), zstd.WithDecoderMaxMemory(256<<20))
	p := &Pipeline{cfg: cfg, log: cfg.Logger.With("component", "pipeline"), breakers: map[string]*Breaker{}, m: newMetrics(cfg.Registerer), dec: dec}
	p.drainCtx, p.drain = context.WithCancel(context.Background())
	for _, s := range cfg.AckSinks {
		p.breakers[s.Name()] = NewBreaker(cfg.OpenAfter, cfg.ProbeInterval, cfg.Now)
		p.m.circuitOpen.WithLabelValues(s.Name()).Set(0)
	}
	for _, s := range cfg.AsyncSinks {
		p.async = append(p.async, newAsyncQueue(s, cfg.AsyncQueue, p.log, p.m))
	}
	return p
}

// Run runs the async sink workers until ctx is cancelled.
func (p *Pipeline) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, q := range p.async {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q.run(ctx)
		}()
	}
	wg.Wait()
}

// Breaker returns the circuit breaker of an acknowledgement sink.
func (p *Pipeline) Breaker(sink string) *Breaker { return p.breakers[sink] }

// Drain stops processing for a graceful shutdown: batches in progress are
// abandoned (not acknowledged) and no new batch is taken, while the
// sessions stay open. When Drain returns, every delivery has been recorded
// in the watermarks, so flushing them before closing the sessions lets the
// next replica skip exactly what this one delivered.
func (p *Pipeline) Drain() {
	p.drain()
	p.active.Wait()
}

// Serve processes the log stream of a session until it ends.
func (p *Pipeline) Serve(ctx context.Context, node *registry.Node, ms *wire.MsgStream) error {
	for {
		lb := &dataplanev1.LogBatch{}
		if err := ms.Recv(lb); err != nil {
			return err
		}
		ok, err := p.handle(ctx, node, lb)
		if err != nil {
			return err
		}
		if !ok {
			// Draining: keep the stream open until the session closes, so
			// the agent does not reconnect before the watermarks are saved.
			<-ctx.Done()
			return ctx.Err()
		}
		if err := ms.Send(&dataplanev1.LogAck{BootId: lb.BootId, Seq: lb.Seq}); err != nil {
			return err
		}
	}
}

// handle processes one received batch. It reports false while draining.
func (p *Pipeline) handle(ctx context.Context, node *registry.Node, lb *dataplanev1.LogBatch) (bool, error) {
	p.active.Add(1)
	defer p.active.Done()
	if p.drainCtx.Err() != nil {
		return false, nil
	}
	b, err := p.decode(node, lb)
	if err != nil {
		// A batch that cannot be decoded will never decode: acknowledge it
		// so the agent does not resend it forever.
		p.log.Warn("drop undecodable batch", "node", node.ID, "seq", lb.Seq, "err", err)
		p.m.badBatches.Inc()
		return true, nil
	}
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(p.drainCtx, cancel)
	defer stop()
	if err := p.Process(pctx, b); err != nil {
		if ctx.Err() == nil && p.drainCtx.Err() != nil {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (p *Pipeline) decode(node *registry.Node, lb *dataplanev1.LogBatch) (*Batch, error) {
	raw, err := p.dec.DecodeAll(lb.ZstdRecords, nil)
	if err != nil {
		return nil, err
	}
	var list dataplanev1.RecordList
	if err := proto.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	b := &Batch{
		NodeID: node.ID, BootID: lb.BootId, Seq: lb.Seq, Type: lb.Type, Instance: lb.Instance,
		Node: node, Received: p.cfg.Now(), Dropped: lb.DroppedSinceLast,
	}
	if lb.Type == record.TypeLog {
		if b.Program = record.NormalizeProgram(lb.Program); b.Program == "" {
			b.Program = "unknown"
		}
	}
	jsonType := record.IsJSON(lb.Type)
	for _, r := range list.Records {
		rec := &Record{Line: r.Line, RID: r.Rid, Time: time.Unix(0, r.TimeUnixNano)}
		if r.TimeUnixNano == 0 {
			rec.Time = b.Received
		}
		if jsonType {
			if e, err := record.ParseEve(r.Line); err == nil {
				rec.Eve = e
				rec.EventType = e.EventType
				if p.cfg.Geo != nil {
					rec.SrcGeo, rec.DestGeo = p.cfg.Geo.Lookup(e.SrcIP), p.cfg.Geo.Lookup(e.DestIP)
				}
			}
		}
		if b.Program != "" {
			rec.Program, rec.Message = b.Program, string(r.Line)
			if b.Program == ProgramSyslog {
				if m, ok := syslogfmt.Parse(string(r.Line), rec.Time); ok {
					if prog := record.NormalizeProgram(m.Program); prog != "" {
						rec.Program, rec.Message = prog, m.Message
					}
				}
			}
		}
		b.Records = append(b.Records, rec)
	}
	p.ingested(b)
	if lb.DroppedSinceLast > 0 {
		p.m.agentDropped.WithLabelValues(node.ID).Add(float64(lb.DroppedSinceLast))
	}
	return b, nil
}

// ingested counts a decoded batch and its programs.
func (p *Pipeline) ingested(b *Batch) {
	if b.Program != "" && p.cfg.Programs != nil {
		counts := map[string]int{}
		for _, r := range b.Records {
			counts[r.Program]++
		}
		for prog, n := range counts {
			p.cfg.Programs.Seen(b.NodeID, prog, n)
		}
	}
	p.m.ingested.WithLabelValues(b.Type).Add(float64(len(b.Records)))
}

// Ingest processes a batch received without an agent behind it (syslog):
// it is delivered at most once, without watermarks. Generic log records
// carry their Program and Message. It reports false while draining.
func (p *Pipeline) Ingest(ctx context.Context, b *Batch) (bool, error) {
	p.active.Add(1)
	defer p.active.Done()
	if p.drainCtx.Err() != nil {
		return false, nil
	}
	b.NoWatermarks = true
	p.ingested(b)
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(p.drainCtx, cancel)
	defer stop()
	if err := p.Process(pctx, b); err != nil {
		if ctx.Err() == nil && p.drainCtx.Err() != nil {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Process delivers a batch to every acknowledgement sink (in parallel), then
// queues it for the async sinks. It returns only when the batch may be
// acknowledged, or ctx's error.
func (p *Pipeline) Process(ctx context.Context, b *Batch) error {
	start := p.cfg.Now()
	var wg sync.WaitGroup
	errs := make([]error, len(p.cfg.AckSinks))
	for i, s := range p.cfg.AckSinks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = p.deliver(ctx, s, b)
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	p.m.ackLatency.Observe(p.cfg.Now().Sub(start).Seconds())
	for _, q := range p.async {
		q.push(b)
	}
	return nil
}

// deliver retries one sink until it has the batch, its circuit opens, or
// ctx ends.
func (p *Pipeline) deliver(ctx context.Context, s Sink, b *Batch) error {
	name := s.Name()
	watermarks := p.cfg.Watermarks != nil && !b.NoWatermarks
	if watermarks && b.Seq <= p.cfg.Watermarks.Get(ctx, b.NodeID, b.BootID, name) {
		// Delivered by a previous session (possibly on another replica).
		p.m.skipped.WithLabelValues(name).Add(float64(len(b.Records)))
		return nil
	}
	br := p.breakers[name]
	wait := p.cfg.RetryMin
	for {
		if !br.Allow() {
			p.m.gap.WithLabelValues(name).Add(float64(len(b.Records)))
			return nil
		}
		t0 := p.cfg.Now()
		err := s.Deliver(ctx, b)
		p.m.sinkLatency.WithLabelValues(name).Observe(p.cfg.Now().Sub(t0).Seconds())
		if err == nil || errors.Is(err, ErrPermanent) {
			br.Success()
			p.m.circuitOpen.WithLabelValues(name).Set(0)
			if err != nil {
				p.log.Warn("sink rejected batch", "sink", name, "node", b.NodeID, "seq", b.Seq, "err", err)
				p.m.rejected.WithLabelValues(name).Add(float64(len(b.Records)))
			}
			if watermarks {
				p.cfg.Watermarks.Set(b.NodeID, b.BootID, name, b.Seq)
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p.m.sinkErrors.WithLabelValues(name).Inc()
		if br.Failure() {
			p.log.Error("sink circuit opened: batches are acknowledged without it", "sink", name, "err", err)
			p.m.circuitOpen.WithLabelValues(name).Set(1)
		} else {
			p.log.Warn("sink delivery failed; retrying", "sink", name, "node", b.NodeID, "seq", b.Seq, "err", err, "retry_in", wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, p.cfg.RetryMax)
	}
}

// Breaker is a sink's circuit: closed while the sink works, open after it
// failed continuously for OpenAfter. While open, one caller every
// ProbeInterval tries the sink; others skip it.
type Breaker struct {
	openAfter, probeEvery time.Duration
	now                   func() time.Time

	mu           sync.Mutex
	failingSince time.Time
	open         bool
	lastProbe    time.Time
}

// NewBreaker creates a closed breaker.
func NewBreaker(openAfter, probeEvery time.Duration, now func() time.Time) *Breaker {
	return &Breaker{openAfter: openAfter, probeEvery: probeEvery, now: now}
}

// Allow reports whether to try the sink now.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return true
	}
	if n := b.now(); n.Sub(b.lastProbe) >= b.probeEvery {
		b.lastProbe = n
		return true
	}
	return false
}

// Success closes the breaker.
func (b *Breaker) Success() {
	b.mu.Lock()
	b.failingSince, b.open = time.Time{}, false
	b.mu.Unlock()
}

// Failure records a failure and reports whether the breaker just opened.
func (b *Breaker) Failure() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := b.now()
	if b.failingSince.IsZero() {
		b.failingSince = n
	}
	if !b.open && n.Sub(b.failingSince) >= b.openAfter {
		b.open, b.lastProbe = true, n
		return true
	}
	return false
}

// Open reports whether the breaker is open.
func (b *Breaker) Open() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open
}

// asyncQueue feeds one async sink; when full it drops the oldest batch.
type asyncQueue struct {
	sink Sink
	log  *slog.Logger
	m    *metrics
	mu   sync.Mutex
	q    []*Batch
	max  int
	wake chan struct{}
}

func newAsyncQueue(s Sink, max int, log *slog.Logger, m *metrics) *asyncQueue {
	return &asyncQueue{sink: s, max: max, log: log, m: m, wake: make(chan struct{}, 1)}
}

func (a *asyncQueue) push(b *Batch) {
	a.mu.Lock()
	if len(a.q) >= a.max {
		a.m.gap.WithLabelValues(a.sink.Name()).Add(float64(len(a.q[0].Records)))
		a.q = a.q[1:]
	}
	a.q = append(a.q, b)
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (a *asyncQueue) run(ctx context.Context) {
	wait := 500 * time.Millisecond
	for {
		a.mu.Lock()
		var b *Batch
		if len(a.q) > 0 {
			b = a.q[0]
		}
		a.mu.Unlock()
		if b == nil {
			select {
			case <-ctx.Done():
				return
			case <-a.wake:
			}
			continue
		}
		err := a.sink.Deliver(ctx, b)
		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, ErrPermanent) {
			a.m.sinkErrors.WithLabelValues(a.sink.Name()).Inc()
			a.log.Warn("async sink delivery failed; retrying", "sink", a.sink.Name(), "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(wait*2, 30*time.Second)
			continue
		}
		wait = 500 * time.Millisecond
		a.mu.Lock()
		if len(a.q) > 0 && a.q[0] == b {
			a.q = a.q[1:]
		}
		a.mu.Unlock()
	}
}

type metrics struct {
	ingested     *prometheus.CounterVec
	agentDropped *prometheus.CounterVec
	badBatches   prometheus.Counter
	ackLatency   prometheus.Histogram
	sinkLatency  *prometheus.HistogramVec
	sinkErrors   *prometheus.CounterVec
	circuitOpen  *prometheus.GaugeVec
	gap          *prometheus.CounterVec
	rejected     *prometheus.CounterVec
	skipped      *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		ingested:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openpicket_ingest_records_total", Help: "Log records received from agents."}, []string{"type"}),
		agentDropped: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openpicket_node_log_dropped_total", Help: "Records dropped by agent queues."}, []string{"node"}),
		badBatches:   prometheus.NewCounter(prometheus.CounterOpts{Name: "openpicket_ingest_bad_batches_total", Help: "Batches that could not be decoded."}),
		ackLatency:   prometheus.NewHistogram(prometheus.HistogramOpts{Name: "openpicket_ack_latency_seconds", Help: "Time from receiving a batch to acknowledging it.", Buckets: prometheus.ExponentialBuckets(0.005, 2, 14)}),
		sinkLatency:  prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "openpicket_sink_latency_seconds", Help: "Sink delivery latency.", Buckets: prometheus.ExponentialBuckets(0.005, 2, 14)}, []string{"sink"}),
		sinkErrors:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openpicket_sink_errors_total", Help: "Failed sink deliveries."}, []string{"sink"}),
		circuitOpen:  prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "openpicket_sink_circuit_open", Help: "1 while the sink's circuit is open."}, []string{"sink"}),
		gap:          prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openpicket_sink_gap_records_total", Help: "Records a sink missed (open circuit or full queue)."}, []string{"sink"}),
		rejected:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openpicket_sink_rejected_records_total", Help: "Records in batches a sink rejected permanently."}, []string{"sink"}),
		skipped:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openpicket_sink_skipped_records_total", Help: "Records of resent batches a sink already had (watermark)."}, []string{"sink"}),
	}
	if reg != nil {
		for _, c := range []prometheus.Collector{m.ingested, m.agentDropped, m.badBatches, m.ackLatency, m.sinkLatency, m.sinkErrors, m.circuitOpen, m.gap, m.rejected, m.skipped} {
			if err := reg.Register(c); err != nil {
				panic(fmt.Sprintf("pipeline metrics: %v", err))
			}
		}
	}
	return m
}
