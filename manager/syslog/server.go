package syslog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/pkg/record"
	"github.com/openpicket/openpicket/pkg/syslogfmt"
)

// MaxLine bounds a message, as the agents bound a log line.
const MaxLine = 64 << 10

// Config configures a Server.
type Config struct {
	// UDP, TCP and TLS are listen addresses (":5514"); empty disables one.
	UDP, TCP, TLS string
	// TLSConfig holds the certificate (and client CAs) of the TLS listener.
	TLSConfig *tls.Config
	Devices   *Devices
	Sources   *Sources
	// Ingest hands a batch to the log pipeline (pipeline.Ingest).
	Ingest func(context.Context, *pipeline.Batch) (bool, error)
	// MaxConns bounds the TCP and TLS connections (default 1000).
	MaxConns int
	// IdleTimeout closes silent connections (default 10m).
	IdleTimeout time.Duration
	// FlushInterval and BatchLines bound how long and how many lines of
	// a device wait for a batch (default 1s, 1000).
	FlushInterval time.Duration
	BatchLines    int
	// Queue bounds the batches waiting for the pipeline (default 64);
	// beyond it batches are dropped.
	Queue      int
	Logger     *slog.Logger
	Registerer prometheus.Registerer
	Now        func() time.Time
}

// Server receives syslog.
type Server struct {
	cfg  Config
	log  *slog.Logger
	boot string
	seq  atomic.Uint64

	udp       *net.UDPConn
	tcp, tlsL net.Listener
	conns     chan struct{}

	mu      sync.Mutex
	pending map[string]*pipeline.Batch
	queue   chan *pipeline.Batch

	messages *prometheus.CounterVec
}

// New opens the listeners (so that a busy port fails the start).
func New(cfg Config) (*Server, error) {
	if cfg.Devices == nil || cfg.Sources == nil || cfg.Ingest == nil {
		return nil, errors.New("syslog: Devices, Sources and Ingest are required")
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 1000
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 10 * time.Minute
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	if cfg.BatchLines <= 0 {
		cfg.BatchLines = 1000
	}
	if cfg.Queue <= 0 {
		cfg.Queue = 64
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	s := &Server{cfg: cfg, log: cfg.Logger.With("component", "syslog"), boot: "syslog-" + hex.EncodeToString(b),
		conns: make(chan struct{}, cfg.MaxConns), pending: map[string]*pipeline.Batch{}, queue: make(chan *pipeline.Batch, cfg.Queue),
		messages: newMessages()}
	if cfg.Registerer != nil {
		if err := cfg.Registerer.Register(s.messages); err != nil {
			return nil, err
		}
	}
	var err error
	if cfg.UDP != "" {
		var a *net.UDPAddr
		if a, err = net.ResolveUDPAddr("udp", cfg.UDP); err == nil {
			s.udp, err = net.ListenUDP("udp", a)
		}
	}
	if err == nil && cfg.TCP != "" {
		s.tcp, err = net.Listen("tcp", cfg.TCP)
	}
	if err == nil && cfg.TLS != "" {
		if cfg.TLSConfig == nil {
			err = errors.New("the TLS listener needs a certificate")
		} else {
			s.tlsL, err = tls.Listen("tcp", cfg.TLS, cfg.TLSConfig)
		}
	}
	if err != nil {
		s.close()
		return nil, fmt.Errorf("syslog: %w", err)
	}
	return s, nil
}

func newMessages() *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{Name: "openpicket_syslog_messages_total",
		Help: "Syslog messages received, by result (accepted, unregistered, disabled, queue_full)."}, []string{"result"})
}

// Listeners describes the open listeners ("udp [::]:5514").
func (s *Server) Listeners() []string {
	var out []string
	if s.udp != nil {
		out = append(out, "udp "+s.udp.LocalAddr().String())
	}
	if s.tcp != nil {
		out = append(out, "tcp "+s.tcp.Addr().String())
	}
	if s.tlsL != nil {
		out = append(out, "tls "+s.tlsL.Addr().String())
	}
	return out
}

func (s *Server) close() {
	if s.udp != nil {
		s.udp.Close()
	}
	if s.tcp != nil {
		s.tcp.Close()
	}
	if s.tlsL != nil {
		s.tlsL.Close()
	}
}

// Run receives until ctx ends.
func (s *Server) Run(ctx context.Context) {
	var wg sync.WaitGroup
	start := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}
	if s.udp != nil {
		start(s.serveUDP)
	}
	if s.tcp != nil {
		start(func() { s.serveStream(ctx, s.tcp) })
	}
	if s.tlsL != nil {
		start(func() { s.serveStream(ctx, s.tlsL) })
	}
	start(func() { s.flushLoop(ctx) })
	for range 2 {
		start(func() { s.deliver(ctx) })
	}
	<-ctx.Done()
	s.close()
	wg.Wait()
}

func (s *Server) serveUDP() {
	buf := make([]byte, 65536)
	for {
		n, from, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		// One message per datagram; some senders pack lines.
		for line := range bytes.SplitSeq(buf[:n], []byte{'\n'}) {
			s.receive(from.Addr(), line)
		}
	}
}

func (s *Server) serveStream(ctx context.Context, l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("syslog accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case s.conns <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-s.conns }()
			s.serveConn(ctx, c)
		}()
	}
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	from, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	if tc, ok := c.(*tls.Conn); ok {
		_ = c.SetDeadline(s.cfg.Now().Add(10 * time.Second))
		if err := tc.HandshakeContext(ctx); err != nil {
			s.log.Debug("syslog TLS handshake", "from", from, "err", err)
			return
		}
		_ = c.SetDeadline(time.Time{})
	}
	r := &deadlineReader{c: c, idle: s.cfg.IdleTimeout}
	_ = ReadFrames(bufio.NewReaderSize(r, MaxLine+16), func(line []byte) { s.receive(from.Addr(), line) })
}

// deadlineReader extends the read deadline before each read.
type deadlineReader struct {
	c    net.Conn
	idle time.Duration
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	_ = d.c.SetReadDeadline(time.Now().Add(d.idle))
	return d.c.Read(p)
}

// ReadFrames calls fn with each message of a TCP stream: octet-counting
// framing ("LEN SP MSG") when a frame starts with a length, newline
// framing otherwise. Messages longer than MaxLine are cut.
func ReadFrames(r *bufio.Reader, fn func([]byte)) error {
	for {
		if _, err := r.Peek(1); err != nil {
			return err
		}
		if n, ok := octetCount(r); ok {
			msg := make([]byte, min(n, MaxLine))
			if _, err := io.ReadFull(r, msg); err != nil {
				return err
			}
			if n > MaxLine {
				if _, err := r.Discard(n - MaxLine); err != nil {
					return err
				}
			}
			fn(msg)
			continue
		}
		line, err := r.ReadSlice('\n')
		if len(line) > 0 {
			fn(bytes.Clone(line[:min(len(line), MaxLine)]))
		}
		// Skip the rest of a line longer than the buffer.
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = r.ReadSlice('\n')
		}
		if err != nil {
			return err
		}
	}
}

// octetCount reads a frame length ("123 ") when the stream starts with
// one, leaving the reader after the space. It peeks one byte past the
// digits only, so a newline-framed message is never waited for beyond its
// own bytes.
func octetCount(r *bufio.Reader) (int, bool) {
	for i := 0; i <= 6; i++ {
		head, err := r.Peek(i + 1)
		if err != nil {
			return 0, false
		}
		switch c := head[i]; {
		case c == ' ' && i > 0:
			n, err := strconv.Atoi(string(head[:i]))
			if err != nil || n == 0 {
				return 0, false
			}
			_, _ = r.Discard(i + 1)
			return n, true
		case c < '0' || c > '9':
			return 0, false
		}
	}
	return 0, false
}

// receive takes one message.
func (s *Server) receive(from netip.Addr, msg []byte) {
	msg = bytes.TrimRight(msg, "\r\n\x00")
	if len(bytes.TrimSpace(msg)) == 0 {
		return
	}
	if len(msg) > MaxLine {
		msg = msg[:MaxLine]
	}
	from = from.Unmap()
	now := s.cfg.Now()
	dev := s.cfg.Devices.Match(from)
	device := ""
	if dev != nil && dev.Registered {
		device = dev.ID
	}
	switch {
	case dev == nil:
		s.messages.WithLabelValues("unregistered").Inc()
		s.cfg.Sources.Seen(from, "", true, msg, now)
		return
	case !dev.Enabled:
		s.messages.WithLabelValues("disabled").Inc()
		s.cfg.Sources.Seen(from, device, true, msg, now)
		return
	}
	s.cfg.Sources.Seen(from, device, false, msg, now)
	line := string(msg)
	// The receive time, not the sender's clock: devices without NTP would
	// otherwise send lines Loki rejects.
	rec := &pipeline.Record{Line: []byte(line), RID: record.MemoryRID(s.boot, s.seq.Add(1)), Time: now}
	tag := ""
	if m, ok := syslogfmt.Parse(line, now); ok {
		tag = m.Program
	}
	// A line without a tag goes to CrowdSec as a plain line of the
	// device's default program.
	rec.Program = dev.Program(tag)
	if tag != "" {
		rec.Syslog, rec.ProgramOverride = true, dev.Programs[tag]
	}

	s.mu.Lock()
	b := s.pending[dev.ID]
	if b == nil {
		b = &pipeline.Batch{NodeID: dev.ID, BootID: s.boot, Type: record.TypeLog, Instance: "syslog", Program: pipeline.ProgramSyslog,
			Node: dev.Node(), Received: now}
		s.pending[dev.ID] = b
	}
	b.Records = append(b.Records, rec)
	full := len(b.Records) >= s.cfg.BatchLines
	if full {
		delete(s.pending, dev.ID)
	}
	s.mu.Unlock()
	if full {
		s.enqueue(b)
	}
	s.messages.WithLabelValues("accepted").Inc()
}

func (s *Server) enqueue(b *pipeline.Batch) {
	b.Seq = s.seq.Add(1)
	select {
	case s.queue <- b:
	default:
		s.messages.WithLabelValues("queue_full").Add(float64(len(b.Records)))
	}
}

func (s *Server) flushLoop(ctx context.Context) {
	t := time.NewTicker(s.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Flush()
		}
	}
}

// Flush queues the waiting lines.
func (s *Server) Flush() {
	s.mu.Lock()
	pending := s.pending
	s.pending = map[string]*pipeline.Batch{}
	s.mu.Unlock()
	for _, b := range pending {
		s.enqueue(b)
	}
}

func (s *Server) deliver(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-s.queue:
			if _, err := s.cfg.Ingest(ctx, b); err != nil && ctx.Err() == nil {
				s.log.Warn("syslog batch not delivered", "device", b.NodeID, "lines", len(b.Records), "err", err)
			}
		}
	}
}
