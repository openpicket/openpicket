// Package dataplane is the agent side of channel B: the session with
// openpicket-manager that carries logs, status, decisions and port
// policies.
package dataplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/noiseconn"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/dpwire"
)

// RejectedError reports that the manager refused the agent. It arrives in
// Noise message 2, so ServerTime can be trusted to correct the clock.
type RejectedError struct {
	Reason     dataplanev1.RejectReason
	Message    string
	ServerTime time.Time
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("manager rejected agent: %s %s", e.Reason, e.Message)
}

// DialConfig configures one connection attempt.
type DialConfig struct {
	URL        string
	Headers    http.Header
	HTTPClient *http.Client
	Key        *sshkey.PrivateKey
	ServerKey  *sshkey.PublicKey
	NodeID     string
	Version    string
	Now        func() time.Time
}

// Session is an established channel B session.
type Session struct {
	ws       *websocket.Conn
	mux      *yamux.Session
	ctrl     *wire.MsgStream
	helloAck *dataplanev1.HelloAck
	cancel   context.CancelFunc
}

// Dial connects, authenticates and exchanges Hello/HelloAck.
func Dial(ctx context.Context, cfg DialConfig, hello *dataplanev1.Hello) (*Session, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	serverX, err := cfg.ServerKey.X25519()
	if err != nil {
		return nil, err
	}
	static, err := noiseconn.KeyPair(cfg.Key.X25519())
	if err != nil {
		return nil, err
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()
	ws, _, err := websocket.Dial(dialCtx, cfg.URL, &websocket.DialOptions{
		HTTPClient: client, HTTPHeader: cfg.Headers, Subprotocols: []string{dpwire.Subprotocol},
	})
	if err != nil {
		return nil, fmt.Errorf("dataplane: websocket dial: %w", err)
	}
	if ws.Subprotocol() != dpwire.Subprotocol {
		ws.Close(websocket.StatusPolicyViolation, "unsupported subprotocol")
		return nil, errors.New("dataplane: manager did not accept the subprotocol")
	}
	sessCtx, cancel := context.WithCancel(context.Background())
	s := &Session{ws: ws, cancel: cancel}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	ws.SetReadLimit(dpwire.MaxMessageSize + 1<<20)
	nc := websocket.NetConn(sessCtx, ws, websocket.MessageBinary)
	payload, _ := proto.Marshal(&dataplanev1.HandshakeInit{NodeId: cfg.NodeID, AgentVersion: cfg.Version, TimestampUnixMs: cfg.Now().UnixMilli()})
	resp := &dataplanev1.HandshakeResponse{}
	sc, _, err := noiseconn.Client(dialCtx, nc, noiseconn.ClientConfig{
		StaticKey: static, PeerStatic: serverX, Payload: payload, Prologue: dpwire.Prologue,
		Accepted: func(p []byte) bool { return proto.Unmarshal(p, resp) == nil && resp.Accepted },
	})
	if err != nil {
		if errors.Is(err, noiseconn.ErrRejected) {
			re := &RejectedError{Reason: resp.Reason, Message: resp.Message}
			if resp.ServerTimeUnixMs != 0 {
				re.ServerTime = time.UnixMilli(resp.ServerTimeUnixMs)
			}
			return nil, re
		}
		return nil, fmt.Errorf("dataplane: handshake: %w", err)
	}
	if s.mux, err = yamux.Client(sc, dpwire.YamuxConfig()); err != nil {
		return nil, err
	}
	if s.ctrl, err = dpwire.OpenStream(s.mux, dataplanev1.StreamType_STREAM_TYPE_CONTROL); err != nil {
		return nil, err
	}
	if err := s.ctrl.Send(&dataplanev1.ControlUp{Body: &dataplanev1.ControlUp_Hello{Hello: hello}}); err != nil {
		return nil, err
	}
	_ = s.ctrl.Conn().SetReadDeadline(time.Now().Add(30 * time.Second))
	down := &dataplanev1.ControlDown{}
	if err := s.ctrl.Recv(down); err != nil {
		return nil, fmt.Errorf("dataplane: read hello ack: %w", err)
	}
	_ = s.ctrl.Conn().SetReadDeadline(time.Time{})
	if s.helloAck = down.GetHelloAck(); s.helloAck == nil {
		return nil, errors.New("dataplane: expected HelloAck")
	}
	ok = true
	return s, nil
}

// HelloAck returns the manager's answer to Hello.
func (s *Session) HelloAck() *dataplanev1.HelloAck { return s.helloAck }

// Open opens a stream of the given type.
func (s *Session) Open(t dataplanev1.StreamType) (*wire.MsgStream, error) {
	return dpwire.OpenStream(s.mux, t)
}

// Close ends the session.
func (s *Session) Close() {
	s.cancel()
	if s.mux != nil {
		s.mux.Close()
	}
	_ = s.ws.CloseNow()
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.mux.CloseChan() }

// Handlers are the agent components fed by the session.
type Handlers struct {
	// Hello builds the Hello for a new session.
	Hello func() *dataplanev1.Hello
	// Status builds a status report.
	Status func(ctx context.Context) *dataplanev1.Status
	// LogPolicy receives the collection policy from the manager.
	LogPolicy func(*agentv1.LogCollectionPolicy)
	Shipper   *Shipper
	// Decisions and Policy may be nil (feature disabled on the node).
	Decisions DecisionSink
	Policy    PolicySink
}

// Client keeps a session with the manager and runs the streams on it.
type Client struct {
	cfg DialConfig
	h   Handlers
	log *slog.Logger

	mu          sync.Mutex
	clockOffset time.Duration
	connected   bool
	statusNow   chan struct{}
}

// NewClient creates a client.
func NewClient(cfg DialConfig, h Handlers, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{cfg: cfg, h: h, log: log.With("component", "dataplane"), statusNow: make(chan struct{}, 1)}
}

// Connected reports whether a session is up.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// PokeStatus asks for an immediate status report.
func (c *Client) PokeStatus() {
	select {
	case c.statusNow <- struct{}{}:
	default:
	}
}

func jitter(d time.Duration) time.Duration { return d/2 + time.Duration(rand.Int64N(int64(d))) }

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Run connects and reconnects until ctx is cancelled.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		cfg := c.cfg
		c.mu.Lock()
		offset := c.clockOffset
		c.mu.Unlock()
		cfg.Now = func() time.Time { return time.Now().Add(offset) }
		sess, err := Dial(ctx, cfg, c.h.Hello())
		if err != nil {
			var re *RejectedError
			switch {
			case errors.As(err, &re) && re.Reason == dataplanev1.RejectReason_REJECT_REASON_CLOCK_SKEW && !re.ServerTime.IsZero():
				c.mu.Lock()
				c.clockOffset = time.Until(re.ServerTime)
				c.mu.Unlock()
				c.log.Warn("local clock differs from the manager; correcting handshake time", "offset", time.Until(re.ServerTime).Round(time.Second))
				sleep(ctx, time.Second)
				continue
			case errors.As(err, &re) && re.Reason == dataplanev1.RejectReason_REJECT_REASON_UNAVAILABLE:
				c.log.Warn("manager cannot check this agent right now", "retry_in", backoff)
			case errors.As(err, &re):
				c.log.Error("manager rejected this agent", "reason", re.Reason.String())
				backoff = max(backoff, 30*time.Second)
			default:
				c.log.Warn("connect to manager failed", "err", err, "retry_in", backoff)
			}
			sleep(ctx, jitter(backoff))
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		c.log.Info("connected to manager", "url", c.cfg.URL, "manager_version", sess.HelloAck().ManagerVersion)
		c.serve(ctx, sess)
		if ctx.Err() == nil {
			c.log.Warn("disconnected from manager")
			sleep(ctx, jitter(time.Second))
		}
	}
}

// serve runs all streams of one session until any of them fails.
func (c *Client) serve(ctx context.Context, sess *Session) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer sess.Close()
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()
	}()
	if p := sess.HelloAck().GetLogPolicy(); p != nil && c.h.LogPolicy != nil {
		c.h.LogPolicy(p)
	}
	var wg sync.WaitGroup
	run := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			if err := fn(ctx); err != nil && ctx.Err() == nil {
				c.log.Debug("stream ended", "stream", name, "err", err)
			}
		}()
	}
	run("control", func(ctx context.Context) error { return c.control(ctx, sess) })
	if c.h.Shipper != nil {
		run("logs", func(ctx context.Context) error {
			ms, err := sess.Open(dataplanev1.StreamType_STREAM_TYPE_LOGS)
			if err != nil {
				return err
			}
			return c.h.Shipper.Serve(ctx, ms)
		})
	}
	if c.h.Decisions != nil {
		run("decisions", func(ctx context.Context) error { return serveDecisions(ctx, sess, c.h.Decisions, c.log) })
	}
	if c.h.Policy != nil {
		run("policy", func(ctx context.Context) error { return servePolicy(ctx, sess, c.h.Policy, c.log) })
	}
	select {
	case <-ctx.Done():
	case <-sess.Done():
	}
	cancel()
	sess.Close()
	wg.Wait()
}

// control sends status reports and receives policy updates.
func (c *Client) control(ctx context.Context, sess *Session) error {
	interval := time.Duration(sess.HelloAck().StatusIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	stop := context.AfterFunc(ctx, func() { sess.ctrl.Close() })
	defer stop()
	go func() {
		for {
			down := &dataplanev1.ControlDown{}
			if err := sess.ctrl.Recv(down); err != nil {
				sess.Close()
				return
			}
			if p := down.GetLogPolicy(); p != nil && c.h.LogPolicy != nil {
				c.h.LogPolicy(p)
			}
		}
	}()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if c.h.Status != nil {
			if err := sess.ctrl.Send(&dataplanev1.ControlUp{Body: &dataplanev1.ControlUp_Status{Status: c.h.Status(ctx)}}); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		case <-c.statusNow:
		}
	}
}
