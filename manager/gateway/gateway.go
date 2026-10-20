// Package gateway is the manager endpoint of channel B. It accepts agent
// WebSocket connections, runs the Noise IK handshake, authenticates the node
// by its key against the shared registry and dispatches the yamux streams
// of the session.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"github.com/hashicorp/yamux"
	"google.golang.org/protobuf/proto"

	"github.com/jc-lab/suricontroller/pkg/noiseconn"
	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/manager/registry"
	"github.com/openpicket/openpicket/pkg/dpwire"
)

// Lookup resolves a node from the X25519 form of its key. It returns
// registry.ErrNotFound for an unknown key.
type Lookup interface {
	Lookup(ctx context.Context, x25519 []byte) (*registry.Node, error)
}

// Handler receives session events. OnStatus runs on the control loop and
// must return quickly; ServeStream runs in its own goroutine and owns ms.
type Handler interface {
	// OnConnect runs after the Hello and returns the HelloAck to send. An
	// error closes the session.
	OnConnect(ctx context.Context, s *Session) (*dataplanev1.HelloAck, error)
	OnDisconnect(s *Session)
	OnStatus(s *Session, st *dataplanev1.Status)
	ServeStream(s *Session, t dataplanev1.StreamType, ms *wire.MsgStream)
}

// Config configures a Gateway.
type Config struct {
	StaticKey noise.DHKey
	Nodes     Lookup
	Handler   Handler
	Logger    *slog.Logger
	Now       func() time.Time
	// TrustProxyHeaders uses CF-Connecting-IP / X-Forwarded-For as the
	// remote address in logs.
	TrustProxyHeaders bool
}

// Gateway implements http.Handler for the data plane endpoint.
type Gateway struct {
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	sessions map[string]*Session
	lastTS   map[string]int64 // hex x25519 -> last accepted handshake timestamp
}

// New creates a gateway.
func New(cfg Config) *Gateway {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Gateway{cfg: cfg, log: cfg.Logger.With("component", "gateway"), sessions: map[string]*Session{}, lastTS: map[string]int64{}}
}

// Session returns the local session of a node, or nil.
func (g *Gateway) Session(nodeID string) *Session {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sessions[nodeID]
}

// Sessions returns the local sessions.
func (g *Gateway) Sessions() []*Session {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]*Session, 0, len(g.sessions))
	for _, s := range g.sessions {
		out = append(out, s)
	}
	return out
}

// Disconnect closes the local session of a node, if any (except keep, when
// that is the current session).
func (g *Gateway) Disconnect(nodeID, keep string) {
	if s := g.Session(nodeID); s != nil && s.ID != keep {
		s.Close()
	}
}

func proxiedAddr(r *http.Request) string {
	if v := r.Header.Get("Cf-Connecting-Ip"); v != "" {
		return v
	}
	if v := r.Header.Values("X-Forwarded-For"); len(v) > 0 {
		parts := strings.Split(v[len(v)-1], ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
			return last
		}
	}
	return r.RemoteAddr
}

// ServeHTTP accepts an agent connection and serves it until it ends.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{dpwire.Subprotocol}})
	if err != nil {
		g.log.Debug("websocket accept failed", "remote", r.RemoteAddr, "err", err)
		return
	}
	if ws.Subprotocol() != dpwire.Subprotocol {
		ws.Close(websocket.StatusPolicyViolation, "unsupported subprotocol")
		return
	}
	ws.SetReadLimit(dpwire.MaxMessageSize + 1<<20)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer nc.Close()
	remote := r.RemoteAddr
	if g.cfg.TrustProxyHeaders {
		remote = proxiedAddr(r)
	}
	var (
		node   *registry.Node
		claim  string
		reject dataplanev1.RejectReason
	)
	sc, _, err := noiseconn.Server(ctx, nc, noiseconn.ServerConfig{
		StaticKey: g.cfg.StaticKey,
		Prologue:  dpwire.Prologue,
		Accept: func(peer, payload []byte) ([]byte, bool) {
			node, claim, reject = g.authenticate(ctx, peer, payload)
			resp := &dataplanev1.HandshakeResponse{
				Accepted: reject == dataplanev1.RejectReason_REJECT_REASON_UNSPECIFIED, Reason: reject,
				ServerTimeUnixMs: g.cfg.Now().UnixMilli(),
			}
			b, _ := proto.Marshal(resp)
			return b, resp.Accepted
		},
	})
	if err != nil {
		if errors.Is(err, noiseconn.ErrRejected) {
			g.log.Warn("agent rejected", "remote", remote, "node", claim, "reason", reject.String())
		} else {
			g.log.Debug("handshake failed", "remote", remote, "err", err)
		}
		return
	}
	mux, err := yamux.Server(sc, dpwire.YamuxConfig())
	if err != nil {
		return
	}
	defer mux.Close()
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	s := &Session{
		gw: g, ID: hex.EncodeToString(id), NodeID: node.ID, Node: node, RemoteAddr: remote,
		ConnectedAt: g.cfg.Now(), mux: mux, ctx: ctx, cancel: cancel,
	}
	if err := s.serve(); err != nil && ctx.Err() == nil {
		g.log.Info("session ended", "node", s.NodeID, "remote", remote, "err", err)
	}
}

// authenticate validates the handshake payload. Message 1 can be replayed,
// so it changes no state except the replay timestamp.
func (g *Gateway) authenticate(ctx context.Context, peer, payload []byte) (*registry.Node, string, dataplanev1.RejectReason) {
	init := &dataplanev1.HandshakeInit{}
	if err := proto.Unmarshal(payload, init); err != nil {
		return nil, "", dataplanev1.RejectReason_REJECT_REASON_PROTOCOL
	}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	n, err := g.cfg.Nodes.Lookup(lctx, peer)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		return nil, init.NodeId, dataplanev1.RejectReason_REJECT_REASON_UNKNOWN_KEY
	case err != nil:
		g.log.Warn("node key lookup failed", "node", init.NodeId, "err", err)
		return nil, init.NodeId, dataplanev1.RejectReason_REJECT_REASON_UNAVAILABLE
	case !n.Enabled:
		return nil, n.ID, dataplanev1.RejectReason_REJECT_REASON_DISABLED
	case init.NodeId != n.ID:
		return nil, n.ID, dataplanev1.RejectReason_REJECT_REASON_NODE_ID_MISMATCH
	}
	ts := time.UnixMilli(init.TimestampUnixMs)
	if d := g.cfg.Now().Sub(ts); d > dpwire.MaxClockSkew || d < -dpwire.MaxClockSkew {
		return nil, n.ID, dataplanev1.RejectReason_REJECT_REASON_CLOCK_SKEW
	}
	k := hex.EncodeToString(peer)
	g.mu.Lock()
	defer g.mu.Unlock()
	if init.TimestampUnixMs <= g.lastTS[k] {
		return nil, n.ID, dataplanev1.RejectReason_REJECT_REASON_REPLAY
	}
	g.lastTS[k] = init.TimestampUnixMs
	return n, n.ID, dataplanev1.RejectReason_REJECT_REASON_UNSPECIFIED
}

func (g *Gateway) register(s *Session) {
	g.mu.Lock()
	old := g.sessions[s.NodeID]
	g.sessions[s.NodeID] = s
	g.mu.Unlock()
	if old != nil {
		g.log.Info("replacing existing session", "node", s.NodeID, "old_remote", old.RemoteAddr)
		old.Close()
	}
}

func (g *Gateway) unregister(s *Session) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sessions[s.NodeID] == s {
		delete(g.sessions, s.NodeID)
	}
}

// Session is one connected agent.
type Session struct {
	gw *Gateway
	// ID is unique per connection (presence across replicas).
	ID          string
	NodeID      string
	Node        *registry.Node
	RemoteAddr  string
	ConnectedAt time.Time

	mux    *yamux.Session
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	hello  *dataplanev1.Hello
	status *dataplanev1.Status
	ctrl   *wire.MsgStream
}

// Context is cancelled when the session ends.
func (s *Session) Context() context.Context { return s.ctx }

// Close ends the session.
func (s *Session) Close() {
	s.cancel()
	s.mux.Close()
}

// Hello returns the agent's Hello.
func (s *Session) Hello() *dataplanev1.Hello {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hello
}

// BootID returns the agent process id of the session.
func (s *Session) BootID() string { return s.Hello().GetBootId() }

// Status returns the latest status report, or nil.
func (s *Session) Status() *dataplanev1.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// SendControl pushes a control message (e.g. a new log policy).
func (s *Session) SendControl(m *dataplanev1.ControlDown) error {
	s.mu.Lock()
	ctrl := s.ctrl
	s.mu.Unlock()
	if ctrl == nil {
		return errors.New("gateway: session not ready")
	}
	return ctrl.Send(m)
}

func (s *Session) serve() error {
	g := s.gw
	type res struct {
		ms  *wire.MsgStream
		t   dataplanev1.StreamType
		err error
	}
	first := make(chan res, 1)
	go func() {
		ms, t, err := dpwire.AcceptStream(s.mux)
		first <- res{ms, t, err}
	}()
	var ctrl *wire.MsgStream
	select {
	case r := <-first:
		if r.err != nil {
			return r.err
		}
		if r.t != dataplanev1.StreamType_STREAM_TYPE_CONTROL {
			r.ms.Close()
			return fmt.Errorf("first stream must be control, got %v", r.t)
		}
		ctrl = r.ms
	case <-time.After(30 * time.Second):
		return errors.New("timeout waiting for the control stream")
	}
	_ = ctrl.Conn().SetReadDeadline(time.Now().Add(30 * time.Second))
	up := &dataplanev1.ControlUp{}
	if err := ctrl.Recv(up); err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	_ = ctrl.Conn().SetReadDeadline(time.Time{})
	hello := up.GetHello()
	if hello == nil {
		return errors.New("first control message must be a Hello")
	}
	if hello.NodeId != s.NodeID {
		return fmt.Errorf("hello node id %q does not match %q", hello.NodeId, s.NodeID)
	}
	s.mu.Lock()
	s.hello = hello
	s.mu.Unlock()

	g.register(s)
	defer g.unregister(s)
	ack, err := g.cfg.Handler.OnConnect(s.ctx, s)
	if err != nil {
		return fmt.Errorf("connect handler: %w", err)
	}
	defer g.cfg.Handler.OnDisconnect(s)
	if err := ctrl.Send(&dataplanev1.ControlDown{Body: &dataplanev1.ControlDown_HelloAck{HelloAck: ack}}); err != nil {
		return err
	}
	s.mu.Lock()
	s.ctrl = ctrl
	s.mu.Unlock()
	go s.acceptStreams()
	g.log.Info("agent connected", "node", s.NodeID, "remote", s.RemoteAddr, "agent_version", hello.AgentVersion)

	stop := context.AfterFunc(s.ctx, func() { ctrl.Close() })
	defer stop()
	for {
		up := &dataplanev1.ControlUp{}
		if err := ctrl.Recv(up); err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			return err
		}
		if st := up.GetStatus(); st != nil {
			s.mu.Lock()
			s.status = st
			s.mu.Unlock()
			g.cfg.Handler.OnStatus(s, st)
		}
	}
}

func (s *Session) acceptStreams() {
	for {
		ms, t, err := dpwire.AcceptStream(s.mux)
		if err != nil {
			return
		}
		switch t {
		case dataplanev1.StreamType_STREAM_TYPE_LOGS, dataplanev1.StreamType_STREAM_TYPE_DECISIONS, dataplanev1.StreamType_STREAM_TYPE_POLICY:
			go func() {
				defer ms.Close()
				stop := context.AfterFunc(s.ctx, func() { ms.Close() })
				defer stop()
				s.gw.cfg.Handler.ServeStream(s, t, ms)
			}()
		default:
			ms.Close()
		}
	}
}
