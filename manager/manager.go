// Package manager is openpicket-manager: the data plane endpoint for agents
// (channel B), the log pipeline to Loki and CrowdSec, decision and policy
// distribution, and the management UI and API.
//
// Every replica is equal and keeps its state in PostgreSQL; tasks that need
// a single writer run under leader election (docs/ARCHITECTURE.md §5.1).
package manager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/jc-lab/suricontroller/pkg/noiseconn"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/manager/alerts"
	"github.com/openpicket/openpicket/manager/api"
	"github.com/openpicket/openpicket/manager/csmetrics"
	"github.com/openpicket/openpicket/manager/db"
	"github.com/openpicket/openpicket/manager/gateway"
	"github.com/openpicket/openpicket/manager/geo"
	"github.com/openpicket/openpicket/manager/lapi"
	"github.com/openpicket/openpicket/manager/notify"
	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/manager/policy"
	"github.com/openpicket/openpicket/manager/registry"
	"github.com/openpicket/openpicket/manager/relay"
	"github.com/openpicket/openpicket/manager/settings"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/pkg/dpwire"
	"github.com/openpicket/openpicket/pkg/version"
)

// HostKeyComment is the comment of the manager host public key.
const HostKeyComment = "openpicket-manager"

// Options configures a Manager.
type Options struct {
	DB *pgxpool.Pool
	// HostKey is the channel B key; all replicas share it.
	HostKey *sshkey.PrivateKey
	// ReplicaID identifies this replica (default: hostname + pid).
	ReplicaID string
	Loki      loki.Config
	// LokiQueryURL is the Loki read endpoint for the log explorer (default:
	// the push URL's host).
	LokiQueryURL string
	CrowdSec     crowdsec.Config
	// LAPI is the primary CrowdSec Local API (decision relay). An empty URL
	// disables decision distribution.
	LAPI lapi.Config
	// LAPIName names the primary LAPI in the UI (default "default").
	LAPIName string
	// ExtraLAPIs are more LAPI instances shown in the UI (alerts and
	// decisions); only the primary feeds the edge.
	ExtraLAPIs []NamedLAPI
	// AlertRetention of the alert copy (default 30d).
	AlertRetention time.Duration
	// AlertPollInterval overrides the alert poll interval (tests).
	AlertPollInterval time.Duration
	// PublicURL is the external URL of the UI (links in notifications).
	PublicURL string
	// CrowdSecMetrics lists CrowdSec Prometheus endpoints shown in the UI.
	CrowdSecMetrics csmetrics.Config
	// EdgeRules select and orient the decisions sent to nodes; zero value
	// uses relay.DefaultRules.
	EdgeRules *relay.Rules
	// RelayPullInterval overrides the relay pull interval (tests).
	RelayPullInterval time.Duration
	// StatusInterval requested from agents (default 30s).
	StatusInterval time.Duration
	// TrustProxyHeaders uses CF-Connecting-IP / X-Forwarded-For as the
	// agent address in logs.
	TrustProxyHeaders bool
	// Pipeline tuning (tests).
	PipelineOpenAfter time.Duration
	Logger            *slog.Logger
	// Registry for metrics; nil creates one (served by MetricsHandler).
	Registry *prometheus.Registry
}

// NamedLAPI is an additional LAPI instance.
type NamedLAPI struct {
	Name   string
	Config lapi.Config
}

// Manager is a running openpicket-manager replica.
type Manager struct {
	opts       Options
	log        *slog.Logger
	reg        *prometheus.Registry
	nodes      *registry.Registry
	listener   *db.Listener
	gw         *gateway.Gateway
	pipe       *pipeline.Pipeline
	watermarks *pipeline.Watermarks
	settings   *settings.Store
	presence   *presence
	cs         *crowdsec.Sink
	relay      *relay.Relay
	dist       *relay.Distributor
	geo        *geo.Store
	policies   *policy.Service
	alerts     *alerts.Syncer
	lokiQuery  *loki.Querier
	notify     *notify.Engine
	lapis      []api.LAPI

	runOnce sync.Once
}

// New creates a manager; call Run.
func New(opts Options) (*Manager, error) {
	if opts.DB == nil || opts.HostKey == nil {
		return nil, errors.New("manager: DB and HostKey are required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.ReplicaID == "" {
		h, _ := os.Hostname()
		opts.ReplicaID = fmt.Sprintf("%s-%d", h, os.Getpid())
	}
	if opts.StatusInterval <= 0 {
		opts.StatusInterval = 30 * time.Second
	}
	m := &Manager{opts: opts, log: opts.Logger, reg: opts.Registry}
	if m.reg == nil {
		m.reg = prometheus.NewRegistry()
		m.reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}
	m.nodes = registry.New(opts.DB, opts.Logger)
	m.listener = db.NewListener(opts.DB, opts.Logger)
	m.settings = settings.New(opts.DB)

	static, err := noiseconn.KeyPair(opts.HostKey.X25519())
	if err != nil {
		return nil, err
	}
	m.gw = gateway.New(gateway.Config{
		StaticKey: static, Nodes: m.nodes, Handler: (*handler)(m), Logger: opts.Logger, TrustProxyHeaders: opts.TrustProxyHeaders,
	})
	m.reg.MustRegister(&nodeCollector{gw: m.gw, nodes: m.nodes})
	m.presence = &presence{db: opts.DB, replica: opts.ReplicaID, gw: m.gw, log: opts.Logger.With("component", "presence")}

	var ack []pipeline.Sink
	lokiCfg := opts.Loki
	lokiCfg.Registerer = m.reg
	lk, err := loki.New(lokiCfg)
	if err != nil {
		return nil, err
	}
	ack = append(ack, lk)
	csCfg := opts.CrowdSec
	csCfg.Logger = opts.Logger
	if m.cs, err = crowdsec.New(csCfg); err != nil {
		return nil, err
	}
	ack = append(ack, m.cs)
	m.geo = geo.New(opts.DB, opts.Logger)
	m.policies = policy.New(opts.DB, m.geo, opts.Logger)
	m.watermarks = pipeline.NewWatermarks(opts.DB, opts.Logger)
	m.pipe = pipeline.New(pipeline.Config{
		AckSinks: ack, Watermarks: m.watermarks, Geo: m.geo, Logger: opts.Logger, Registerer: m.reg, OpenAfter: opts.PipelineOpenAfter,
	})

	m.nodes.OnRevoked = func(id string) { m.gw.Disconnect(id, "") }
	m.listener.Handle(db.ChannelNodes, func(id string) {
		m.nodes.Changed(context.Background(), id)
		// Bundles depend on node labels.
		m.policies.Notified("")
	})
	m.listener.Handle(db.ChannelGeo, m.geo.Notified)
	m.listener.Handle(db.ChannelPolicy, m.policies.Notified)
	m.listener.OnResync(func() {
		m.geo.Notified("")
		m.policies.Notified("")
	})
	m.listener.Handle(db.ChannelSessions, m.presence.notified)
	m.listener.Handle(db.ChannelSettings, m.settings.Notified)
	m.dist = relay.NewDistributor(opts.DB, opts.Logger)
	m.listener.Handle(db.ChannelDecisions, m.dist.Notified)
	// After a reconnect notifications may have been missed: wake the
	// decision streams so they compare versions.
	m.listener.OnResync(func() { m.dist.Notified("") })
	if opts.LAPI.URL != "" {
		lc, err := lapi.New(opts.LAPI)
		if err != nil {
			return nil, err
		}
		rules := relay.DefaultRules()
		if opts.EdgeRules != nil {
			rules = *opts.EdgeRules
		}
		m.relay = relay.New(relay.Config{LAPI: lc, Rules: rules, Logger: opts.Logger, Registerer: m.reg, PullInterval: opts.RelayPullInterval})
	} else {
		m.log.Warn("no LAPI configured: decisions are not distributed to nodes")
	}
	m.notify = notify.NewEngine(notify.Config{DB: opts.DB, PublicURL: opts.PublicURL, Logger: opts.Logger, Health: m.sinksDown})
	if err := m.setupAlerts(); err != nil {
		return nil, err
	}
	if m.alerts != nil {
		// Changes made through another replica's API.
		m.listener.Handle(db.ChannelAlerts, func(payload string) {
			if payload == resyncPayload {
				m.alerts.Resync()
				return
			}
			m.alerts.Poke(payload)
		})
	}
	m.listener.OnResync(func() { m.nodes.Resync(context.Background()) })
	m.settings.OnChange = func(key string) {
		if key == settings.KeyLogPolicy {
			m.pushLogPolicy()
		}
	}
	return m, nil
}

// setupAlerts creates the watcher clients and the alert syncer for every
// LAPI with watcher credentials.
func (m *Manager) setupAlerts() error {
	all := []NamedLAPI{}
	if m.opts.LAPI.URL != "" {
		name := m.opts.LAPIName
		if name == "" {
			name = "default"
		}
		all = append(all, NamedLAPI{Name: name, Config: m.opts.LAPI})
	}
	all = append(all, m.opts.ExtraLAPIs...)
	var instances []alerts.Instance
	seen := map[string]bool{}
	for _, l := range all {
		if l.Config.Login == "" {
			m.log.Warn("LAPI without watcher credentials: its alerts are not shown", "instance", l.Name)
			continue
		}
		if seen[l.Name] {
			return fmt.Errorf("manager: duplicate LAPI name %q", l.Name)
		}
		seen[l.Name] = true
		c, err := lapi.New(l.Config)
		if err != nil {
			return err
		}
		w, err := c.Watcher()
		if err != nil {
			return err
		}
		instances = append(instances, alerts.Instance{Name: l.Name, URL: c.URL(), Watcher: w})
		m.lapis = append(m.lapis, api.LAPI{Name: l.Name, Watcher: w})
	}
	if len(instances) > 0 {
		m.alerts = alerts.NewSyncer(alerts.Config{DB: m.opts.DB, Instances: instances, Retention: m.opts.AlertRetention,
			PollInterval: m.opts.AlertPollInterval, Logger: m.log, Registerer: m.reg})
	}
	return nil
}

// HostPublicKey returns the line agents pin as openpicket.host_key.
func (m *Manager) HostPublicKey() string { return m.opts.HostKey.Public(HostKeyComment).String() }

// Gateway returns the channel B gateway.
func (m *Manager) Gateway() *gateway.Gateway { return m.gw }

// Settings returns the settings store.
func (m *Manager) Settings() *settings.Store { return m.settings }

// Geo returns the GeoIP store.
func (m *Manager) Geo() *geo.Store { return m.geo }

// Policies returns the port policy service.
func (m *Manager) Policies() *policy.Service { return m.policies }

// Pipeline returns the log pipeline.
func (m *Manager) Pipeline() *pipeline.Pipeline { return m.pipe }

// Run starts the background work and blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	started := false
	m.runOnce.Do(func() { started = true })
	if !started {
		return errors.New("manager: Run called twice")
	}
	if err := m.geo.Load(ctx); err != nil {
		m.log.Warn("load geo databases", "err", err)
	}
	var wg sync.WaitGroup
	for _, fn := range []func(context.Context){
		m.listener.Run,
		m.pipe.Run,
		m.watermarks.Run,
		m.cs.Run,
		func(ctx context.Context) {
			if m.relay != nil {
				db.RunLeader(ctx, m.opts.DB, "relay", m.opts.ReplicaID, m.log, func(ctx context.Context, l *db.Leadership) { m.relay.Run(ctx, l) })
			}
		},
		func(ctx context.Context) { m.presence.run(ctx, 30*time.Second) },
		func(ctx context.Context) {
			db.RunLeader(ctx, m.opts.DB, "notify", m.opts.ReplicaID, m.log, func(ctx context.Context, l *db.Leadership) { m.notify.Run(ctx, l) })
		},
		func(ctx context.Context) {
			if m.alerts != nil {
				db.RunLeader(ctx, m.opts.DB, "alerts", m.opts.ReplicaID, m.log, func(ctx context.Context, l *db.Leadership) { m.alerts.Run(ctx, l) })
			}
		},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}
	<-ctx.Done()
	// Graceful handover: stop processing while the agents stay connected,
	// save the watermarks, then let the agents move to another replica.
	m.pipe.Drain()
	fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	m.watermarks.Flush(fctx)
	cancel()
	for _, s := range m.gw.Sessions() {
		s.Close()
	}
	wg.Wait()
	return nil
}

// Handler serves the agent endpoint and the health checks.
func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	m.Mount(mux)
	return mux
}

// Mount adds the agent endpoint and the health checks to mux.
func (m *Manager) Mount(mux *http.ServeMux) {
	mux.Handle(dpwire.Path, m.gw)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := m.opts.DB.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
}

// MetricsHandler serves Prometheus metrics.
func (m *Manager) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

func (m *Manager) pushLogPolicy() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := m.settings.LogPolicy(ctx)
	for _, s := range m.gw.Sessions() {
		if err := s.SendControl(&dataplanev1.ControlDown{Body: &dataplanev1.ControlDown_LogPolicy{LogPolicy: p}}); err != nil {
			m.log.Debug("push log policy", "node", s.NodeID, "err", err)
		}
	}
}

// handler adapts the manager to gateway.Handler.
type handler Manager

func (h *handler) OnConnect(ctx context.Context, s *gateway.Session) (*dataplanev1.HelloAck, error) {
	m := (*Manager)(h)
	m.presence.connected(ctx, s)
	m.watermarks.Forget(s.NodeID, s.BootID())
	return &dataplanev1.HelloAck{
		ServerTimeUnixMs:      time.Now().UnixMilli(),
		ManagerVersion:        version.Version,
		StatusIntervalSeconds: uint32(m.opts.StatusInterval / time.Second),
		LogPolicy:             m.settings.LogPolicy(ctx),
	}, nil
}

func (h *handler) OnDisconnect(s *gateway.Session) {
	m := (*Manager)(h)
	m.presence.disconnected(s)
	m.log.Info("agent disconnected", "node", s.NodeID)
}

func (h *handler) OnStatus(s *gateway.Session, st *dataplanev1.Status) {
	(*Manager)(h).presence.status(s, st)
}

func (h *handler) ServeStream(s *gateway.Session, t dataplanev1.StreamType, ms *wire.MsgStream) {
	m := (*Manager)(h)
	var err error
	switch t {
	case dataplanev1.StreamType_STREAM_TYPE_LOGS:
		err = m.pipe.Serve(s.Context(), s.Node, ms)
	case dataplanev1.StreamType_STREAM_TYPE_DECISIONS:
		err = m.dist.Serve(s.Context(), s.NodeID, ms)
	case dataplanev1.StreamType_STREAM_TYPE_POLICY:
		err = m.policies.Serve(s.Context(), func() *registry.Node {
			if cur := m.nodes.Node(s.NodeID); cur != nil {
				return cur
			}
			return s.Node
		}, ms)
	default:
		// Decisions and policies are served once their distributors exist;
		// until then the stream stays open and idle.
		<-s.Context().Done()
	}
	if err != nil && s.Context().Err() == nil {
		m.log.Debug("stream ended", "node", s.NodeID, "stream", t.String(), "err", err)
	}
}
