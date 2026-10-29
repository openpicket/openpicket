// Package manager is openpicket-manager: the data plane endpoint for agents
// (channel B), the log pipeline to Loki and CrowdSec, decision and policy
// distribution, and the management UI and API.
//
// Every replica is equal and keeps its state in PostgreSQL; tasks that need
// a single writer run under leader election (docs/ARCHITECTURE.md §5.1).
package manager

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
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
	"github.com/openpicket/openpicket/manager/hub"
	"github.com/openpicket/openpicket/manager/lapi"
	"github.com/openpicket/openpicket/manager/logprog"
	"github.com/openpicket/openpicket/manager/misp"
	"github.com/openpicket/openpicket/manager/notify"
	"github.com/openpicket/openpicket/manager/pipeline"
	"github.com/openpicket/openpicket/manager/policy"
	"github.com/openpicket/openpicket/manager/registry"
	"github.com/openpicket/openpicket/manager/relay"
	"github.com/openpicket/openpicket/manager/settings"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/manager/sinks/opensearch"
	"github.com/openpicket/openpicket/manager/syslog"
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
	// Role selects what this replica runs (default RoleAll).
	Role Role
	// Keys of the UI and API (session, suricontroller principal); nil
	// derives them from HostKey (setups without OPENPICKET_KEY_SECRET).
	Keys *Keys
	// CrowdSecSync locates the log processors' content sync
	// (openpicket-crowdsec-sync).
	CrowdSecSync CrowdSecSync
	// Hub is the CrowdSec hub items are downloaded from.
	Hub hub.Source
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
	// OpenSearch, when set, receives every record after the
	// acknowledgement (best effort) and the LAPI alerts.
	OpenSearch *opensearch.Config
	// MISP enables the MISP source and approval queue.
	MISP *MISPOptions
	// PublicURL is the external URL of the UI (links in notifications).
	PublicURL string
	// Suricontroller is the openpicket-suricontroller base URL. The
	// manager reads its host key and agent path there and hands them to
	// agents without a controller section (HelloAck.controller).
	Suricontroller *url.URL
	// AgentControllerURL overrides the URL in that endpoint: ws(s)://...,
	// or a path agents resolve against their openpicket.url.
	AgentControllerURL string
	// ControllerPollInterval overrides how often that endpoint is read
	// (default 1m; tests).
	ControllerPollInterval time.Duration
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
	// Syslog configures the gateways' syslog receiver (and the default
	// for unregistered senders the API shows).
	Syslog SyslogOptions
	// Pipeline tuning (tests).
	PipelineOpenAfter time.Duration
	Logger            *slog.Logger
	// Registry for metrics; nil creates one (served by MetricsHandler).
	Registry *prometheus.Registry
}

// Role is what a replica runs (docs/ARCHITECTURE.md §5.10).
type Role string

const (
	// RoleAll runs everything (single deployment, docker compose).
	RoleAll Role = "all"
	// RoleGateway runs what faces the agents: channel B, the log pipeline,
	// the decision and policy streams (and the syslog receiver). It holds
	// the channel B host key, and nothing of the UI and API.
	RoleGateway Role = "gateway"
	// RoleAPI runs the UI and API and the leader tasks (LAPI, alerts,
	// notifications, MISP, CrowdSec content, policy compilation).
	RoleAPI Role = "api"
)

// Gateway reports whether the role faces the agents.
func (r Role) Gateway() bool { return r != RoleAPI }

// API reports whether the role runs the UI, API and leader tasks.
func (r Role) API() bool { return r != RoleGateway }

// SyslogOptions configure the syslog receiver (docs/ARCHITECTURE.md
// §4.10). Without a listen address there is none.
type SyslogOptions struct {
	// UDP, TCP and TLS listen addresses (":5514").
	UDP, TCP, TLS string
	// TLSConfig of the TLS listener (syslog.TLSFiles).
	TLSConfig *tls.Config
	// Unregistered applies to senders no device matches until the UI
	// stores a choice: syslog.ModeDrop (default) or syslog.ModeAccept.
	Unregistered string
}

func (o SyslogOptions) enabled() bool { return o.UDP != "" || o.TCP != "" || o.TLS != "" }

// CrowdSecSync locates the content sync of the log processors.
type CrowdSecSync struct {
	// Endpoints are sync base URLs (http://lp:8082); empty: every log
	// processor of the CrowdSec sink on Port.
	Endpoints []string
	// Port of the sync on the log processors (default 8082).
	Port int
}

// MISPOptions configure the MISP integration.
type MISPOptions struct {
	Client           misp.ClientConfig
	Interval         time.Duration
	Renew            time.Duration
	DefaultTTL       string
	ProposeMinAlerts int
	ProposeWindow    time.Duration
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
	geoUpdater *geo.Updater
	hub        *hub.Store
	hubRemote  *hub.Hub
	programs   *logprog.Store
	rollout    *hub.Rollout
	policies   *policy.Service
	alerts     *alerts.Syncer
	lokiQuery  *loki.Querier
	notify     *notify.Engine
	search     *opensearch.Client
	misp       *misp.Service
	lapis      []api.LAPI
	controller *controllerEndpoint
	// ctlEP is the suricontroller endpoint a gateway hands agents: kept by
	// the API replicas in the settings (role gateway).
	ctlEP    atomic.Pointer[dataplanev1.ControllerEndpoint]
	ackSinks []pipeline.Sink
	// syslog receives from devices without an agent (gateway); nil when
	// no listener is configured.
	syslog        *syslog.Server
	syslogDevices *syslog.Devices
	syslogSources *syslog.Sources

	runOnce sync.Once
}

// New creates a manager; call Run.
func New(opts Options) (*Manager, error) {
	if opts.Role == "" {
		opts.Role = RoleAll
	}
	switch opts.Role {
	case RoleAll, RoleGateway, RoleAPI:
	default:
		return nil, fmt.Errorf("manager: unknown role %q", opts.Role)
	}
	if opts.DB == nil {
		return nil, errors.New("manager: DB is required")
	}
	if opts.HostKey == nil && opts.Role.Gateway() {
		return nil, errors.New("manager: the channel B host key is required (role " + string(opts.Role) + ")")
	}
	if opts.Keys == nil && opts.Role.API() {
		if opts.HostKey == nil {
			return nil, errors.New("manager: OPENPICKET_KEY_SECRET is required for role api")
		}
		keys, err := DeriveKeys(opts.HostKey)
		if err != nil {
			return nil, err
		}
		opts.Keys = keys
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

	var err error
	m.programs = logprog.New(opts.DB, m.settings, opts.Logger)
	csCfg := opts.CrowdSec
	csCfg.Logger = opts.Logger
	if m.cs, err = crowdsec.New(csCfg); err != nil {
		return nil, err
	}
	m.geo = geo.New(opts.DB, opts.Logger)
	m.geoUpdater = geo.NewUpdater(m.geo)
	m.policies = policy.New(opts.DB, m.geo, opts.Logger)
	// Compilation results (last good versions, errors) are written by the
	// API replicas; a gateway compiles for its streams only.
	m.policies.ReadOnly = !opts.Role.API()
	if opts.Role.API() {
		m.hub = hub.NewStore(opts.DB, opts.Logger)
		m.hubRemote = hub.NewHub(m.hub, opts.Hub)
		header, token := m.cs.Auth()
		m.rollout = &hub.Rollout{Store: m.hub, Targets: m.syncTargets, Header: header, Token: token, Logger: opts.Logger}
		m.rollout.Init()
		m.listener.Handle(db.ChannelHub, m.rollout.Notified)
		m.listener.OnResync(func() { m.rollout.Notified("") })
	}
	if opts.Role.Gateway() {
		if err := m.setupGateway(); err != nil {
			return nil, err
		}
	}
	// Policies compile against the GeoIP data this replica loaded: a
	// reload (first successful load after a failure, new upload) recompiles.
	m.geo.OnChange = func() { m.policies.Notified("") }
	if opts.OpenSearch != nil && opts.OpenSearch.URL != "" {
		// The sink (gateway) and the alert indexing leader (api).
		if m.search, err = opensearch.New(*opts.OpenSearch); err != nil {
			return nil, err
		}
	}
	if opts.Role.Gateway() {
		var async []pipeline.Sink
		if m.search != nil {
			async = append(async, m.search)
		}
		m.pipe = pipeline.New(pipeline.Config{
			AckSinks: m.ackSinks, AsyncSinks: async, Watermarks: m.watermarks, Geo: m.geo, Programs: m.programs, Logger: opts.Logger, Registerer: m.reg, OpenAfter: opts.PipelineOpenAfter,
		})
		if opts.Syslog.enabled() {
			if err := m.setupSyslog(); err != nil {
				return nil, err
			}
		}
	}
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
	m.listener.Handle(db.ChannelSettings, m.settings.Notified)
	m.listener.OnResync(func() { m.nodes.Resync(context.Background()) })
	m.settings.OnChange = func(key string) {
		switch key {
		case settings.KeyLogPolicy:
			if opts.Role.Gateway() {
				m.pushLogPolicy()
			}
		case logprog.KeyStorage:
			m.programs.Load(context.Background())
		case keyControllerEndpoint:
			if !opts.Role.API() {
				m.loadControllerEndpoint(context.Background(), true)
			}
		case syslog.KeyUnregistered:
			if m.syslogDevices != nil {
				m.syslogDevices.LoadMode(context.Background())
			}
		}
	}
	if !opts.Role.API() {
		return m, nil
	}
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
	if opts.MISP != nil && opts.MISP.Client.URL != "" {
		if err := m.setupMISP(); err != nil {
			return nil, err
		}
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
	if opts.Suricontroller != nil {
		m.controller = newControllerEndpoint(opts.Suricontroller, opts.Keys.Principal, opts.AgentControllerURL, opts.ControllerPollInterval, opts.Logger)
	}
	return m, nil
}

// setupGateway creates what faces the agents: channel B, presence, the
// log pipeline's sinks and the decision streams.
func (m *Manager) setupGateway() error {
	opts := m.opts
	static, err := noiseconn.KeyPair(opts.HostKey.X25519())
	if err != nil {
		return err
	}
	m.gw = gateway.New(gateway.Config{
		StaticKey: static, Nodes: m.nodes, Handler: (*handler)(m), Logger: opts.Logger, TrustProxyHeaders: opts.TrustProxyHeaders,
	})
	m.reg.MustRegister(&nodeCollector{gw: m.gw, nodes: m.nodes})
	m.presence = &presence{db: opts.DB, replica: opts.ReplicaID, gw: m.gw, log: opts.Logger.With("component", "presence")}
	lokiCfg := opts.Loki
	lokiCfg.Registerer = m.reg
	lokiCfg.Skip = m.programs.Skip
	lk, err := loki.New(lokiCfg)
	if err != nil {
		return err
	}
	m.ackSinks = []pipeline.Sink{lk, m.cs}
	m.watermarks = pipeline.NewWatermarks(opts.DB, opts.Logger)
	m.nodes.OnRevoked = func(id string) { m.gw.Disconnect(id, "") }
	m.listener.Handle(db.ChannelSessions, m.presence.notified)
	m.dist = relay.NewDistributor(opts.DB, opts.Logger)
	m.listener.Handle(db.ChannelDecisions, m.dist.Notified)
	// After a reconnect notifications may have been missed: wake the
	// decision streams so they compare versions.
	m.listener.OnResync(func() { m.dist.Notified("") })
	return nil
}

// setupSyslog opens the syslog listeners (role gateway).
func (m *Manager) setupSyslog() error {
	o := m.opts.Syslog
	m.syslogDevices = syslog.NewDevices(m.opts.DB, m.settings, o.Unregistered, m.log)
	m.syslogSources = syslog.NewSources(m.opts.DB, m.log)
	srv, err := syslog.New(syslog.Config{UDP: o.UDP, TCP: o.TCP, TLS: o.TLS, TLSConfig: o.TLSConfig, Devices: m.syslogDevices, Sources: m.syslogSources,
		Ingest: m.pipe.Ingest, Logger: m.log, Registerer: m.reg})
	if err != nil {
		return err
	}
	m.syslog = srv
	reload := func(string) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := m.syslogDevices.Load(ctx); err != nil {
			m.log.Warn("load syslog devices", "err", err)
		}
	}
	m.listener.Handle(db.ChannelSyslog, reload)
	m.listener.OnResync(func() { reload("") })
	return nil
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

// setupMISP creates the MISP service; it needs the primary LAPI with
// watcher credentials (decisions are added as a watcher).
func (m *Manager) setupMISP() error {
	if m.opts.LAPI.URL == "" || m.opts.LAPI.Login == "" {
		return fmt.Errorf("manager: MISP needs the primary LAPI with watcher credentials")
	}
	c, err := misp.NewClient(m.opts.MISP.Client)
	if err != nil {
		return err
	}
	lc, err := lapi.New(m.opts.LAPI)
	if err != nil {
		return err
	}
	w, err := lc.Watcher()
	if err != nil {
		return err
	}
	o := m.opts.MISP
	m.misp = misp.New(misp.Config{DB: m.opts.DB, Client: c, LAPI: w, Interval: o.Interval, Renew: o.Renew, DefaultTTL: o.DefaultTTL,
		ProposeMinAlerts: o.ProposeMinAlerts, ProposeWindow: o.ProposeWindow, Logger: m.log})
	m.listener.Handle(db.ChannelMISP, func(string) { m.misp.Poke() })
	return nil
}

// HostPublicKey returns the line agents pin as openpicket.host_key. An API
// replica without the host key reads the one the gateways published.
func (m *Manager) HostPublicKey() string {
	if m.opts.HostKey != nil {
		return m.opts.HostKey.Public(HostKeyComment).String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var line string
	if err := m.opts.DB.QueryRow(ctx, `SELECT host_key FROM openpicket.gateway_info ORDER BY seen_at DESC LIMIT 1`).Scan(&line); err != nil {
		return ""
	}
	return line
}

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

// Syslog returns the syslog receiver; nil without listeners.
func (m *Manager) Syslog() *syslog.Server { return m.syslog }

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
	m.programs.Load(ctx)
	workers := []func(context.Context){m.listener.Run, m.cs.Run}
	if m.opts.Role.API() {
		// The CrowdSec image carries no content: the built-in items come
		// from this binary (hub.Builtin).
		if err := m.hub.SeedBuiltin(ctx); err != nil {
			m.log.Error("store built-in CrowdSec content", "err", err)
		}
		// One lock connection for every leader task of this replica.
		el := db.NewElector(m.opts.DB, m.opts.ReplicaID, m.log)
		if m.relay != nil {
			el.Add("relay", func(ctx context.Context, l *db.Leadership) { m.relay.Run(ctx, l) })
		}
		if m.search != nil {
			el.Add("opensearch", func(ctx context.Context, _ *db.Leadership) {
				m.search.RunLeader(ctx, m.opts.DB, m.log.With("component", "opensearch"), 30*time.Second)
			})
		}
		if m.misp != nil {
			el.Add("misp", func(ctx context.Context, l *db.Leadership) { m.misp.Run(ctx, l) })
		}
		el.Add("geo-update", func(ctx context.Context, _ *db.Leadership) { m.geoUpdater.Run(ctx) })
		el.Add("notify", func(ctx context.Context, l *db.Leadership) { m.notify.Run(ctx, l) })
		el.Add("hub", func(ctx context.Context, l *db.Leadership) {
			go m.hubRemote.RunRefresh(ctx)
			m.rollout.Run(ctx, l)
		})
		if m.alerts != nil {
			el.Add("alerts", func(ctx context.Context, l *db.Leadership) { m.alerts.Run(ctx, l) })
		}
		workers = append(workers, el.Run, m.policies.RunCompiler)
		if m.controller != nil {
			onChange := m.pushController
			if !m.opts.Role.Gateway() {
				onChange = m.storeControllerEndpoint
			}
			workers = append(workers, func(ctx context.Context) { m.controller.run(ctx, onChange) })
		}
	}
	if m.opts.Role.Gateway() {
		if !m.opts.Role.API() {
			m.loadControllerEndpoint(ctx, false)
		}
		workers = append(workers, m.pipe.Run, m.watermarks.Run, m.programs.Run, m.runGatewayInfo,
			func(ctx context.Context) { m.presence.run(ctx, 30*time.Second) })
		if m.syslog != nil {
			if err := m.syslogDevices.Load(ctx); err != nil {
				m.log.Warn("load syslog devices", "err", err)
			}
			workers = append(workers, m.syslog.Run, m.syslogSources.Run)
		}
	}
	var wg sync.WaitGroup
	for _, fn := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}
	<-ctx.Done()
	if m.opts.Role.Gateway() {
		// Graceful handover: stop processing while the agents stay
		// connected, save the watermarks, then let the agents move to
		// another replica.
		m.pipe.Drain()
		fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		m.watermarks.Flush(fctx)
		cancel()
		for _, s := range m.gw.Sessions() {
			s.Close()
		}
	}
	wg.Wait()
	return nil
}

// syncTargets returns the content sync URLs of the log processors.
func (m *Manager) syncTargets() []string {
	if len(m.opts.CrowdSecSync.Endpoints) > 0 {
		return m.opts.CrowdSecSync.Endpoints
	}
	port := m.opts.CrowdSecSync.Port
	if port == 0 {
		port = 8082
	}
	var out []string
	for _, e := range m.cs.Endpoints() {
		u, err := url.Parse(e)
		if err != nil || u.Hostname() == "" {
			continue
		}
		out = append(out, "http://"+net.JoinHostPort(u.Hostname(), strconv.Itoa(port)))
	}
	return out
}

// Hub returns the CrowdSec content store.
func (m *Manager) Hub() *hub.Store { return m.hub }

// Handler serves the agent endpoint and the health checks.
func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	m.Mount(mux)
	return mux
}

// Mount adds the agent endpoint and the health checks to mux.
func (m *Manager) Mount(mux *http.ServeMux) {
	if m.gw != nil {
		mux.Handle(dpwire.Path, m.gw)
	}
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

func (m *Manager) pushController(ep *dataplanev1.ControllerEndpoint) {
	for _, s := range m.gw.Sessions() {
		if err := s.SendControl(&dataplanev1.ControlDown{Body: &dataplanev1.ControlDown_Controller{Controller: ep}}); err != nil {
			m.log.Debug("push controller endpoint", "node", s.NodeID, "err", err)
		}
	}
}

// handler adapts the manager to gateway.Handler.
type handler Manager

func (h *handler) OnConnect(ctx context.Context, s *gateway.Session) (*dataplanev1.HelloAck, error) {
	m := (*Manager)(h)
	m.presence.connected(ctx, s)
	m.watermarks.Forget(s.NodeID, s.BootID())
	ack := &dataplanev1.HelloAck{
		ServerTimeUnixMs:      time.Now().UnixMilli(),
		ManagerVersion:        version.Version,
		StatusIntervalSeconds: uint32(m.opts.StatusInterval / time.Second),
		LogPolicy:             m.settings.LogPolicy(ctx),
	}
	ack.Controller = m.controllerEndpoint()
	return ack, nil
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
