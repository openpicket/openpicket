// Command openpicket-manager runs one manager replica: the agent data plane
// endpoint, the log pipeline, decision and policy distribution, and the UI
// and API. Configuration comes
// from OPENPICKET_* environment variables; secrets accept *_FILE.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/internal/envconf"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager"
	"github.com/openpicket/openpicket/manager/api"
	"github.com/openpicket/openpicket/manager/auth"
	"github.com/openpicket/openpicket/manager/csmetrics"
	"github.com/openpicket/openpicket/manager/hub"
	"github.com/openpicket/openpicket/manager/lapi"
	"github.com/openpicket/openpicket/manager/relay"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/manager/sinks/opensearch"
	"github.com/openpicket/openpicket/pkg/version"
	"github.com/openpicket/openpicket/web"
)

type config struct {
	Listen            string
	MetricsListen     string
	DatabaseURL       string
	HostKey           string
	ReplicaID         string
	TrustProxyHeaders bool
	LogLevel          string
	Loki              loki.Config
	LokiQueryURL      string
	PublicURL         string
	OpenSearch        opensearch.Config
	MISP              manager.MISPOptions
	Metrics           csmetrics.Config
	CrowdSec          crowdsec.Config
	CrowdSecSync      manager.CrowdSecSync
	LAPI              lapi.Config
	LAPIName          string
	LAPIExtra         string
	AlertRetention    time.Duration
	Rules             relay.Rules

	// UI and API
	AuthConfig        string
	AdminUsername     string
	AdminPassword     string
	AdminPasswordHash string
	InsecureCookies   bool
	ReadOnly          bool
	AllowedOrigins    []string
	SuricontrollerURL string
	// AgentControllerURL overrides the controller URL handed to agents.
	AgentControllerURL string
}

func loadConfig() (*config, error) {
	c := &config{Listen: ":8080", MetricsListen: ":9090", LogLevel: "info", Rules: relay.DefaultRules()}
	e := envconf.New("OPENPICKET_")
	e.String("LISTEN", &c.Listen)
	e.String("METRICS_LISTEN", &c.MetricsListen)
	e.Secret("DATABASE_URL", &c.DatabaseURL)
	e.Secret("HOST_KEY", &c.HostKey)
	e.String("REPLICA_ID", &c.ReplicaID)
	e.Bool("TRUST_PROXY_HEADERS", &c.TrustProxyHeaders)
	e.String("LOG_LEVEL", &c.LogLevel)
	e.String("LOKI_URL", &c.Loki.URL)
	e.String("LOKI_TENANT", &c.Loki.TenantID)
	e.String("LOKI_QUERY_URL", &c.LokiQueryURL)
	e.String("PUBLIC_URL", &c.PublicURL)
	e.String("MISP_URL", &c.MISP.Client.URL)
	e.Secret("MISP_API_KEY", &c.MISP.Client.APIKey)
	e.String("MISP_CA_FILE", &c.MISP.Client.CAFile)
	e.Bool("MISP_INSECURE_SKIP_VERIFY", &c.MISP.Client.InsecureSkipVerify)
	e.Duration("MISP_SYNC_INTERVAL", &c.MISP.Interval)
	e.Duration("MISP_RENEW", &c.MISP.Renew)
	e.String("MISP_DEFAULT_TTL", &c.MISP.DefaultTTL)
	e.Int("MISP_PROPOSE_MIN_ALERTS", &c.MISP.ProposeMinAlerts)
	e.Duration("MISP_PROPOSE_WINDOW", &c.MISP.ProposeWindow)
	e.String("OPENSEARCH_URL", &c.OpenSearch.URL)
	e.String("OPENSEARCH_USERNAME", &c.OpenSearch.Username)
	e.Secret("OPENSEARCH_PASSWORD", &c.OpenSearch.Password)
	e.String("OPENSEARCH_CA_FILE", &c.OpenSearch.CAFile)
	e.Bool("OPENSEARCH_INSECURE_SKIP_VERIFY", &c.OpenSearch.InsecureSkipVerify)
	e.Duration("OPENSEARCH_RETENTION", &c.OpenSearch.Retention)
	e.Int("OPENSEARCH_REPLICAS", &c.OpenSearch.Replicas)
	e.String("LOKI_USERNAME", &c.Loki.Username)
	e.Secret("LOKI_PASSWORD", &c.Loki.Password)
	e.Duration("LOKI_MAX_AGE", &c.Loki.MaxAge)
	e.List("CROWDSEC_ENDPOINTS", &c.CrowdSec.Endpoints)
	e.String("CROWDSEC_DISCOVERY_HOST", &c.CrowdSec.DiscoveryHost)
	e.Int("CROWDSEC_DISCOVERY_PORT", &c.CrowdSec.DiscoveryPort)
	e.String("CROWDSEC_AUTH_HEADER", &c.CrowdSec.AuthHeader)
	e.Secret("CROWDSEC_AUTH_VALUE", &c.CrowdSec.AuthValue)
	e.List("CROWDSEC_EVE_TYPES", &c.CrowdSec.EveTypes)
	e.List("CROWDSEC_NFLOG_PREFIXES", &c.CrowdSec.NflogPrefixes)
	e.List("CROWDSEC_SYNC_ENDPOINTS", &c.CrowdSecSync.Endpoints)
	e.Int("CROWDSEC_SYNC_PORT", &c.CrowdSecSync.Port)
	e.String("LAPI_URL", &c.LAPI.URL)
	e.Secret("LAPI_BOUNCER_KEY", &c.LAPI.BouncerKey)
	e.String("LAPI_LOGIN", &c.LAPI.Login)
	e.Secret("LAPI_PASSWORD", &c.LAPI.Password)
	e.String("LAPI_CA_FILE", &c.LAPI.CAFile)
	e.String("LAPI_NAME", &c.LAPIName)
	e.List("CROWDSEC_METRICS_URLS", &c.Metrics.URLs)
	e.List("CROWDSEC_METRICS_DISCOVERY_HOSTS", &c.Metrics.DiscoveryHosts)
	e.Int("CROWDSEC_METRICS_DISCOVERY_PORT", &c.Metrics.DiscoveryPort)
	e.Secret("LAPI_EXTRA", &c.LAPIExtra)
	e.Duration("ALERT_RETENTION", &c.AlertRetention)
	e.List("EDGE_TYPES", &c.Rules.Types)
	e.List("EDGE_SCOPES", &c.Rules.Scopes)
	e.List("EDGE_EXCLUDE_ORIGINS", &c.Rules.ExcludeOrigins)
	e.List("EDGE_EXCLUDE_SCENARIOS", &c.Rules.ExcludeScenarios)
	e.List("EDGE_BOTH_SCENARIOS", &c.Rules.BothScenarios)
	e.Secret("AUTH_CONFIG", &c.AuthConfig)
	e.String("ADMIN_USERNAME", &c.AdminUsername)
	e.Secret("ADMIN_PASSWORD", &c.AdminPassword)
	e.Secret("ADMIN_PASSWORD_HASH", &c.AdminPasswordHash)
	e.Bool("INSECURE_COOKIES", &c.InsecureCookies)
	e.Bool("READ_ONLY", &c.ReadOnly)
	e.List("ALLOWED_ORIGINS", &c.AllowedOrigins)
	e.String("SURICONTROLLER_URL", &c.SuricontrollerURL)
	e.String("AGENT_CONTROLLER_URL", &c.AgentControllerURL)
	if err := e.Err(); err != nil {
		return nil, err
	}
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("OPENPICKET_DATABASE_URL is required"))
	}
	if c.HostKey == "" {
		errs = append(errs, errors.New("OPENPICKET_HOST_KEY(_FILE) is required (create one with `openpicket-manager keygen`)"))
	}
	if c.Loki.URL == "" {
		errs = append(errs, errors.New("OPENPICKET_LOKI_URL is required"))
	}
	if c.AuthConfig == "" && c.AdminUsername == "" {
		errs = append(errs, errors.New("OPENPICKET_AUTH_CONFIG(_FILE) or OPENPICKET_ADMIN_USERNAME is required"))
	}
	if len(c.CrowdSec.Endpoints) == 0 && c.CrowdSec.DiscoveryHost == "" {
		errs = append(errs, errors.New("OPENPICKET_CROWDSEC_ENDPOINTS or OPENPICKET_CROWDSEC_DISCOVERY_HOST is required"))
	}
	return c, errors.Join(errs...)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: openpicket-manager [command]

Commands:
  serve    run the manager (default)
  keygen   print a new channel B host key (OpenSSH PEM) to store as a Secret
  pubkey   print the host public key (agent.yaml openpicket.host_key)
  principal-pubkey
           print the principal public key
           (openpicket-suricontroller OPENPICKET_SURI_PRINCIPAL_PUBLIC_KEY)
  hash-password
           read a password from stdin and print its bcrypt hash
  hub-bundle
           print the built-in CrowdSec content as a log processor bundle
           (JSON, for openpicket-crowdsec-sync PUT /hub/bundle)
  version  print the version
`)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	cmd := "serve"
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "keygen":
		err = keygen()
	case "pubkey":
		err = pubkey(false)
	case "principal-pubkey":
		err = pubkey(true)
	case "hash-password":
		err = hashPassword()
	case "hub-bundle":
		err = hubBundle()
	case "version":
		fmt.Println(version.Version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func hubBundle() error {
	b, err := hub.BuiltinBundle(1)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(b)
}

func keygen() error {
	k, err := sshkey.Generate()
	if err != nil {
		return err
	}
	pem, err := k.MarshalOpenSSH(manager.HostKeyComment)
	if err != nil {
		return err
	}
	_, _ = os.Stdout.Write(pem)
	fmt.Fprintln(os.Stderr, "public key:", k.Public(manager.HostKeyComment).String())
	return nil
}

func hashPassword() error {
	pw, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
	if err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(strings.TrimRight(string(pw), "\r\n")), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	fmt.Println(string(h))
	return nil
}

func pubkey(principal bool) error {
	var raw string
	e := envconf.New("OPENPICKET_")
	e.Secret("HOST_KEY", &raw)
	if err := e.Err(); err != nil {
		return err
	}
	k, err := sshkey.ParsePrivateKey([]byte(raw))
	if err != nil {
		return err
	}
	if !principal {
		fmt.Println(k.Public(manager.HostKeyComment).String())
		return nil
	}
	keys, err := manager.DeriveKeys(k)
	if err != nil {
		return err
	}
	fmt.Println(keys.Principal.Public(manager.PrincipalKeyComment).String())
	return nil
}

// parseExtraLAPIs parses OPENPICKET_LAPI_EXTRA:
// [{"name":"dc2","url":"http://...","login":"...","password":"...","ca_file":"..."}]
func parseExtraLAPIs(raw string) ([]manager.NamedLAPI, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var in []struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Login    string `json:"login"`
		Password string `json:"password"`
		CAFile   string `json:"ca_file"`
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("OPENPICKET_LAPI_EXTRA: %w", err)
	}
	var out []manager.NamedLAPI
	for _, l := range in {
		if l.Name == "" || l.URL == "" || l.Login == "" {
			return nil, errors.New("OPENPICKET_LAPI_EXTRA: name, url and login are required")
		}
		out = append(out, manager.NamedLAPI{Name: l.Name, Config: lapi.Config{URL: l.URL, Login: l.Login, Password: l.Password, CAFile: l.CAFile}})
	}
	return out, nil
}

// buildAuth creates the provider chain from OPENPICKET_AUTH_CONFIG and the
// OPENPICKET_ADMIN_* shortcut for the static login.
func buildAuth(cfg *config, sessionKey []byte) (*auth.Chain, error) {
	ac, err := auth.ParseConfig([]byte(cfg.AuthConfig))
	if err != nil {
		return nil, err
	}
	if cfg.AdminUsername != "" {
		ac.Static = &auth.StaticConfig{Username: cfg.AdminUsername, PasswordHash: cfg.AdminPasswordHash, Password: cfg.AdminPassword, Role: auth.RoleAdmin}
	}
	if cfg.InsecureCookies {
		ac.InsecureCookies = true
	}
	return ac.Build(sessionKey)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func serve() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	hostKey, err := sshkey.ParsePrivateKey([]byte(cfg.HostKey))
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := schema.Migrate(ctx, pool); err != nil {
		return err
	}
	extra, err := parseExtraLAPIs(cfg.LAPIExtra)
	if err != nil {
		return err
	}
	var suri *url.URL
	if cfg.SuricontrollerURL != "" {
		if suri, err = url.Parse(cfg.SuricontrollerURL); err != nil {
			return fmt.Errorf("OPENPICKET_SURICONTROLLER_URL: %w", err)
		}
	}
	m, err := manager.New(manager.Options{
		DB: pool, HostKey: hostKey, ReplicaID: cfg.ReplicaID, Loki: cfg.Loki, CrowdSec: cfg.CrowdSec, CrowdSecSync: cfg.CrowdSecSync, LAPI: cfg.LAPI, EdgeRules: &cfg.Rules,
		LokiQueryURL: cfg.LokiQueryURL, PublicURL: cfg.PublicURL, OpenSearch: &cfg.OpenSearch, MISP: &cfg.MISP, CrowdSecMetrics: cfg.Metrics, LAPIName: cfg.LAPIName, ExtraLAPIs: extra, AlertRetention: cfg.AlertRetention,
		Suricontroller: suri, AgentControllerURL: cfg.AgentControllerURL, TrustProxyHeaders: cfg.TrustProxyHeaders, Logger: log,
	})
	if err != nil {
		return err
	}
	keys, err := manager.DeriveKeys(hostKey)
	if err != nil {
		return err
	}
	chain, err := buildAuth(cfg, keys.Session)
	if err != nil {
		return err
	}
	apiCfg := api.Config{Auth: chain, ReadOnly: cfg.ReadOnly, AllowedOrigins: cfg.AllowedOrigins, TrustProxyHeaders: cfg.TrustProxyHeaders,
		PrincipalKey: keys.Principal.Key, Suricontroller: suri}
	apiSrv, err := m.API(apiCfg)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	m.Mount(mux)
	apiSrv.Mount(mux)
	mux.Handle("/", web.Handler())
	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	metrics := &http.Server{Addr: cfg.MetricsListen, Handler: m.MetricsHandler(), ReadHeaderTimeout: 15 * time.Second}
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = m.Run(ctx)
	}()
	errc := make(chan error, 2)
	go func() {
		log.Info("openpicket-manager listening", "addr", cfg.Listen, "version", version.Version, "host_key", m.HostPublicKey())
		errc <- srv.ListenAndServe()
	}()
	go func() { errc <- metrics.ListenAndServe() }()
	select {
	case err = <-errc:
		stop()
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	_ = metrics.Shutdown(shutdownCtx)
	<-runDone
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
