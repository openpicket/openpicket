// Command openpicket-manager runs one manager replica: the agent data plane
// endpoint, the log pipeline and (later) the UI and API. Configuration comes
// from OPENPICKET_* environment variables; secrets accept *_FILE.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/internal/envconf"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/manager"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/pkg/version"
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
	CrowdSec          crowdsec.Config
}

func loadConfig() (*config, error) {
	c := &config{Listen: ":8080", MetricsListen: ":9090", LogLevel: "info"}
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
		err = pubkey()
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

func pubkey() error {
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
	fmt.Println(k.Public(manager.HostKeyComment).String())
	return nil
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
	m, err := manager.New(manager.Options{
		DB: pool, HostKey: hostKey, ReplicaID: cfg.ReplicaID, Loki: cfg.Loki, CrowdSec: cfg.CrowdSec,
		TrustProxyHeaders: cfg.TrustProxyHeaders, Logger: log,
	})
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: m.Handler(), ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
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
