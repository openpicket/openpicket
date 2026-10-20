// Command openpicket-suricontroller is suri-controller for OpenPicket: the
// Suricata control plane (rules, configuration, bundles, deployment) with
// its state in the shared PostgreSQL database and authentication delegated
// to openpicket-manager.
//
// It runs as a single replica. Agents connect to it on /agent/v1/connect
// (channel A); browsers reach its UI and API only through the manager's
// /suricata/ proxy. Logs do not go through it: agents ship them to the
// manager (channel B), so log collection is disabled here.
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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jc-lab/suricontroller/controller"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/wire"

	"github.com/openpicket/openpicket/internal/envconf"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/internal/suriweb"
	"github.com/openpicket/openpicket/pkg/version"
	"github.com/openpicket/openpicket/suriauth"
	"github.com/openpicket/openpicket/suristore"
)

type config struct {
	Listen      string
	DataDir     string
	DatabaseURL string
	// PrincipalKey is the manager's principal public key
	// ("ssh-ed25519 AAAA...").
	PrincipalKey string
	LoginURL     string
	// UIBase is the public path of the UI behind the manager proxy.
	UIBase            string
	TrustProxyHeaders bool
	DisableETOpen     bool
	LogLevel          string
}

func loadConfig() (*config, error) {
	c := &config{Listen: ":8080", DataDir: "/var/lib/openpicket-suricontroller", LoginURL: "/login", UIBase: "/suricata/", LogLevel: "info"}
	e := envconf.New("OPENPICKET_")
	e.String("SURI_LISTEN", &c.Listen)
	e.String("SURI_DATA_DIR", &c.DataDir)
	e.Secret("DATABASE_URL", &c.DatabaseURL)
	e.Secret("SURI_PRINCIPAL_PUBLIC_KEY", &c.PrincipalKey)
	e.String("SURI_LOGIN_URL", &c.LoginURL)
	e.String("SURI_UI_BASE", &c.UIBase)
	e.Bool("SURI_TRUST_PROXY_HEADERS", &c.TrustProxyHeaders)
	e.Bool("SURI_DISABLE_ET_OPEN", &c.DisableETOpen)
	e.String("LOG_LEVEL", &c.LogLevel)
	if err := e.Err(); err != nil {
		return nil, err
	}
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("OPENPICKET_DATABASE_URL is required"))
	}
	if c.PrincipalKey == "" {
		errs = append(errs, errors.New("OPENPICKET_SURI_PRINCIPAL_PUBLIC_KEY is required (the manager's principal public key)"))
	}
	return c, errors.Join(errs...)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: openpicket-suricontroller [command]

Commands:
  serve    run the controller (default)
  hostkey  print the controller host public key (agent.yaml controller.host_key)
  version  print the version

Configuration is read from OPENPICKET_* environment variables; secrets also
accept a *_FILE variant.
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
	case "hostkey":
		err = printHostKey()
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

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func printHostKey() error {
	dir := "/var/lib/openpicket-suricontroller"
	if v := os.Getenv("OPENPICKET_SURI_DATA_DIR"); v != "" {
		dir = v
	}
	k, _, err := sshkey.LoadOrGenerate(filepath.Join(dir, "hostkey"), controller.HostKeyComment)
	if err != nil {
		return err
	}
	fmt.Println(k.Public(controller.HostKeyComment).String())
	return nil
}

// discardSink drops logs: agents ship them to the manager instead.
type discardSink struct{}

func (discardSink) Write(context.Context, string, agentv1.LogType, [][]byte) error { return nil }
func (discardSink) Close() error                                                   { return nil }

func serve() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	pk, err := sshkey.ParsePublicKey(cfg.PrincipalKey)
	if err != nil {
		return fmt.Errorf("principal public key: %w", err)
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

	ctl, err := controller.New(controller.Options{
		DataDir:           cfg.DataDir,
		Store:             suristore.New(pool),
		Auth:              &suriauth.Provider{Key: pk.Key, Login: cfg.LoginURL},
		Authorizer:        suriauth.Authorizer{},
		LogSink:           discardSink{},
		Logger:            log,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
		DisableETOpen:     cfg.DisableETOpen,
	})
	if err != nil {
		return err
	}
	defer ctl.Close()
	// Agents ship logs over channel B; nothing should be collected here.
	if err := ctl.Logs().SetGlobalPolicy(ctx, &agentv1.LogCollectionPolicy{Enabled: false}); err != nil {
		return fmt.Errorf("disable log collection: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle(wire.AgentPath, ctl.AgentHandler())
	mux.Handle("/api/", http.StripPrefix("/api", ctl.APIHandler()))
	mux.Handle("/", suriweb.Handler(suriweb.Options{APIBase: strings.TrimSuffix(cfg.UIBase, "/") + "/api"}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })

	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = ctl.Run(ctx)
	}()
	errc := make(chan error, 1)
	go func() {
		log.Info("openpicket-suricontroller listening", "addr", cfg.Listen, "version", version.Version, "host_key", ctl.HostPublicKey())
		errc <- srv.ListenAndServe()
	}()
	select {
	case err = <-errc:
		stop()
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	<-runDone
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
