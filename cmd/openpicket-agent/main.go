// Command openpicket-agent runs on an edge node (router, server): Suricata
// managed by openpicket-suricontroller (channel A) and the OpenPicket data
// plane to openpicket-manager (channel B).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"

	suriagent "github.com/jc-lab/suricontroller/agent"
	suricfg "github.com/jc-lab/suricontroller/agent/config"
	"github.com/jc-lab/suricontroller/pkg/nodeid"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent"
	"github.com/openpicket/openpicket/agent/config"
	"github.com/openpicket/openpicket/agent/dataplane"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/version"
)

const defaultConfig = "/etc/suri-agent/agent.yaml"

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: openpicket-agent <command> [flags]

Commands:
  run      run the agent (default)
  keygen   create the agent key and print its public key line
  pubkey   print the public key line to register in OpenPicket
  check    check the configuration and the manager connection
  version  print the version

Flags:
`)
	flag.PrintDefaults()
}

func main() {
	configPath := flag.String("config", envOr("OPENPICKET_AGENT_CONFIG", defaultConfig), "agent configuration file")
	nodeID := flag.String("node-id", "", "node id (keygen without a configuration file)")
	keyFile := flag.String("key-file", "", "key file (keygen without a configuration file)")
	flag.Usage = usage
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	if err := flag.CommandLine.Parse(args); err != nil {
		os.Exit(2)
	}
	var err error
	switch cmd {
	case "run":
		err = run(*configPath)
	case "keygen", "pubkey":
		err = keygen(*configPath, *nodeID, *keyFile, cmd == "keygen")
	case "check":
		err = check(*configPath)
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

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func newLogger(level string, w io.Writer) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: l}))
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	tee := &suriagent.LogTee{}
	log := newLogger(cfg.Suri.LogLevel, io.MultiWriter(os.Stderr, tee))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := agent.New(ctx, cfg, agent.Options{Logger: log, LogTee: tee})
	if err != nil {
		return err
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Info("SIGHUP: reopening Suricata log files")
			a.ReopenLogs()
		}
	}()
	return a.Run(ctx)
}

func keygen(configPath, id, keyFile string, create bool) error {
	if id == "" || keyFile == "" {
		// Decode leniently: keygen runs before the configuration is complete.
		cfg := suricfg.Default()
		if b, err := os.ReadFile(configPath); err == nil {
			_ = yaml.Unmarshal(b, cfg)
		}
		if id == "" {
			id = cfg.NodeID
		}
		if keyFile == "" {
			keyFile = cfg.KeyFile
		}
	}
	if err := nodeid.Validate(id); err != nil {
		return fmt.Errorf("%w (set node_id in %s or pass -node-id)", err, configPath)
	}
	var (
		k   *sshkey.PrivateKey
		err error
	)
	if create {
		k, _, err = sshkey.LoadOrGenerate(keyFile, id)
	} else {
		k, err = sshkey.LoadPrivateKey(keyFile)
	}
	if err != nil {
		return err
	}
	fmt.Println(k.Public(id).String())
	return nil
}

func check(configPath string) error {
	ok := true
	report := func(name string, err error, detail string) {
		status := "ok  "
		if err != nil {
			status, ok = "FAIL", false
			detail = err.Error()
		}
		fmt.Printf("[%s] %-14s %s\n", status, name, detail)
	}
	cfg, err := config.Load(configPath)
	report("config", err, configPath)
	if err != nil {
		return errors.New("configuration is invalid")
	}
	key, err := sshkey.LoadPrivateKey(cfg.Suri.KeyFile)
	if err != nil {
		report("key", err, "")
		return errors.New("some checks failed")
	}
	report("key", nil, key.Public(cfg.Suri.NodeID).String())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hostKey, _ := sshkey.ParsePublicKey(cfg.OpenPicket.HostKey)
	sess, err := dataplane.Dial(ctx, dataplane.DialConfig{
		URL: cfg.OpenPicket.URL, Key: key, ServerKey: hostKey, NodeID: cfg.Suri.NodeID, Version: version.Version,
	}, &dataplanev1.Hello{NodeId: cfg.Suri.NodeID, AgentVersion: version.Version, BootId: "check"})
	if err == nil {
		report("manager", nil, cfg.OpenPicket.URL+" (manager "+sess.HelloAck().ManagerVersion+")")
		sess.Close()
	} else {
		report("manager", err, "")
	}
	switch {
	case !cfg.ControllerFromManager():
		report("controller", nil, cfg.Suri.Controller.URL+" (agent.yaml)")
	case err != nil:
		report("controller", errors.New("from the manager, which is unreachable"), "")
	case sess.HelloAck().GetController() == nil:
		report("controller", errors.New("the manager sent no endpoint (OPENPICKET_SURICONTROLLER_URL unset, or openpicket-suricontroller unreachable)"), "")
	default:
		ep := sess.HelloAck().GetController()
		report("controller", nil, ep.GetUrl()+" (from the manager)")
	}
	if !ok {
		return errors.New("some checks failed; run suri-node-agent-style checks for Suricata with the same configuration")
	}
	return nil
}
