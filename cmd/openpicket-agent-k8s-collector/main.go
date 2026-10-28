// Command openpicket-agent-k8s-collector ships the logs of Kubernetes
// pods to OpenPicket: it follows the containers of the configured
// namespaces and selectors through the Kubernetes API (as `kubectl logs
// -f` does) and sends them over channel B as generic logs, under the
// program each target names.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/jc-lab/suricontroller/pkg/nodeid"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent/dataplane"
	"github.com/openpicket/openpicket/agent/k8slogs"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/version"
)

const defaultConfig = "/etc/openpicket-agent-k8s-collector/config.yaml"

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: openpicket-agent-k8s-collector <command> [flags]

Commands:
  run      ship the logs of the configured pods (default)
  keygen   create the node key and print its public key line
  pubkey   print the public key line to register in OpenPicket
  check    check the configuration, the Kubernetes API and the manager
  version  print the version

Flags:
`)
	flag.PrintDefaults()
}

func main() {
	configPath := flag.String("config", envOr("OPENPICKET_K8S_COLLECTOR_CONFIG", defaultConfig), "configuration file")
	nodeID := flag.String("node-id", "", "node id (keygen without a configuration file)")
	keyFile := flag.String("key-file", "", "key file (keygen without a configuration file)")
	flag.Usage = usage
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
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

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func run(configPath string) error {
	cfg, err := k8slogs.Load(configPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	a, err := k8slogs.NewAgent(cfg, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.Run(ctx)
}

func keygen(configPath, id, keyFile string, create bool) error {
	if id == "" || keyFile == "" {
		// Decode leniently: keygen runs before the configuration is complete.
		var cfg struct {
			NodeID  string `yaml:"node_id"`
			KeyFile string `yaml:"key_file"`
		}
		if b, err := os.ReadFile(configPath); err == nil {
			_ = yaml.Unmarshal(b, &cfg)
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
	if keyFile == "" {
		return fmt.Errorf("no key file (set key_file in %s or pass -key-file)", configPath)
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
	report := func(what string, err error, detail string) {
		if err != nil {
			ok = false
			fmt.Printf("[FAIL] %-14s %v\n", what, err)
			return
		}
		fmt.Printf("[ok  ] %-14s %s\n", what, detail)
	}
	cfg, err := k8slogs.Load(configPath)
	report("config", err, configPath)
	if err != nil {
		return errors.New("configuration is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	kube, err := k8slogs.NewKube(cfg.Kubernetes)
	report("kubernetes", err, "API reachable with the configured credentials")
	if err == nil {
		col, err := k8slogs.New(k8slogs.CollectorConfig{Kube: kube, Targets: cfg.Targets, Logger: slog.New(slog.DiscardHandler)})
		if err == nil {
			for _, r := range col.Check(ctx) {
				detail := fmt.Sprintf("%d container(s), program %s", r.Containers, r.Program)
				report("target", r.Err, r.Target+": "+detail)
			}
		}
	}
	if cfg.StateFile == "" {
		report("state", nil, "stateless (no state_file): a restart starts at the containers' current ends")
	} else if err := checkWritable(cfg.StateFile); err != nil {
		report("state", err, "")
	} else {
		report("state", nil, cfg.StateFile)
	}
	key, err := sshkey.LoadPrivateKey(cfg.KeyFile)
	if err != nil {
		report("key", err, "")
		return errors.New("some checks failed")
	}
	report("key", nil, key.Public(cfg.NodeID).String())
	hostKey, _ := sshkey.ParsePublicKey(cfg.OpenPicket.HostKey)
	httpClient, err := dataplane.NewHTTPClient(cfg.OpenPicket.CAFile, cfg.OpenPicket.TLSInsecureSkipVerify)
	if err != nil {
		report("manager", err, "")
		return errors.New("some checks failed")
	}
	sess, err := dataplane.Dial(ctx, dataplane.DialConfig{
		URL: cfg.OpenPicket.URL, HTTPClient: httpClient, Key: key, ServerKey: hostKey, NodeID: cfg.NodeID, Version: version.Version,
	}, &dataplanev1.Hello{NodeId: cfg.NodeID, AgentVersion: version.Version, BootId: "check"})
	if err == nil {
		report("manager", nil, cfg.OpenPicket.URL+" (manager "+sess.HelloAck().ManagerVersion+")")
		sess.Close()
	} else {
		report("manager", err, "")
	}
	if !ok {
		return errors.New("some checks failed")
	}
	return nil
}

// checkWritable creates (and removes) a file next to the state file.
func checkWritable(stateFile string) error {
	dir := filepath.Dir(stateFile)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
