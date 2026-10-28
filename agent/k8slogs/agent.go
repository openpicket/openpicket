package k8slogs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent/dataplane"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/version"
)

// Capability is reported to the manager besides "logs" and "log_sources".
const Capability = "kubernetes"

// Agent is a running collector: it connects to the manager as its node
// and ships the targets' logs.
type Agent struct {
	cfg     *Config
	log     *slog.Logger
	bootID  string
	col     *Collector
	shipper *dataplane.Shipper
	client  *dataplane.Client
}

// NewAgent creates the collector and its manager connection.
func NewAgent(cfg *Config, log *slog.Logger) (*Agent, error) {
	if log == nil {
		log = slog.Default()
	}
	key, err := sshkey.LoadPrivateKey(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("key_file: %w (create it with `openpicket-agent-k8s-collector keygen`)", err)
	}
	hostKey, err := sshkey.ParsePublicKey(cfg.OpenPicket.HostKey)
	if err != nil {
		return nil, fmt.Errorf("openpicket.host_key: %w", err)
	}
	kube, err := NewKube(cfg.Kubernetes)
	if err != nil {
		return nil, err
	}
	col, err := New(CollectorConfig{Kube: kube, Targets: cfg.Targets, StateFile: cfg.StateFile, ScanInterval: cfg.ScanInterval, Logger: log})
	if err != nil {
		return nil, err
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	a := &Agent{cfg: cfg, log: log, bootID: hex.EncodeToString(b), col: col}
	a.shipper = dataplane.NewShipper(dataplane.ShipperConfig{NodeID: cfg.NodeID, BootID: a.bootID, MaxInflightBytes: cfg.OpenPicket.InflightMaxBytes, Logger: log})
	httpClient, err := dataplane.NewHTTPClient(cfg.OpenPicket.CAFile, cfg.OpenPicket.TLSInsecureSkipVerify)
	if err != nil {
		return nil, fmt.Errorf("openpicket.ca_file: %w", err)
	}
	headers := http.Header{}
	for k, v := range cfg.OpenPicket.Headers {
		headers.Set(k, v)
	}
	a.client = dataplane.NewClient(dataplane.DialConfig{
		URL: cfg.OpenPicket.URL, Headers: headers, HTTPClient: httpClient, Key: key, ServerKey: hostKey,
		NodeID: cfg.NodeID, Version: version.Version,
	}, dataplane.Handlers{Hello: a.hello, Status: a.status, Shipper: a.shipper}, log)
	return a, nil
}

// Collector returns the log collector.
func (a *Agent) Collector() *Collector { return a.col }

// Run ships until ctx ends; the positions are saved last.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("openpicket-agent-k8s-collector starting", "version", version.Version, "node", a.cfg.NodeID, "boot_id", a.bootID,
		"targets", len(a.cfg.Targets), "state_file", a.cfg.StateFile)
	var wg sync.WaitGroup
	for _, fn := range []func(context.Context){
		a.client.Run,
		a.col.Run,
		func(ctx context.Context) {
			if err := a.shipper.ShipSources(ctx, a.col); err != nil {
				a.log.Error("shipping stopped", "err", err)
			}
		},
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}
	wg.Wait()
	a.col.Flush()
	return nil
}

func (a *Agent) hello() *dataplanev1.Hello {
	p := &agentv1.PlatformInfo{Profile: "kubernetes", Arch: runtime.GOARCH, FirewallBackend: "none"}
	p.Hostname, _ = os.Hostname()
	return &dataplanev1.Hello{NodeId: a.cfg.NodeID, AgentVersion: version.Version, BootId: a.bootID, Platform: p,
		Capabilities: []string{"logs", "log_sources", Capability}}
}

func (a *Agent) status(context.Context) *dataplanev1.Status {
	st := &dataplanev1.Status{TimeUnixMs: time.Now().UnixMilli(), Logs: a.shipper.Stats()}
	for _, s := range a.col.Status() {
		st.LogSources = append(st.LogSources, &dataplanev1.LogSourceStatus{Program: s.Program, Path: s.Path, Files: uint32(s.Followed),
			Lines: s.Lines, Truncated: s.Truncated, LastError: s.LastError})
	}
	return st
}
