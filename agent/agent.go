// Package agent is openpicket-agent: the suricontroller agent (Suricata,
// channel A) plus the OpenPicket data plane (channel B) — log shipping with
// at-least-once delivery, status, and later NFLOG collection, decision
// enforcement and port policies.
package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	suriagent "github.com/jc-lab/suricontroller/agent"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent/config"
	"github.com/openpicket/openpicket/agent/dataplane"
	"github.com/openpicket/openpicket/agent/localnets"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/direction"
	"github.com/openpicket/openpicket/pkg/version"
)

// Options configures New.
type Options struct {
	Logger *slog.Logger
	// LogTee receives the agent's own log so it can be shipped.
	LogTee *suriagent.LogTee
	// SuriOptions are passed to the suricontroller agent (tests replace
	// the engine and firewall there). LogOutput and Logger are set here.
	SuriOptions suriagent.Options
}

// Agent is a running openpicket-agent.
type Agent struct {
	cfg     *config.Config
	log     *slog.Logger
	suri    *suriagent.Agent
	shipper *dataplane.Shipper
	client  *dataplane.Client
	bootID  string

	nets      atomic.Pointer[direction.Nets]
	localNets atomic.Pointer[dataplanev1.LocalNets]
}

// New prepares the agent.
func New(ctx context.Context, cfg *config.Config, opts Options) (*Agent, error) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	a := &Agent{cfg: cfg, log: log, bootID: hex.EncodeToString(b)}
	a.nets.Store(&direction.Nets{})
	a.localNets.Store(&dataplanev1.LocalNets{})
	a.shipper = dataplane.NewShipper(dataplane.ShipperConfig{
		NodeID: cfg.Suri.NodeID, BootID: a.bootID, MaxInflightBytes: int64(cfg.OpenPicket.Logs.InflightMaxBytes),
		Nets: func() *direction.Nets { return a.nets.Load() }, Logger: log,
	})
	so := opts.SuriOptions
	so.Logger, so.LogTee, so.LogOutput = log, opts.LogTee, a.shipper
	var err error
	if a.suri, err = suriagent.New(ctx, cfg.Suri, so); err != nil {
		return nil, err
	}
	key, _, err := suriagent.LoadKey(cfg.Suri)
	if err != nil {
		return nil, err
	}
	hostKey, err := sshkey.ParsePublicKey(cfg.OpenPicket.HostKey)
	if err != nil {
		return nil, err
	}
	client, err := httpClient(cfg.OpenPicket)
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	for k, v := range cfg.OpenPicket.Headers {
		headers.Set(k, v)
	}
	a.client = dataplane.NewClient(dataplane.DialConfig{
		URL: cfg.OpenPicket.URL, Headers: headers, HTTPClient: client, Key: key, ServerKey: hostKey,
		NodeID: cfg.Suri.NodeID, Version: version.Version,
	}, dataplane.Handlers{
		Hello: a.hello, Status: a.status, LogPolicy: a.shipper.SetPolicy, Shipper: a.shipper,
	}, log)
	a.refreshNets()
	return a, nil
}

func httpClient(o config.OpenPicket) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.TLSInsecureSkipVerify}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("openpicket.ca_file: no certificates found")
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsCfg}}, nil
}

// PublicKey returns the agent public key line (same key on both channels).
func (a *Agent) PublicKey() string { return a.suri.PublicKey() }

// refreshNets recomputes the local networks; it reports a change.
func (a *Agent) refreshNets() bool {
	ln := localnets.Collect(a.suri.Instances(), a.cfg.OpenPicket.WANInterfaces, a.cfg.OpenPicket.LocalNets)
	old := a.localNets.Load()
	if slices.Equal(old.HomeNet, ln.HomeNet) && slices.Equal(old.InterfaceAddrs, ln.InterfaceAddrs) && slices.Equal(old.Extra, ln.Extra) {
		return false
	}
	a.localNets.Store(ln)
	a.nets.Store(localnets.Nets(ln))
	return true
}

// Run runs both channels until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("openpicket-agent starting", "version", version.Version, "node", a.cfg.Suri.NodeID, "boot_id", a.bootID)
	var wg sync.WaitGroup
	for _, fn := range []func(context.Context){
		func(ctx context.Context) { _ = a.suri.Run(ctx) },
		a.client.Run,
		a.watchNets,
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}
	wg.Wait()
	return nil
}

// watchNets follows HOME_NET and address changes (DHCP, PPPoE).
func (a *Agent) watchNets(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if a.refreshNets() {
			a.log.Info("local networks changed", "home_net", a.localNets.Load().HomeNet, "addresses", a.localNets.Load().InterfaceAddrs)
			a.client.PokeStatus()
		}
	}
}

func (a *Agent) hello() *dataplanev1.Hello {
	sh := a.suri.Hello()
	h := &dataplanev1.Hello{
		NodeId: a.cfg.Suri.NodeID, AgentVersion: version.Version, BootId: a.bootID,
		LocalNets: a.localNets.Load(), Platform: sh.GetPlatform(), Engine: sh.GetEngine(),
		WanInterfaces: a.cfg.OpenPicket.WANInterfaces, LogSources: a.suri.LogSources(), Warnings: sh.GetWarnings(),
		Capabilities: []string{"logs"},
	}
	for _, p := range localnets.UncoveredIPv6(a.nets.Load(), a.cfg.OpenPicket.WANInterfaces) {
		h.Warnings = append(h.Warnings, warning("ipv6_not_local", "IPv6 prefix "+p+" is not in HOME_NET or openpicket.local_nets: its hosts look external"))
	}
	return h
}

func (a *Agent) status(ctx context.Context) *dataplanev1.Status {
	return &dataplanev1.Status{
		TimeUnixMs: time.Now().UnixMilli(),
		Suricata:   a.suri.Status(ctx),
		LocalNets:  a.localNets.Load(),
		Logs:       a.shipper.Stats(),
	}
}

func warning(code, msg string) *agentv1.Warning { return &agentv1.Warning{Code: code, Message: msg} }

// ReopenLogs asks Suricata to reopen its log files (SIGHUP after an
// external logrotate).
func (a *Agent) ReopenLogs() { a.suri.ReopenLogs() }
