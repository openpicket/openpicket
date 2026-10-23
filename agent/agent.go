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
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	suriagent "github.com/jc-lab/suricontroller/agent"
	"github.com/jc-lab/suricontroller/agent/collector"
	"github.com/jc-lab/suricontroller/agent/platform"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent/config"
	"github.com/openpicket/openpicket/agent/dataplane"
	"github.com/openpicket/openpicket/agent/enforcer"
	"github.com/openpicket/openpicket/agent/localnets"
	"github.com/openpicket/openpicket/agent/logsrc"
	"github.com/openpicket/openpicket/agent/natmap"
	"github.com/openpicket/openpicket/agent/nflog"
	"github.com/openpicket/openpicket/agent/nft"
	"github.com/openpicket/openpicket/agent/policy"
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
	// Host overrides how nft and host files are reached (tests).
	Host *nft.Host
	// Fw4 overrides the fw4 detection (tests).
	Fw4 *bool
}

// Agent is a running openpicket-agent.
type Agent struct {
	cfg     *config.Config
	log     *slog.Logger
	suri    *suriagent.Agent
	shipper *dataplane.Shipper
	client  *dataplane.Client
	bootID  string
	host    *nft.Host
	nflog   *nflog.Source
	reject  *nft.WANReject
	allow   *allowlist
	enf     *enforcer.Enforcer
	pol     *policy.Sink
	// ctl is the controller endpoint from the manager (nil: agent.yaml
	// names the controller).
	ctl *controllerSource

	// fw4: OpenWrt, the WAN follows the fw4 zones (wan.go).
	fw4        bool
	wan        *nft.WAN
	zoneDevs   []string
	emptyZones []string

	nets      atomic.Pointer[direction.Nets]
	localNets atomic.Pointer[dataplanev1.LocalNets]

	// NAT lookup for eve alerts (nil when disabled).
	nat       *natmap.Tracker
	natHits   atomic.Uint64
	natMisses atomic.Uint64

	// logs tails openpicket.log_sources (nil without any).
	logs *logsrc.Collector
	// pub is the agent's public key line.
	pub string
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
	sc := dataplane.ShipperConfig{
		NodeID: cfg.Node.NodeID, BootID: a.bootID, MaxInflightBytes: int64(cfg.OpenPicket.Logs.InflightMaxBytes),
		Nets: func() *direction.Nets { return a.nets.Load() }, Logger: log,
	}
	// The NAT lookup names the inside host of Suricata alerts.
	if nl := cfg.OpenPicket.NATLookup; nl.Enabled && cfg.Suri != nil {
		a.nat = &natmap.Tracker{Table: natmap.NewTable(nl.Retention, nl.MaxEntries), Logger: log.With("component", "natmap")}
		sc.NAT = a.lookupNAT
	}
	a.shipper = dataplane.NewShipper(sc)
	var err error
	if cfg.Suri != nil {
		so := opts.SuriOptions
		so.Logger, so.LogTee, so.LogOutput = log, opts.LogTee, a.shipper
		if cfg.ControllerFromManager() {
			if a.ctl, err = newControllerSource(cfg.OpenPicket.URL, a.statePath("controller.json"), log); err != nil {
				return nil, err
			}
			so.Controller = a.ctl
		}
		if a.suri, err = suriagent.New(ctx, cfg.Suri, so); err != nil {
			return nil, err
		}
	}
	key, created, err := sshkey.LoadOrGenerate(cfg.Node.KeyFile, cfg.Node.NodeID)
	if err != nil {
		return nil, fmt.Errorf("agent key: %w", err)
	}
	a.pub = key.Public(cfg.Node.NodeID).String()
	if created {
		log.Info("generated agent key; register this public key in OpenPicket", "public_key", a.pub)
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
	a.host = opts.Host
	fw4 := false
	if a.host == nil {
		a.host = hostAccess(cfg.Node)
		fw4 = platform.Probe(ctx, a.host.FS, a.host.Exec).Fw4
	}
	if opts.Fw4 != nil {
		fw4 = *opts.Fw4
	}
	a.fw4 = fw4
	a.wan = nft.NewWAN(cfg.OpenPicket.WANInterfaces...)
	if fw4 {
		a.zoneDevs = a.loadZoneDevices()
		a.wan.Set(append(slices.Clone(cfg.OpenPicket.WANInterfaces), a.zoneDevs...))
		a.refreshWAN(ctx)
	} else if len(cfg.OpenPicket.WANInterfaces) == 0 {
		if cfg.Suri != nil {
			return nil, errors.New("openpicket.wan_interfaces: required without OpenWrt fw4 (fw4_zones applies to fw4 only)")
		}
		// Without Suricata and without a WAN (a server shipping its logs):
		// nothing to filter.
		log.Info("no WAN interface: NFLOG, bans and port policies are off (set openpicket.wan_interfaces to use them)")
		cfg.OpenPicket.Nflog.Enabled, cfg.OpenPicket.Enforcer.Enabled, cfg.OpenPicket.Policy.Enabled = false, false, false
	}
	if len(cfg.OpenPicket.LogSources) > 0 {
		var srcs []logsrc.Source
		for _, s := range cfg.OpenPicket.LogSources {
			src := logsrc.Source{Program: s.Program, Path: s.Path, Listen: s.Listen}
			if s.Journal != nil {
				src.Journal, src.Matches = true, s.Journal.Matches
			}
			if src.Path == "" && src.Program == "" {
				src.Program = "syslog"
			}
			srcs = append(srcs, src)
		}
		root := ""
		if cfg.Node.Docker() {
			root = cfg.Node.Platform.HostRoot
		}
		if a.logs, err = logsrc.New(logsrc.Config{Sources: srcs, Root: root, StateFile: a.statePath("log-positions.json"), Logger: log}); err != nil {
			return nil, err
		}
	}
	if n := cfg.OpenPicket.Nflog; n.Enabled {
		groups := []uint16{nflog.GroupWANReject}
		if cfg.OpenPicket.Policy.Enabled {
			groups = append(groups, nflog.GroupPolicyDrop)
		}
		if cfg.OpenPicket.Enforcer.Enabled && cfg.OpenPicket.Enforcer.EgressBlock {
			groups = append(groups, nflog.GroupBanEgress)
		}
		a.nflog = nflog.New(nflog.Config{Groups: groups, AggregateWindow: n.AggregateWindow, Output: a.shipper,
			Nets: func() *direction.Nets { return a.nets.Load() }, Logger: log})
		mode := n.InstallRule
		if mode == "auto" {
			mode = "nftables"
			if fw4 {
				mode = "fw4"
			}
		}
		if mode != "none" {
			a.reject = &nft.WANReject{Host: a.host, Mode: mode, WAN: a.wan, Zones: cfg.OpenPicket.Fw4Zones, Rate: n.Rate, Burst: n.Burst,
				Group: nflog.GroupWANReject, IgnorePorts: n.IgnorePorts, WithoutSocketCheck: n.WithoutSocketCheck}
		}
	}
	hosts := []string{cfg.OpenPicket.URL}
	if cfg.Suri != nil {
		hosts = append(hosts, cfg.Suri.Controller.URL)
	}
	a.allow = newAllowlist(cfg.OpenPicket.Allowlist, hosts, log)
	if a.ctl != nil {
		a.allow.learn(a.ctl.URL())
		a.ctl.onChange = func(u string) {
			if a.allow.learn(u) {
				go a.allow.refresh(context.Background())
			}
		}
	}
	a.allow.refresh(ctx)
	if e := cfg.OpenPicket.Enforcer; e.Enabled {
		a.enf = enforcer.New(enforcer.Config{
			Host: a.host, Table: nft.BanConfig{WAN: a.wan, Egress: e.EgressBlock},
			Allow: a.allow.Prefixes, Nets: func() *direction.Nets { return a.nets.Load() },
			MaxElements: e.MaxElements, StateFile: a.statePath("decisions.json"), Logger: log,
		})
	}
	if p := cfg.OpenPicket.Policy; p.Enabled {
		a.pol = policy.New(policy.Config{
			Host: a.host, Table: nft.PolicyConfig{WAN: a.wan}, Allow: a.allow.Prefixes,
			MaxElements: p.MaxElements, StateFile: a.statePath("policy.pb"), Logger: log,
		})
	}
	handlers := dataplane.Handlers{Hello: a.hello, Status: a.status, LogPolicy: a.shipper.SetPolicy, Shipper: a.shipper}
	if a.ctl != nil {
		handlers.Controller = a.ctl.Set
	}
	if a.enf != nil {
		handlers.Decisions = a.enf
	}
	if a.pol != nil {
		handlers.Policy = a.pol
	}
	a.client = dataplane.NewClient(dataplane.DialConfig{
		URL: cfg.OpenPicket.URL, Headers: headers, HTTPClient: client, Key: key, ServerKey: hostKey,
		NodeID: cfg.Node.NodeID, Version: version.Version,
	}, handlers, log)
	a.refreshNets()
	return a, nil
}

// hostAccess reaches the host like the suricontroller agent does: through
// chroot and the /host mount in the docker profile.
func hostAccess(n config.Node) *nft.Host {
	if n.Docker() {
		return &nft.Host{Exec: platform.ChrootExec{Root: n.Platform.HostRoot, Fallback: platform.LocalExec{}}, FS: platform.HostFS{Root: n.Platform.HostRoot}}
	}
	return &nft.Host{Exec: platform.LocalExec{}, FS: platform.HostFS{Root: "/"}}
}

// statePath is a file of the agent's own state.
func (a *Agent) statePath(name string) string {
	return filepath.Join(a.cfg.Node.StateDir, "openpicket", name)
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
func (a *Agent) PublicKey() string { return a.pub }

// refreshNets recomputes the local networks; it reports a change.
func (a *Agent) refreshNets() bool {
	var instances []collector.Instance
	if a.suri != nil {
		instances = a.suri.Instances()
	}
	ln := localnets.Collect(instances, a.wan.Get(), a.cfg.OpenPicket.LocalNets)
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
	a.log.Info("openpicket-agent starting", "version", version.Version, "node", a.cfg.Node.NodeID, "boot_id", a.bootID, "suricata", a.suri != nil)
	if a.enf != nil {
		// Blocks are back in place before any connection (§1.1 principle 5).
		if err := a.enf.Restore(ctx); err != nil {
			a.log.Error("restore ban table", "err", err)
		}
	}
	if a.pol != nil {
		if err := a.pol.Restore(ctx); err != nil {
			a.log.Error("restore port policies", "err", err)
		}
	}
	var wg sync.WaitGroup
	workers := []func(context.Context){
		a.client.Run,
		a.watchNets,
	}
	if a.suri != nil {
		workers = append(workers, func(ctx context.Context) { _ = a.suri.Run(ctx) })
	}
	if a.logs != nil {
		workers = append(workers, func(ctx context.Context) {
			defer a.logs.Close()
			if err := a.shipper.ShipSources(ctx, a.logs); err != nil {
				a.log.Error("log sources stopped", "err", err)
			}
		})
	}
	if a.nflog != nil {
		workers = append(workers, a.nflog.Run)
	}
	if a.nat != nil {
		workers = append(workers, a.nat.Run)
	}
	if a.reject != nil {
		workers = append(workers, a.keepWANReject)
	}
	if a.enf != nil || a.pol != nil {
		workers = append(workers, a.allow.run)
	}
	if a.enf != nil {
		workers = append(workers, a.enf.Run)
	}
	if a.pol != nil {
		workers = append(workers, a.pol.Run)
	}
	for _, fn := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}
	wg.Wait()
	return nil
}

// keepWANReject installs the WAN-REJECT log rule and puts it back when it
// disappears (fw4 reload, manual flush).
func (a *Agent) keepWANReject(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		if err := a.reject.Ensure(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("install WAN-REJECT log rule", "mode", a.reject.Mode, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// lookupNAT finds the translation of a connection for the shipper.
func (a *Agent) lookupNAT(proto uint8, client, server netip.AddrPort) (natmap.Mapping, bool) {
	m, ok := a.nat.Table.Lookup(proto, client, server)
	if ok {
		a.natHits.Add(1)
	} else {
		a.natMisses.Add(1)
	}
	return m, ok
}

// watchNets follows HOME_NET and address changes (DHCP, PPPoE), and the
// devices of the fw4 WAN zones.
func (a *Agent) watchNets(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if a.refreshWAN(ctx) {
			a.applyWAN(ctx)
			a.client.PokeStatus()
		}
		if a.refreshNets() {
			a.log.Info("local networks changed", "home_net", a.localNets.Load().HomeNet, "addresses", a.localNets.Load().InterfaceAddrs)
			// Blocks on addresses that became local are lifted (and ones
			// that stopped being local come back) now, not at the next
			// periodic check.
			if a.enf != nil {
				if err := a.enf.Ensure(ctx); err != nil && ctx.Err() == nil {
					a.log.Warn("re-check bans after a network change", "err", err)
				}
			}
			a.client.PokeStatus()
		}
	}
}

func (a *Agent) hello() *dataplanev1.Hello {
	h := &dataplanev1.Hello{
		NodeId: a.cfg.Node.NodeID, AgentVersion: version.Version, BootId: a.bootID,
		LocalNets: a.localNets.Load(), WanInterfaces: a.wan.Get(), Capabilities: a.capabilities(),
	}
	if a.suri != nil {
		sh := a.suri.Hello()
		h.Platform, h.Engine, h.LogSources, h.Warnings = sh.GetPlatform(), sh.GetEngine(), a.suri.LogSources(), sh.GetWarnings()
	} else {
		h.Platform = platformInfo(a.cfg.Node)
	}
	for _, p := range localnets.UncoveredIPv6(a.nets.Load(), a.wan.Get()) {
		h.Warnings = append(h.Warnings, warning("ipv6_not_local", "IPv6 prefix "+p+" is not in HOME_NET or openpicket.local_nets: its hosts look external"))
	}
	return h
}

func (a *Agent) capabilities() []string {
	caps := []string{"logs"}
	if a.suri != nil {
		caps = append(caps, "suricata")
	}
	if a.logs != nil {
		caps = append(caps, "log_sources")
	}
	if a.nflog != nil {
		caps = append(caps, "nflog")
	}
	if a.enf != nil {
		caps = append(caps, "enforcer")
	}
	if a.pol != nil {
		caps = append(caps, "policy")
	}
	return caps
}

func (a *Agent) status(ctx context.Context) *dataplanev1.Status {
	st := &dataplanev1.Status{
		TimeUnixMs:    time.Now().UnixMilli(),
		LocalNets:     a.localNets.Load(),
		Logs:          a.shipper.Stats(),
		WanInterfaces: a.wan.Get(),
	}
	if a.suri != nil {
		st.Suricata = a.suri.Status(ctx)
	}
	if a.logs != nil {
		for _, s := range a.logs.Status() {
			st.LogSources = append(st.LogSources, &dataplanev1.LogSourceStatus{Program: s.Program, Path: s.Path, Files: uint32(s.Files),
				Lines: s.Lines, Truncated: s.Truncated, Dropped: s.Dropped, LastError: s.LastError})
		}
	}
	if a.nflog != nil {
		st.Nflog = a.nflog.Status()
		if a.reject != nil {
			st.Nflog.RuleError = a.reject.Err()
		}
	}
	if a.enf != nil {
		st.Enforcer = a.enf.Status()
	}
	if a.pol != nil {
		st.Policy = a.pol.Status(ctx)
	}
	if a.nat != nil {
		ts, ns := a.nat.Table.Stats(), a.nat.State()
		st.Nat = &dataplanev1.NatStatus{Enabled: true, Ready: ns.Ready, Flows: uint64(ts.Flows), Dropped: ts.Dropped,
			Hits: a.natHits.Load(), Misses: a.natMisses.Load(), Resyncs: ns.Resyncs, LastError: ns.LastErr}
	}
	return st
}

func warning(code, msg string) *agentv1.Warning { return &agentv1.Warning{Code: code, Message: msg} }

// ReopenLogs asks Suricata to reopen its log files (SIGHUP after an
// external logrotate).
func (a *Agent) ReopenLogs() {
	if a.suri != nil {
		a.suri.ReopenLogs()
	}
}

// platformInfo describes the host when the suricontroller agent (which
// reports it with Suricata) does not run.
func platformInfo(n config.Node) *agentv1.PlatformInfo {
	p := &agentv1.PlatformInfo{Profile: n.Platform.Profile, Arch: runtime.GOARCH, FirewallBackend: n.Platform.Firewall}
	p.Hostname, _ = os.Hostname()
	root := "/"
	if n.Docker() {
		root = n.Platform.HostRoot
	}
	if b, err := os.ReadFile(filepath.Join(root, "etc/os-release")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "NAME":
				p.OsName = v
			case "VERSION_ID":
				p.OsVersion = v
			}
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		p.Kernel = strings.TrimSpace(string(b))
	}
	return p
}
