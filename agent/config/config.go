// Package config loads agent.yaml: the suricontroller agent settings plus an
// "openpicket" section for channel B, NFLOG, the enforcer, port policies
// and log sources. With openpicket.suricata.enabled false the agent runs
// without Suricata and without the suricontroller agent; the top level
// then holds the node settings only (Node).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	suricfg "github.com/jc-lab/suricontroller/agent/config"
	"github.com/jc-lab/suricontroller/pkg/nodeid"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/agent/nft"
	"github.com/openpicket/openpicket/pkg/record"
)

// Config is the whole agent configuration.
type Config struct {
	// Suri is the suricontroller agent configuration (channel A); nil when
	// Suricata is disabled.
	Suri *suricfg.Config
	// Node holds the settings used whether or not Suricata runs.
	Node Node
	// OpenPicket is the "openpicket" section.
	OpenPicket OpenPicket
}

// Node is the node's identity and local paths.
type Node struct {
	NodeID   string `yaml:"node_id"`
	KeyFile  string `yaml:"key_file"`
	StateDir string `yaml:"state_dir"`
	LogLevel string `yaml:"log_level"`
	Platform struct {
		// Profile: docker (host reached through HostRoot) or a direct
		// install (systemd-native, openwrt-native).
		Profile  string `yaml:"profile"`
		HostRoot string `yaml:"host_root"`
		Firewall string `yaml:"firewall"`
	} `yaml:"platform"`
}

// Docker reports the docker profile: host files under HostRoot.
func (n Node) Docker() bool { return n.Platform.Profile == suricfg.ProfileDocker }

// LogSource is a generic log the agent ships: a file (path), the systemd
// journal or a local syslog listener.
type LogSource struct {
	// Program wrote the lines (nginx, postgres); "syslog" for files in
	// syslog format (auth.log), whose lines name their program. The
	// journal and a listener are "syslog" (the default for them).
	Program string `yaml:"program"`
	// Path of the file; a glob takes every match (new files too).
	Path string `yaml:"path"`
	// Journal follows the systemd journal with journalctl, from the last
	// acknowledged entry (new entries only the first time).
	Journal *JournalSource `yaml:"journal"`
	// Listen receives syslog datagrams on a UDP address, e.g. OpenWrt's
	// system log (system.@system[0].log_ip/log_port). Nothing replays
	// them: messages sent while the agent is down are lost.
	Listen string `yaml:"listen"`
}

// JournalSource selects journal entries.
type JournalSource struct {
	// Matches are journalctl matches ("_SYSTEMD_UNIT=sshd.service",
	// "SYSLOG_IDENTIFIER=sshd", "+" between alternatives); none: all.
	Matches []string `yaml:"matches"`
}

// Kind names the source in errors.
func (s LogSource) Kind() string {
	switch {
	case s.Journal != nil:
		return "journal"
	case s.Listen != "":
		return "listen " + s.Listen
	}
	return s.Path
}

func validLogSource(s LogSource) error {
	kinds := 0
	for _, set := range []bool{s.Path != "", s.Journal != nil, s.Listen != ""} {
		if set {
			kinds++
		}
	}
	if kinds != 1 {
		return errors.New("set one of path, journal and listen")
	}
	if s.Path == "" {
		// The journal and listeners give syslog lines.
		if s.Program != "" && s.Program != "syslog" {
			return fmt.Errorf("program %q: the journal and listeners give syslog lines (program syslog)", s.Program)
		}
	} else if record.NormalizeProgram(s.Program) != strings.ToLower(strings.TrimSpace(s.Program)) || s.Program == "" {
		return fmt.Errorf("program %q: letters, digits, '.', '_', '-' only", s.Program)
	}
	switch {
	case s.Path != "":
		if !filepath.IsAbs(s.Path) {
			return fmt.Errorf("path %q must be absolute", s.Path)
		}
		if _, err := filepath.Match(s.Path, ""); err != nil {
			return err
		}
	case s.Journal != nil:
		for _, m := range s.Journal.Matches {
			// Matches go to journalctl as arguments: no options.
			if m != "+" && (!strings.Contains(m, "=") || strings.HasPrefix(m, "-")) {
				return fmt.Errorf("journal match %q: FIELD=value or +", m)
			}
		}
	default:
		if _, _, err := net.SplitHostPort(s.Listen); err != nil {
			return fmt.Errorf("listen %q: host:port (UDP)", s.Listen)
		}
	}
	return nil
}

// OpenPicket configures the OpenPicket parts of the agent.
type OpenPicket struct {
	// URL of the manager data plane endpoint (ws:// or wss://).
	URL     string            `yaml:"url"`
	HostKey string            `yaml:"host_key"`
	Headers map[string]string `yaml:"headers"`
	CAFile  string            `yaml:"ca_file"`
	// TLSInsecureSkipVerify skips TLS verification (Noise still
	// authenticates the manager).
	TLSInsecureSkipVerify bool `yaml:"tls_insecure_skip_verify"`

	// WANInterfaces are the interfaces facing the internet: NFLOG, ban and
	// port policies apply to them only. The agent decides; the manager
	// cannot change them. On OpenWrt the devices of Fw4Zones are added.
	WANInterfaces []string `yaml:"wan_interfaces"`
	// Fw4Zones are the OpenWrt fw4 zones facing the internet (default
	// "wan"): their devices are WAN interfaces, followed as they change,
	// and WAN-REJECT logs in their input chains. Ignored without fw4.
	Fw4Zones []string `yaml:"fw4_zones"`
	// LocalNets are extra networks treated as inside, beyond Suricata
	// HOME_NET and the interface addresses.
	LocalNets []string `yaml:"local_nets"`
	// Allowlist is never blocked, whatever the manager sends. "controller"
	// adds the addresses of both controller hosts.
	Allowlist []string `yaml:"allowlist"`

	Logs struct {
		InflightMaxBytes suricfg.ByteSize `yaml:"inflight_max_bytes"`
	} `yaml:"logs"`

	Nflog struct {
		Enabled bool `yaml:"enabled"`
		// InstallRule: auto | fw4 | nftables | none (rule managed by the user).
		InstallRule string `yaml:"install_rule"`
		// Rate is the nftables limit of the WAN-REJECT log rule ("30/minute").
		Rate  string `yaml:"rate"`
		Burst int    `yaml:"burst"`
		// IgnorePorts are destination ports never logged, e.g. services
		// open on the WAN when nft_socket is unavailable.
		IgnorePorts []uint16 `yaml:"ignore_ports"`
		// WithoutSocketCheck keeps WAN-REJECT logging (nftables mode) on a
		// kernel without nft_socket: connections to services open on the
		// WAN are logged too unless listed in IgnorePorts. Off by default:
		// the rule is then left out.
		WithoutSocketCheck bool `yaml:"without_socket_check"`
		// AggregateWindow merges (src_ip, dest_port) repeats; 0 disables.
		AggregateWindow time.Duration `yaml:"aggregate_window"`
	} `yaml:"nflog"`

	Enforcer struct {
		Enabled bool `yaml:"enabled"`
		// EgressBlock also blocks outbound traffic to BOTH decisions.
		EgressBlock bool `yaml:"egress_block"`
		MaxElements int  `yaml:"max_elements"`
	} `yaml:"enforcer"`

	Policy struct {
		Enabled     bool `yaml:"enabled"`
		MaxElements int  `yaml:"max_elements"`
	} `yaml:"policy"`

	// Suricata: false runs the agent without Suricata (a server shipping
	// its logs, a host blocking for itself).
	Suricata struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"suricata"`

	// LogSources are generic logs shipped to the manager (§4.8).
	LogSources []LogSource `yaml:"log_sources"`

	// NATLookup names the other side of the node's NAT in Suricata alerts
	// from conntrack events: the inside host behind an outbound alert
	// captured on the WAN, the public port of a port forward.
	NATLookup struct {
		Enabled bool `yaml:"enabled"`
		// Retention keeps ended connections for records read late.
		Retention  time.Duration `yaml:"retention"`
		MaxEntries int           `yaml:"max_entries"`
	} `yaml:"nat_lookup"`
}

func defaults() OpenPicket {
	var o OpenPicket
	o.Fw4Zones = []string{"wan"}
	o.NATLookup.Enabled = true
	o.NATLookup.Retention = 10 * time.Minute
	o.NATLookup.MaxEntries = 100000
	o.Logs.InflightMaxBytes = 4 << 20
	o.Nflog.Enabled = true
	o.Nflog.InstallRule = "auto"
	o.Nflog.Rate = "30/minute"
	o.Nflog.Burst = 10
	o.Enforcer.Enabled = true
	o.Enforcer.EgressBlock = true
	o.Enforcer.MaxElements = 100000
	o.Policy.Enabled = true
	o.Policy.MaxElements = 200000
	o.Suricata.Enabled = true
	return o
}

// Load reads agent.yaml.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse splits off the openpicket section, lets suricontroller parse the
// rest, and validates both.
func Parse(b []byte) (*Config, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	op := defaults()
	rest := b
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 && root.Content[0].Kind == yaml.MappingNode {
		m := root.Content[0]
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value != "openpicket" {
				continue
			}
			sec, err := yaml.Marshal(m.Content[i+1])
			if err != nil {
				return nil, err
			}
			dec := yaml.NewDecoder(bytes.NewReader(sec))
			dec.KnownFields(true)
			if err := dec.Decode(&op); err != nil && !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("openpicket: %w", err)
			}
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			if rest, err = yaml.Marshal(&root); err != nil {
				return nil, err
			}
			break
		}
	}
	if !op.Suricata.Enabled {
		return parseWithoutSuricata(rest, op)
	}
	// OpenPicket supports nftables only (§7.3): "auto" means nftables.
	var fw struct {
		Platform struct {
			Firewall string `yaml:"firewall"`
		} `yaml:"platform"`
	}
	_ = yaml.Unmarshal(rest, &fw)
	switch fw.Platform.Firewall {
	case "", "auto":
		var err error
		if rest, err = setFirewall(rest, "nftables"); err != nil {
			return nil, err
		}
	case "nftables", "none":
	default:
		return nil, fmt.Errorf("platform.firewall: %q is not supported by OpenPicket (nftables or none)", fw.Platform.Firewall)
	}
	// Without a controller section the manager hands out the endpoint.
	suri, err := suricfg.ParseWith(rest, suricfg.ParseOptions{ExternalController: true})
	if err != nil {
		return nil, err
	}
	c := &Config{Suri: suri, OpenPicket: op}
	c.Node.NodeID, c.Node.KeyFile, c.Node.StateDir, c.Node.LogLevel = suri.NodeID, suri.KeyFile, suri.StateDir, suri.LogLevel
	c.Node.Platform.Profile, c.Node.Platform.HostRoot, c.Node.Platform.Firewall = suri.Platform.Profile, suri.Platform.HostRoot, suri.Platform.Firewall
	if c.ControllerFromManager() {
		// Channel A then goes the way of channel B (same host by default).
		sc := &c.Suri.Controller
		if sc.Headers == nil {
			sc.Headers = op.Headers
		}
		if sc.CAFile == "" {
			sc.CAFile = op.CAFile
		}
		sc.TLSInsecureSkipVerify = sc.TLSInsecureSkipVerify || op.TLSInsecureSkipVerify
	}
	return c, c.validate()
}

// ControllerFromManager reports an agent.yaml without controller url and
// host_key: the manager hands out the endpoint.
func (c *Config) ControllerFromManager() bool {
	return c.Suri != nil && c.Suri.Controller.URL == "" && c.Suri.Controller.HostKey == ""
}

// Defaults of an agent without Suricata (a direct install).
const (
	DefaultKeyFile  = "/etc/openpicket-agent/agent_ed25519"
	DefaultStateDir = "/var/lib/openpicket-agent"
)

// parseWithoutSuricata reads the top level as node settings only: the
// suricontroller sections (controller, interfaces, ips, suricata, logs)
// are refused, so a configuration does not look like it runs Suricata.
func parseWithoutSuricata(rest []byte, op OpenPicket) (*Config, error) {
	c := &Config{OpenPicket: op}
	n := &c.Node
	n.KeyFile, n.StateDir, n.LogLevel = DefaultKeyFile, DefaultStateDir, "info"
	n.Platform.Profile, n.Platform.HostRoot, n.Platform.Firewall = "systemd-native", "/", "nftables"
	dec := yaml.NewDecoder(bytes.NewReader(rest))
	dec.KnownFields(true)
	if err := dec.Decode(n); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w (without Suricata, the top level only has node_id, key_file, state_dir, log_level and platform)", err)
	}
	if n.Platform.Firewall == "" || n.Platform.Firewall == "auto" {
		n.Platform.Firewall = "nftables"
	}
	if n.Platform.Firewall != "nftables" && n.Platform.Firewall != "none" {
		return nil, fmt.Errorf("platform.firewall: %q is not supported by OpenPicket (nftables or none)", n.Platform.Firewall)
	}
	return c, c.validate()
}

func setFirewall(b []byte, value string) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
		return b, nil
	}
	m := root.Content[0]
	var platform *yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == "platform" {
			platform = m.Content[i+1]
		}
	}
	if platform == nil {
		platform = &yaml.Node{Kind: yaml.MappingNode}
		m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "platform"}, platform)
	}
	for i := 0; i+1 < len(platform.Content); i += 2 {
		if platform.Content[i].Value == "firewall" {
			platform.Content[i+1].Value = value
			return yaml.Marshal(&root)
		}
	}
	platform.Content = append(platform.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "firewall"}, &yaml.Node{Kind: yaml.ScalarNode, Value: value})
	return yaml.Marshal(&root)
}

func (c *Config) validate() error {
	o := &c.OpenPicket
	var errs []error
	if err := nodeid.Validate(c.Node.NodeID); err != nil {
		errs = append(errs, fmt.Errorf("node_id: %w", err))
	}
	if c.Node.KeyFile == "" || c.Node.StateDir == "" {
		errs = append(errs, errors.New("key_file and state_dir are required"))
	}
	seen := map[string]bool{}
	for _, s := range o.LogSources {
		if err := validLogSource(s); err != nil {
			errs = append(errs, fmt.Errorf("openpicket.log_sources: %s: %w", s.Kind(), err))
		} else if seen[s.Kind()] {
			errs = append(errs, fmt.Errorf("openpicket.log_sources: %s listed twice", s.Kind()))
		}
		seen[s.Kind()] = true
	}
	if o.URL == "" {
		errs = append(errs, errors.New("openpicket.url is required"))
	} else if !strings.HasPrefix(o.URL, "ws://") && !strings.HasPrefix(o.URL, "wss://") {
		errs = append(errs, errors.New("openpicket.url must start with ws:// or wss://"))
	}
	if _, err := sshkey.ParsePublicKey(o.HostKey); err != nil {
		errs = append(errs, fmt.Errorf("openpicket.host_key: %w", err))
	}
	if len(o.WANInterfaces) == 0 && len(o.Fw4Zones) == 0 {
		errs = append(errs, errors.New("openpicket: name the WAN in wan_interfaces or fw4_zones"))
	}
	for _, n := range o.WANInterfaces {
		if !nft.ValidIfname(n) {
			errs = append(errs, fmt.Errorf("openpicket.wan_interfaces: invalid name %q", n))
		}
	}
	for _, z := range o.Fw4Zones {
		if !zoneRe.MatchString(z) {
			errs = append(errs, fmt.Errorf("openpicket.fw4_zones: invalid zone name %q", z))
		}
	}
	for _, s := range o.LocalNets {
		if !validNet(s) {
			errs = append(errs, fmt.Errorf("openpicket.local_nets: invalid network %q", s))
		}
	}
	for _, s := range o.Allowlist {
		if s != "controller" && !validNet(s) {
			errs = append(errs, fmt.Errorf("openpicket.allowlist: invalid network %q", s))
		}
	}
	switch o.Nflog.InstallRule {
	case "auto", "fw4", "nftables", "none":
	default:
		errs = append(errs, fmt.Errorf("openpicket.nflog.install_rule: unknown %q", o.Nflog.InstallRule))
	}
	if !rateRe.MatchString(o.Nflog.Rate) {
		errs = append(errs, fmt.Errorf("openpicket.nflog.rate: invalid %q (e.g. 30/minute)", o.Nflog.Rate))
	}
	if o.Nflog.Burst < 1 {
		errs = append(errs, errors.New("openpicket.nflog.burst must be at least 1"))
	}
	if slices.Contains(o.Nflog.IgnorePorts, 0) {
		errs = append(errs, errors.New("openpicket.nflog.ignore_ports: ports are 1-65535"))
	}
	if o.NATLookup.Retention <= 0 || o.NATLookup.MaxEntries < 1 {
		errs = append(errs, errors.New("openpicket.nat_lookup: retention and max_entries must be positive"))
	}
	if o.Enforcer.MaxElements < 1 || o.Policy.MaxElements < 1 {
		errs = append(errs, errors.New("openpicket: max_elements must be positive"))
	}
	if c.Node.Platform.Firewall == "none" && (o.Enforcer.Enabled || o.Policy.Enabled) {
		errs = append(errs, errors.New("platform.firewall none: disable openpicket.enforcer and openpicket.policy"))
	}
	return errors.Join(errs...)
}

var rateRe = regexp.MustCompile(`^[0-9]{1,6}/(second|minute|hour|day)$`)

// zoneRe matches fw4 zone names.
var zoneRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,11}$`)

func validNet(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}
