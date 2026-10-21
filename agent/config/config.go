// Package config loads agent.yaml: the suricontroller agent settings plus an
// "openpicket" section for channel B, NFLOG, the enforcer and port policies.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	suricfg "github.com/jc-lab/suricontroller/agent/config"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

// Config is the whole agent configuration.
type Config struct {
	// Suri is the suricontroller agent configuration (channel A).
	Suri *suricfg.Config
	// OpenPicket is the "openpicket" section.
	OpenPicket OpenPicket
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
	// cannot change them.
	WANInterfaces []string `yaml:"wan_interfaces"`
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
		// Fw4Zone is the fw4 zone of the WAN (default "wan"): the rule is
		// appended to its input chain.
		Fw4Zone string `yaml:"fw4_zone"`
		// IgnorePorts are destination ports never logged, e.g. services
		// open on the WAN when nft_socket is unavailable.
		IgnorePorts []uint16 `yaml:"ignore_ports"`
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
}

func defaults() OpenPicket {
	var o OpenPicket
	o.WANInterfaces = []string{"wan"}
	o.Logs.InflightMaxBytes = 4 << 20
	o.Nflog.Enabled = true
	o.Nflog.InstallRule = "auto"
	o.Nflog.Rate = "30/minute"
	o.Nflog.Burst = 10
	o.Nflog.Fw4Zone = "wan"
	o.Enforcer.Enabled = true
	o.Enforcer.EgressBlock = true
	o.Enforcer.MaxElements = 100000
	o.Policy.Enabled = true
	o.Policy.MaxElements = 200000
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
	suri, err := suricfg.Parse(rest)
	if err != nil {
		return nil, err
	}
	c := &Config{Suri: suri, OpenPicket: op}
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

var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)

func (c *Config) validate() error {
	o := &c.OpenPicket
	var errs []error
	if o.URL == "" {
		errs = append(errs, errors.New("openpicket.url is required"))
	} else if !strings.HasPrefix(o.URL, "ws://") && !strings.HasPrefix(o.URL, "wss://") {
		errs = append(errs, errors.New("openpicket.url must start with ws:// or wss://"))
	}
	if _, err := sshkey.ParsePublicKey(o.HostKey); err != nil {
		errs = append(errs, fmt.Errorf("openpicket.host_key: %w", err))
	}
	if len(o.WANInterfaces) == 0 {
		errs = append(errs, errors.New("openpicket.wan_interfaces must name at least one interface"))
	}
	for _, n := range o.WANInterfaces {
		if !ifaceRe.MatchString(n) {
			errs = append(errs, fmt.Errorf("openpicket.wan_interfaces: invalid name %q", n))
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
	if !zoneRe.MatchString(o.Nflog.Fw4Zone) {
		errs = append(errs, fmt.Errorf("openpicket.nflog.fw4_zone: invalid zone name %q", o.Nflog.Fw4Zone))
	}
	if slices.Contains(o.Nflog.IgnorePorts, 0) {
		errs = append(errs, errors.New("openpicket.nflog.ignore_ports: ports are 1-65535"))
	}
	if o.Enforcer.MaxElements < 1 || o.Policy.MaxElements < 1 {
		errs = append(errs, errors.New("openpicket: max_elements must be positive"))
	}
	if c.Suri.Platform.Firewall == "none" && (o.Enforcer.Enabled || o.Policy.Enabled) {
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
