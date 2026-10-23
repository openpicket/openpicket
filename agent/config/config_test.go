package config

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

func sample(firewall, extra string) string {
	k, _ := sshkey.Generate()
	m, _ := sshkey.Generate()
	return fmt.Sprintf(`
node_id: router-01
controller:
  url: wss://picket.example.com/agent/v1/connect
  host_key: %q
platform:
  profile: docker
%s
openpicket:
  url: wss://picket.example.com/agent/data/v1/connect
  host_key: %q
  wan_interfaces: [wan, wan6]
  allowlist: [192.168.0.0/16, controller]
%s
`, k.Public("suri-controller").String(), firewall, m.Public("openpicket-manager").String(), extra)
}

func TestParse(t *testing.T) {
	c, err := Parse([]byte(sample("", "")))
	if err != nil {
		t.Fatal(err)
	}
	if c.Suri.NodeID != "router-01" || c.Suri.Platform.Firewall != "nftables" {
		t.Fatalf("suri = %+v", c.Suri.Platform)
	}
	o := c.OpenPicket
	if len(o.WANInterfaces) != 2 || !o.Nflog.Enabled || o.Nflog.Rate != "30/minute" || o.Logs.InflightMaxBytes != 4<<20 || !o.Enforcer.EgressBlock ||
		!slices.Equal(o.Fw4Zones, []string{"wan"}) {
		t.Fatalf("openpicket = %+v", o)
	}
	c, err = Parse([]byte(sample("", "  fw4_zones: [wan, wan_lte]\n  nflog: {ignore_ports: [22, 51820]}")))
	if err != nil || len(c.OpenPicket.Fw4Zones) != 2 || len(c.OpenPicket.Nflog.IgnorePorts) != 2 {
		t.Fatalf("options: %+v %v", c.OpenPicket, err)
	}
	// OpenWrt: the zones alone name the WAN.
	c, err = Parse([]byte(noWAN(sample("", ""))))
	if err != nil || len(c.OpenPicket.WANInterfaces) != 0 {
		t.Fatalf("zones only: %v", err)
	}
}

func noWAN(s string) string { return strings.Replace(s, "  wan_interfaces: [wan, wan6]\n", "", 1) }

func TestFirewallBackends(t *testing.T) {
	if _, err := Parse([]byte(sample("  firewall: iptables", ""))); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("iptables: %v", err)
	}
	c, err := Parse([]byte(sample("  firewall: auto", "")))
	if err != nil || c.Suri.Platform.Firewall != "nftables" {
		t.Fatalf("auto: %v %v", err, c)
	}
	if _, err := Parse([]byte(sample("  firewall: none", ""))); err == nil {
		t.Fatal("none with enforcer enabled must be rejected")
	}
	if _, err := Parse([]byte(sample("  firewall: none", "  enforcer: {enabled: false}\n  policy: {enabled: false}"))); err != nil {
		t.Fatalf("none without enforcement: %v", err)
	}
}

func TestValidation(t *testing.T) {
	for _, extra := range []string{
		"  unknown_key: 1",
		"  local_nets: [not-a-net]",
		"  nflog: {rate: fast}",
		"  nflog: {install_rule: iptables}",
		"  fw4_zones: [\"wan; drop\"]",
		"  nflog: {ignore_ports: [0]}",
		"  nflog: {ignore_ports: [70000]}",
	} {
		if _, err := Parse([]byte(sample("", extra))); err == nil {
			t.Errorf("accepted %q", extra)
		}
	}
	for _, extra := range []string{"  fw4_zones: []", "  wan_interfaces: [\"eth0 }\"]", "  wan_interfaces: [\"*\"]"} {
		if _, err := Parse([]byte(noWAN(sample("", extra)))); err == nil {
			t.Errorf("accepted %q", extra)
		}
	}
	if _, err := Parse([]byte(noWAN(sample("", "  wan_interfaces: [eth1, \"wg*\"]")))); err != nil {
		t.Errorf("wildcard: %v", err)
	}
}

func TestControllerFromManager(t *testing.T) {
	c, err := Parse([]byte(sample("", "")))
	if err != nil || c.ControllerFromManager() {
		t.Fatalf("controller section: %v", err)
	}
	// Without a controller section the manager hands out the endpoint, and
	// channel A goes the way of channel B.
	s := sample("", "  headers: {CF-Access-Client-Id: abc}\n  tls_insecure_skip_verify: true")
	start := strings.Index(s, "controller:\n")
	end := strings.Index(s, "platform:")
	c, err = Parse([]byte(s[:start] + s[end:]))
	if err != nil {
		t.Fatal(err)
	}
	if !c.ControllerFromManager() || c.Suri.Controller.Headers["CF-Access-Client-Id"] != "abc" || !c.Suri.Controller.TLSInsecureSkipVerify {
		t.Fatalf("controller = %+v", c.Suri.Controller)
	}
	// Half a controller section is an error.
	half := s[:start] + "controller:\n  url: wss://picket.example.com/agent/v1/connect\n" + s[end:]
	if _, err := Parse([]byte(half)); err == nil || !strings.Contains(err.Error(), "controller.host_key") {
		t.Fatalf("half controller section: %v", err)
	}
}

func withoutSuricata(top, extra string) string {
	m, _ := sshkey.Generate()
	return fmt.Sprintf(`%s
openpicket:
  url: wss://picket.example.com/agent/data/v1/connect
  host_key: %q
  suricata: { enabled: false }
%s
`, top, m.Public("openpicket-manager").String(), extra)
}

func TestWithoutSuricata(t *testing.T) {
	c, err := Parse([]byte(withoutSuricata("node_id: web-01", "  log_sources:\n    - { program: nginx, path: \"/var/log/nginx/*access.log\" }\n    - { program: syslog, path: /var/log/auth.log }")))
	if err != nil {
		t.Fatal(err)
	}
	if c.Suri != nil || c.Node.NodeID != "web-01" || c.Node.KeyFile != DefaultKeyFile || c.Node.StateDir != DefaultStateDir ||
		c.Node.Docker() || len(c.OpenPicket.LogSources) != 2 || c.ControllerFromManager() {
		t.Fatalf("config = %+v %+v", c.Node, c.OpenPicket.LogSources)
	}
	for name, cfg := range map[string]string{
		"suricontroller section": withoutSuricata("node_id: web-01\ninterfaces: [{name: eth0}]", ""),
		"no node id":             withoutSuricata("key_file: /k", ""),
		"relative path":          withoutSuricata("node_id: web-01", "  log_sources: [{program: nginx, path: access.log}]"),
		"bad program":            withoutSuricata("node_id: web-01", "  log_sources: [{program: \"Nginx Logs\", path: /a.log}]"),
		"same path twice":        withoutSuricata("node_id: web-01", "  log_sources: [{program: a, path: /a.log}, {program: b, path: /a.log}]"),
		"bad glob":               withoutSuricata("node_id: web-01", "  log_sources: [{program: a, path: \"/a/[x\"}]"),
		"iptables":               withoutSuricata("node_id: web-01\nplatform: {firewall: iptables}", ""),
	} {
		if _, err := Parse([]byte(cfg)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// With Suricata, log sources work too and Node mirrors the top level.
	c, err = Parse([]byte(sample("", "  log_sources: [{program: uhttpd, path: /var/log/uhttpd.log}]")))
	if err != nil || c.Suri == nil || c.Node.NodeID != "router-01" || len(c.OpenPicket.LogSources) != 1 {
		t.Fatalf("with Suricata: %v %+v", err, c.Node)
	}
}
