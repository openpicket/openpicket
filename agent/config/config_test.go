package config

import (
	"fmt"
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
		o.Nflog.Fw4Zone != "wan" {
		t.Fatalf("openpicket = %+v", o)
	}
	c, err = Parse([]byte(sample("", "  nflog: {fw4_zone: wan_pppoe, ignore_ports: [22, 51820]}")))
	if err != nil || c.OpenPicket.Nflog.Fw4Zone != "wan_pppoe" || len(c.OpenPicket.Nflog.IgnorePorts) != 2 {
		t.Fatalf("nflog options: %+v %v", c.OpenPicket.Nflog, err)
	}
}

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
		"  nflog: {fw4_zone: \"wan; drop\"}",
		"  nflog: {ignore_ports: [0]}",
		"  nflog: {ignore_ports: [70000]}",
	} {
		if _, err := Parse([]byte(sample("", extra))); err == nil {
			t.Errorf("accepted %q", extra)
		}
	}
}
