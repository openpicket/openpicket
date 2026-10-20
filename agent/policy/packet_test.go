package policy

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/agent/platform"

	"github.com/openpicket/openpicket/agent/enforcer"
	"github.com/openpicket/openpicket/agent/nft"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/direction"
	"github.com/openpicket/openpicket/pkg/geoip"
	"github.com/openpicket/openpicket/pkg/geoip/geoiptest"
	"github.com/openpicket/openpicket/pkg/portpolicy"
)

func sh(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// connect reports whether a TCP connection from src (in the wan namespace)
// to the router succeeds.
func connect(ns, src, dst string, port int) bool {
	args := []string{"netns", "exec", ns, "nc", "-z", "-w", "2"}
	if src != "" {
		args = append(args, "-s", src)
	}
	args = append(args, dst, fmt.Sprint(port))
	return exec.Command("ip", args...).Run() == nil
}

// TestPacketPolicyAndBans checks the behavior that matters with real
// packets: port policies match the public port before DNAT, INBOUND bans
// keep replies of connections the node opens, BOTH bans cut everything.
// It needs network namespaces (scripts/netns-test.sh runs it privileged).
func TestPacketPolicyAndBans(t *testing.T) {
	if os.Getenv("OPENPICKET_TEST_NETNS") != "1" {
		t.Skip("OPENPICKET_TEST_NETNS not set")
	}
	// Router (this namespace) <- veth "wan" -> internet namespace "inet".
	sh(t, "ip", "link", "set", "lo", "up")
	sh(t, "ip", "netns", "add", "inet")
	sh(t, "ip", "link", "add", "wan", "type", "veth", "peer", "name", "peer")
	sh(t, "ip", "link", "set", "peer", "netns", "inet")
	sh(t, "ip", "addr", "add", "203.0.113.1/24", "dev", "wan")
	sh(t, "ip", "link", "set", "wan", "up")
	sh(t, "ip", "-n", "inet", "link", "set", "lo", "up")
	sh(t, "ip", "-n", "inet", "addr", "add", "203.0.113.2/24", "dev", "peer")
	internet := map[string]string{"cn": "1.0.0.5", "kr": "2.0.0.5", "banned": "198.51.100.4", "both": "198.51.100.9"}
	for _, a := range internet {
		sh(t, "ip", "-n", "inet", "addr", "add", a+"/32", "dev", "peer")
		sh(t, "ip", "route", "add", a+"/32", "via", "203.0.113.2")
	}
	sh(t, "ip", "-n", "inet", "link", "set", "peer", "up")
	sh(t, "ip", "-n", "inet", "route", "add", "default", "via", "203.0.113.1")

	// A port forward: public 443 -> local 8443.
	nat := "table inet nat_test {\n\tchain pre {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\ttcp dport 443 redirect to :8443\n\t}\n}\n"
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nat)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nat: %v %s", err, out)
	}
	for _, port := range []string{"8443", "587", "2222"} {
		l := exec.Command("nc", "-lk", port)
		if err := l.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Process.Kill() })
	}
	// Servers on the internet side for connections the router opens.
	for _, a := range []string{internet["banned"], internet["both"]} {
		l := exec.Command("ip", "netns", "exec", "inet", "nc", "-lk", a, "9000")
		if err := l.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Process.Kill() })
	}
	time.Sleep(300 * time.Millisecond)
	router := "203.0.113.1"
	if !connect("inet", internet["cn"], router, 443) || !connect("inet", internet["kr"], router, 2222) {
		t.Fatal("baseline connectivity broken")
	}
	for _, a := range []string{internet["banned"], internet["both"]} {
		if out, err := exec.Command("nc", "-z", "-w", "2", a, "9000").CombinedOutput(); err != nil {
			t.Fatalf("baseline: router cannot reach %s:9000: %v %s", a, err, out)
		}
	}

	ctx := context.Background()
	host := &nft.Host{Exec: platform.LocalExec{}}
	geo, err := geoip.Open(
		geoiptest.Country(t, map[string]string{"1.0.0.0/24": "CN", "2.0.0.0/16": "KR"}),
		geoiptest.ASN(t, map[string]uint32{"8.8.8.0/24": 15169}))
	if err != nil {
		t.Fatal(err)
	}
	bundle, skipped := portpolicy.Compile(1, []portpolicy.Policy{
		{ID: "https_block_cn", Enabled: true, Mode: portpolicy.ModeEnforce, Proto: "tcp", Ports: []portpolicy.PortRange{{From: 443, To: 443}},
			Default: portpolicy.ActionAccept, Rules: []portpolicy.Rule{{Source: portpolicy.Source{Countries: []string{"CN"}}, Action: portpolicy.ActionDrop}}},
		{ID: "smtp_submission", Enabled: true, Mode: portpolicy.ModeEnforce, Proto: "tcp", Ports: []portpolicy.PortRange{{From: 587, To: 587}},
			Default: portpolicy.ActionReject, Rules: []portpolicy.Rule{
				{Source: portpolicy.Source{Countries: []string{"KR"}}, Action: portpolicy.ActionAccept},
				{Source: portpolicy.Source{ASNs: []uint32{15169}}, Action: portpolicy.ActionAccept}}},
	}, nil, geo, "edge", nil)
	if len(skipped) > 0 {
		t.Fatal(skipped)
	}
	pol := New(Config{Host: host, Table: nft.PolicyConfig{WAN: []string{"wan"}}, MaxElements: 1000})
	if err := pol.Apply(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	// The policy sees the public port 443, not the redirected 8443.
	if connect("inet", internet["cn"], router, 443) {
		t.Fatal("CN reached 443 through the port forward")
	}
	if !connect("inet", internet["kr"], router, 443) {
		t.Fatal("KR blocked on 443")
	}
	if !connect("inet", internet["kr"], router, 587) || connect("inet", internet["cn"], router, 587) {
		t.Fatal("587: KR must pass, CN must be rejected")
	}

	nets, _ := direction.NewNets([]string{"192.168.1.0/24"})
	enf := enforcer.New(enforcer.Config{Host: host, Table: nft.BanConfig{WAN: []string{"wan"}, Egress: true},
		Nets: func() *direction.Nets { return nets }, Allow: func() []netip.Prefix { return nil }})
	if err := enf.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := enf.ApplySnapshot(ctx, &dataplanev1.DecisionSnapshot{Version: 1, Decisions: []*dataplanev1.Decision{
		{Value: internet["banned"], Scope: dataplanev1.Scope_SCOPE_IP, Direction: dataplanev1.Direction_DIRECTION_INBOUND, TtlMs: time.Hour.Milliseconds()},
		{Value: internet["both"], Scope: dataplanev1.Scope_SCOPE_IP, Direction: dataplanev1.Direction_DIRECTION_BOTH, TtlMs: time.Hour.Milliseconds()},
		// A ban of a KR address overrides the policy accept (ban first).
		{Value: internet["kr"], Scope: dataplanev1.Scope_SCOPE_IP, Direction: dataplanev1.Direction_DIRECTION_INBOUND, TtlMs: time.Hour.Milliseconds()},
	}}); err != nil {
		t.Fatal(err)
	}
	if connect("inet", internet["banned"], router, 2222) {
		t.Fatal("INBOUND-banned source connected")
	}
	if connect("inet", internet["kr"], router, 587) {
		t.Fatal("ban must take precedence over the policy accept")
	}
	// The router itself opens a connection to the INBOUND-banned address:
	// its replies must pass (only connections the remote starts are cut).
	if exec.Command("nc", "-z", "-w", "2", internet["banned"], "9000").Run() != nil {
		t.Fatal("reply of an outbound connection to an INBOUND-banned address was dropped")
	}
	// BOTH cuts both ways.
	if exec.Command("nc", "-z", "-w", "2", internet["both"], "9000").Run() == nil {
		t.Fatal("outbound connection to a BOTH-banned address succeeded")
	}
	if connect("inet", internet["both"], router, 2222) {
		t.Fatal("BOTH-banned source connected")
	}
}
