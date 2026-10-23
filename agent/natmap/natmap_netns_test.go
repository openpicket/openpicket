package natmap

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func sh(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// TestNetnsNAT routes real connections through masquerade and a port
// forward and finds them, from conntrack events, as the WAN and the LAN
// see them (scripts/netns-test.sh).
func TestNetnsNAT(t *testing.T) {
	if os.Getenv("OPENPICKET_TEST_NETNS") != "1" {
		t.Skip("OPENPICKET_TEST_NETNS not set")
	}
	// lan (192.168.1.50) <-> router (this namespace) <-> inet (203.0.113.2).
	sh(t, "ip", "link", "set", "lo", "up")
	for _, ns := range []string{"lan", "inet"} {
		sh(t, "ip", "netns", "add", ns)
		sh(t, "ip", "-n", ns, "link", "set", "lo", "up")
	}
	sh(t, "ip", "link", "add", "br-lan", "type", "veth", "peer", "name", "lanpeer")
	sh(t, "ip", "link", "set", "lanpeer", "netns", "lan")
	sh(t, "ip", "addr", "add", "192.168.1.1/24", "dev", "br-lan")
	sh(t, "ip", "link", "set", "br-lan", "up")
	sh(t, "ip", "-n", "lan", "addr", "add", "192.168.1.50/24", "dev", "lanpeer")
	sh(t, "ip", "-n", "lan", "link", "set", "lanpeer", "up")
	sh(t, "ip", "-n", "lan", "route", "add", "default", "via", "192.168.1.1")
	sh(t, "ip", "link", "add", "wan", "type", "veth", "peer", "name", "peer")
	sh(t, "ip", "link", "set", "peer", "netns", "inet")
	sh(t, "ip", "addr", "add", "203.0.113.1/24", "dev", "wan")
	sh(t, "ip", "link", "set", "wan", "up")
	sh(t, "ip", "-n", "inet", "addr", "add", "203.0.113.2/24", "dev", "peer")
	sh(t, "ip", "-n", "inet", "link", "set", "peer", "up")
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	nat := "table inet nat_test {\n" +
		"\tchain pre {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tiifname \"wan\" tcp dport 587 dnat ip to 192.168.1.50:2587\n\t}\n" +
		"\tchain post {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname \"wan\" masquerade\n\t}\n}\n"
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nat)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nat: %v %s", err, out)
	}
	for _, l := range [][]string{{"ip", "netns", "exec", "inet", "nc", "-lk", "9000"}, {"ip", "netns", "exec", "lan", "nc", "-lk", "2587"}} {
		c := exec.Command(l[0], l[1:]...)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill() })
	}
	time.Sleep(300 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr := &Tracker{Table: NewTable(time.Minute, 1000)}
	go tr.Run(ctx)
	waitUntil(t, func() bool { return tr.State().Ready }, "tracker ready: "+tr.State().LastErr)

	// Both connections start after the listing: they arrive as events.
	if out, err := exec.Command("ip", "netns", "exec", "lan", "nc", "-z", "-w", "2", "-p", "51515", "203.0.113.2", "9000").CombinedOutput(); err != nil {
		t.Fatalf("outbound: %v %s", err, out)
	}
	if out, err := exec.Command("ip", "netns", "exec", "inet", "nc", "-z", "-w", "2", "-p", "50000", "203.0.113.1", "587").CombinedOutput(); err != nil {
		t.Fatalf("port forward: %v %s", err, out)
	}
	var m Mapping
	var ok bool
	waitUntil(t, func() bool {
		// As the WAN sees it: the node's address, masquerade keeping the
		// port when it is free.
		m, ok = tr.Table.Lookup(ProtoTCP, ep("203.0.113.1:51515"), ep("203.0.113.2:9000"))
		return ok
	}, "outbound connection not found")
	if m.Type != "snat" || m.Inside != ep("192.168.1.50:51515") || m.Public != ep("203.0.113.1:51515") {
		t.Fatalf("outbound: %+v", m)
	}
	waitUntil(t, func() bool {
		m, ok = tr.Table.Lookup(ProtoTCP, ep("203.0.113.2:50000"), ep("203.0.113.1:587"))
		return ok
	}, "port forward not found")
	if m.Type != "dnat" || m.Inside != ep("192.168.1.50:2587") || m.Public != ep("203.0.113.1:587") {
		t.Fatalf("port forward: %+v", m)
	}
	// As the LAN side sees the port forward.
	if m, ok := tr.Table.Lookup(ProtoTCP, ep("203.0.113.2:50000"), ep("192.168.1.50:2587")); !ok || m.Public != ep("203.0.113.1:587") {
		t.Fatalf("port forward inside: %+v %v", m, ok)
	}
}

func waitUntil(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
