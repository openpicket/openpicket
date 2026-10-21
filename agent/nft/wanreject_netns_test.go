package nft

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/agent/platform"
)

func run(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// probe connects from the "inet" namespace with source src to the router.
func probe(src string, port int) bool {
	return exec.Command("ip", "netns", "exec", "inet", "nc", "-z", "-w", "2", "-s", src, "203.0.113.1", fmt.Sprint(port)).Run() == nil
}

var counterRe = regexp.MustCompile(`counter packets (\d+)`)

// logged returns the packet counter of the WAN-REJECT rule in a table.
func logged(t *testing.T, family, table string) int {
	t.Helper()
	out, err := exec.Command("nft", "list", "table", family, table).CombinedOutput()
	if err != nil {
		t.Fatalf("list %s: %v %s", table, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, WANRejectPrefix) {
			if m := counterRe.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[1])
				return n
			}
		}
	}
	t.Fatalf("no WAN-REJECT rule in %s:\n%s", table, out)
	return 0
}

// TestNetnsWANReject checks with real packets that only refused
// connections are logged: in the standalone table (no fw4) and in a copy
// of fw4's chain layout with an Allow rule and a source-restricted port
// forward (scripts/netns-test.sh).
func TestNetnsWANReject(t *testing.T) {
	if os.Getenv("OPENPICKET_TEST_NETNS") != "1" {
		t.Skip("OPENPICKET_TEST_NETNS not set")
	}
	// Router (this namespace) <- veth "wan" -> internet namespace "inet"
	// with two sources: "kr" (allowed to 587) and "other".
	const kr, other = "1.0.0.5", "203.0.113.2"
	// Other kernel tests of this package leave their tables behind (the
	// container is thrown away).
	run(t, "nft", "flush", "ruleset")
	run(t, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "add", "inet")
	run(t, "ip", "link", "add", "wan", "type", "veth", "peer", "name", "peer")
	run(t, "ip", "link", "set", "peer", "netns", "inet")
	run(t, "ip", "addr", "add", "203.0.113.1/24", "dev", "wan")
	run(t, "ip", "link", "set", "wan", "up")
	run(t, "ip", "-n", "inet", "link", "set", "lo", "up")
	run(t, "ip", "-n", "inet", "addr", "add", other+"/24", "dev", "peer")
	run(t, "ip", "-n", "inet", "addr", "add", kr+"/32", "dev", "peer")
	run(t, "ip", "-n", "inet", "link", "set", "peer", "up")
	run(t, "ip", "route", "add", kr+"/32", "via", other)
	run(t, "ip", "-n", "inet", "route", "add", "default", "via", "203.0.113.1")
	// An open service on the WAN (SSH) and the mail server behind 587.
	for _, port := range []string{"2222", "2587"} {
		l := exec.Command("nc", "-lk", port)
		if err := l.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Process.Kill() })
	}
	time.Sleep(300 * time.Millisecond)
	ctx := context.Background()
	h := &Host{Exec: platform.LocalExec{}}

	t.Run("nftables", func(t *testing.T) {
		w := &WANReject{Host: h, Mode: "nftables", WAN: []string{"wan"}, Rate: "100/second", Burst: 100, Group: 100}
		if err := w.Ensure(ctx); err != nil {
			t.Fatal(err)
		}
		if w.noSocket {
			t.Fatal("nft_socket unavailable on this kernel")
		}
		if !probe(other, 2222) {
			t.Fatal("open service unreachable")
		}
		if n := logged(t, "inet", NflogTable); n != 0 && !w.noSocket {
			t.Fatalf("a connection to an open service was logged (%d)", n)
		}
		before := logged(t, "inet", NflogTable)
		if probe(other, 2300) {
			t.Fatal("closed port answered")
		}
		if n := logged(t, "inet", NflogTable); n != before+1 {
			t.Fatalf("closed port: counter %d -> %d", before, n)
		}
		if err := w.Remove(ctx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("fw4", func(t *testing.T) {
		w := &WANReject{Host: h, Mode: "fw4", Rate: "100/second", Burst: 100, Group: 100}
		// fw4's layout: Allow-SSH and accepted redirections in input_wan,
		// the snippet appended, then the zone's reject.
		fw4 := "table inet fw4 {\n" +
			"\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tiif lo accept\n" +
			"\t\tct state vmap { established : accept, related : accept }\n\t\tiifname \"wan\" jump input_wan\n\t}\n" +
			"\tchain input_wan {\n\t\ttcp dport 2222 accept comment \"Allow-SSH\"\n" +
			"\t\tct status dnat accept comment \"!fw4: Accept port redirections\"\n\t\t" + strings.TrimSpace(w.Fw4Snippet()) +
			"\n\t\tjump reject_from_wan\n\t}\n" +
			"\tchain reject_from_wan {\n\t\tiifname \"wan\" counter reject\n\t}\n" +
			// 587 only for KR sources, redirected to the local mail server.
			"\tchain dstnat {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n" +
			"\t\tiifname \"wan\" ip saddr " + kr + " tcp dport 587 redirect to :2587\n\t}\n}\n"
		if err := h.Apply(ctx, fw4); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.Apply(ctx, "delete table inet fw4\n") })
		cases := []struct {
			name   string
			src    string
			port   int
			ok     bool
			logged bool
		}{
			{"allowed service (SSH)", other, 2222, true, false},
			{"KR to 587 (redirected)", kr, 587, true, false},
			{"other to 587 (not redirected)", other, 587, false, true},
			{"closed port", other, 2300, false, true},
		}
		for _, c := range cases {
			before := logged(t, "inet", "fw4")
			if got := probe(c.src, c.port); got != c.ok {
				t.Fatalf("%s: connected=%v, want %v", c.name, got, c.ok)
			}
			if n := logged(t, "inet", "fw4") - before; (n == 1) != c.logged {
				t.Fatalf("%s: logged %d, want logged=%v", c.name, n, c.logged)
			}
		}
	})
}
