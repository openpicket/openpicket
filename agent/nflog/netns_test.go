package nflog

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestNetnsReceive logs a real packet to an NFLOG group and receives it
// (scripts/netns-test.sh runs it inside a container with CAP_NET_ADMIN).
func TestNetnsReceive(t *testing.T) {
	if os.Getenv("OPENPICKET_TEST_NETNS") != "1" {
		t.Skip("OPENPICKET_TEST_NETNS not set")
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("lo up: %v %s", err, out)
	}
	rules := `table inet t {
	chain o {
		type filter hook output priority 0; policy accept;
		udp dport 9999 log group 100 prefix "DNAT-MISS: " snaplen 128
	}
}`
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v %s", err, out)
	}
	r, err := openNetlink(GroupDNATMiss, nil)
	if err != nil {
		t.Fatalf("open nflog: %v", err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := make(chan Event, 1)
	go func() {
		_ = r.Receive(ctx, func(ev Event) {
			select {
			case got <- ev:
			default:
			}
		})
	}()
	time.Sleep(200 * time.Millisecond)
	c, err := net.Dial("udp", "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("probe"))
	c.Close()
	select {
	case ev := <-got:
		kind, _ := SplitPrefix(ev.Prefix)
		if kind != PrefixDNATMiss || ev.Packet.Proto != "UDP" || ev.Packet.DstPort != 9999 || ev.Packet.Dst.String() != "127.0.0.1" || ev.Group != GroupDNATMiss {
			t.Fatalf("event = %+v packet = %+v", ev, ev.Packet)
		}
	case <-ctx.Done():
		t.Fatal("no NFLOG event received")
	}
}
