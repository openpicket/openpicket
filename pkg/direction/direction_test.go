package direction

import "testing"

func TestJudge(t *testing.T) {
	nets, bad := NewNets([]string{"192.168.1.0/24", "2001:db8:10::/48"}, []string{"203.0.113.10", "bogus"})
	if len(bad) != 1 || bad[0] != "bogus" {
		t.Fatalf("bad = %v", bad)
	}
	pc, wan, c2, scanner := "192.168.1.50", "203.0.113.10", "198.51.100.9", "198.51.100.4"
	cases := []struct {
		name string
		p    Packet
		want Result
	}{
		{"inbound attack (to_server)", Packet{SrcIP: scanner, DestIP: pc, PacketDirection: "to_server"},
			Result{Inbound, High, scanner, pc}},
		{"C2 request from the PC", Packet{SrcIP: pc, DestIP: c2, PacketDirection: "to_server", FlowSrcIP: pc},
			Result{Outbound, High, c2, pc}},
		// The review case: a C2 reply alert has the server as packet source.
		{"C2 reply with flow info", Packet{SrcIP: c2, DestIP: pc, PacketDirection: "to_client", FlowSrcIP: pc},
			Result{Outbound, High, c2, pc}},
		{"C2 reply, direction field only", Packet{SrcIP: c2, DestIP: pc, PacketDirection: "to_client"},
			Result{Outbound, High, c2, pc}},
		{"no flow information", Packet{SrcIP: c2, DestIP: pc},
			Result{Inbound, Low, c2, pc}},
		{"captured after SNAT on the WAN", Packet{SrcIP: wan, DestIP: c2, FlowSrcIP: wan},
			Result{Outbound, High, c2, wan}},
		{"DNAT miss (nflog)", Packet{SrcIP: scanner, DestIP: wan, SrcIsInitiator: true},
			Result{Inbound, High, scanner, wan}},
		{"lateral movement", Packet{SrcIP: pc, DestIP: "192.168.1.7", FlowSrcIP: pc},
			Result{Internal, High, "", ""}},
		{"transit", Packet{SrcIP: scanner, DestIP: c2, FlowSrcIP: c2},
			Result{Transit, High, c2, ""}},
		{"IPv6 GUA inside", Packet{SrcIP: "2001:db8:10::5", DestIP: "2001:db8:99::1", FlowSrcIP: "2001:db8:10::5"},
			Result{Outbound, High, "2001:db8:99::1", "2001:db8:10::5"}},
		{"IPv4-mapped", Packet{SrcIP: "::ffff:192.168.1.50", DestIP: c2, FlowSrcIP: "::ffff:192.168.1.50"},
			Result{Outbound, High, c2, "::ffff:192.168.1.50"}},
	}
	for _, c := range cases {
		if got := Judge(nets, c.p); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}
