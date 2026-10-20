package nflog

import (
	"encoding/binary"
	"testing"
)

func ipv4TCP(src, dst [4]byte, sport, dport uint16, flags byte) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 40)
	b[8] = 51
	b[9] = 6
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[20:22], sport)
	binary.BigEndian.PutUint16(b[22:24], dport)
	b[33] = flags
	return b
}

func TestParseIPv4TCP(t *testing.T) {
	p, err := ParsePacket(ipv4TCP([4]byte{198, 51, 100, 4}, [4]byte{203, 0, 113, 10}, 51234, 3389, 0x02))
	if err != nil {
		t.Fatal(err)
	}
	if p.IPVersion != 4 || p.Proto != "TCP" || p.Src.String() != "198.51.100.4" || p.Dst.String() != "203.0.113.10" ||
		p.SrcPort != 51234 || p.DstPort != 3389 || p.TCPFlags != "S" || p.TTL != 51 || p.Length != 40 {
		t.Fatalf("packet = %+v", p)
	}
}

func TestParseIPv6UDPWithExtension(t *testing.T) {
	b := make([]byte, 40+8+8)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], 16)
	b[6] = 0 // hop-by-hop
	b[7] = 64
	b[8], b[9] = 0x20, 0x01
	b[24], b[25] = 0x20, 0x01
	b[39] = 1
	b[40] = 17 // next: UDP
	b[41] = 0  // length 8
	binary.BigEndian.PutUint16(b[48:50], 5353)
	binary.BigEndian.PutUint16(b[50:52], 53)
	p, err := ParsePacket(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.IPVersion != 6 || p.Proto != "UDP" || p.DstPort != 53 || p.SrcPort != 5353 || p.Dst.String() != "2001::1" {
		t.Fatalf("packet = %+v", p)
	}
}

func TestParseRejects(t *testing.T) {
	for _, b := range [][]byte{nil, {0x45, 0}, {0x70}} {
		if _, err := ParsePacket(b); err == nil {
			t.Errorf("accepted %v", b)
		}
	}
	if itoa(47) != "47" || tcpFlags(0x12) != "SA" {
		t.Fatal("helpers")
	}
}
