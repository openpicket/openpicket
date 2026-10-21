package nflog

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

// Packet holds the header fields of a logged packet.
type Packet struct {
	IPVersion int
	Proto     string
	Src, Dst  netip.Addr
	SrcPort   int
	DstPort   int
	TCPFlags  string
	TTL       int
	Length    int
	ICMPType  int
}

var errShort = errors.New("nflog: truncated packet")

// ParsePacket decodes the IP and transport headers of a network-layer
// payload (snaplen 128 is plenty).
func ParsePacket(b []byte) (*Packet, error) {
	if len(b) < 1 {
		return nil, errShort
	}
	var (
		p     Packet
		proto byte
		l4    []byte
	)
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return nil, errShort
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return nil, errShort
		}
		p.IPVersion = 4
		p.Length = int(binary.BigEndian.Uint16(b[2:4]))
		p.TTL = int(b[8])
		proto = b[9]
		p.Src = netip.AddrFrom4([4]byte(b[12:16]))
		p.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		// Only the first fragment carries the transport header.
		if binary.BigEndian.Uint16(b[6:8])&0x1fff == 0 {
			l4 = b[ihl:]
		}
	case 6:
		if len(b) < 40 {
			return nil, errShort
		}
		p.IPVersion = 6
		p.Length = int(binary.BigEndian.Uint16(b[4:6])) + 40
		p.TTL = int(b[7])
		proto = b[6]
		p.Src = netip.AddrFrom16([16]byte(b[8:24]))
		p.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		l4 = b[40:]
		// Skip common extension headers.
		for i := 0; i < 4; i++ {
			switch proto {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(l4) < 8 {
					l4 = nil
					break
				}
				proto, l4 = l4[0], l4[(int(l4[1])+1)*8:]
				continue
			case 44: // fragment
				if len(l4) < 8 {
					l4 = nil
					break
				}
				frag := binary.BigEndian.Uint16(l4[2:4]) &^ 7
				proto, l4 = l4[0], l4[8:]
				if frag != 0 {
					l4 = nil
				}
				continue
			}
			break
		}
	default:
		return nil, errors.New("nflog: not an IP packet")
	}
	switch proto {
	case 6:
		p.Proto = "TCP"
		if len(l4) >= 14 {
			p.SrcPort, p.DstPort = int(binary.BigEndian.Uint16(l4[0:2])), int(binary.BigEndian.Uint16(l4[2:4]))
			p.TCPFlags = tcpFlags(l4[13])
		}
	case 17:
		p.Proto = "UDP"
		if len(l4) >= 4 {
			p.SrcPort, p.DstPort = int(binary.BigEndian.Uint16(l4[0:2])), int(binary.BigEndian.Uint16(l4[2:4]))
		}
	case 132:
		p.Proto = "SCTP"
		if len(l4) >= 4 {
			p.SrcPort, p.DstPort = int(binary.BigEndian.Uint16(l4[0:2])), int(binary.BigEndian.Uint16(l4[2:4]))
		}
	case 1:
		p.Proto = "ICMP"
		if len(l4) >= 1 {
			p.ICMPType = int(l4[0])
		}
	case 58:
		p.Proto = "IPv6-ICMP"
		if len(l4) >= 1 {
			p.ICMPType = int(l4[0])
		}
	default:
		p.Proto = "IP-" + itoa(int(proto))
	}
	return &p, nil
}

func tcpFlags(f byte) string {
	var b strings.Builder
	for i, c := range "FSRPAUEC" {
		if f&(1<<i) != 0 {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
