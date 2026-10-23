package natmap

import (
	"net/netip"
	"testing"
	"time"
)

func ep(s string) Endpoint { return netip.MustParseAddrPort(s) }

// An inside host behind masquerade, and a port forward.
var (
	snat = Flow{ID: 1, Proto: ProtoTCP, SNAT: true,
		OrigSrc: ep("192.168.1.50:51515"), OrigDst: ep("162.243.103.246:443"),
		ReplySrc: ep("162.243.103.246:443"), ReplyDst: ep("125.131.127.16:40123")}
	dnat = Flow{ID: 2, Proto: ProtoTCP, DNAT: true,
		OrigSrc: ep("198.51.100.4:50000"), OrigDst: ep("125.131.127.16:587"),
		ReplySrc: ep("192.168.1.20:2587"), ReplyDst: ep("198.51.100.4:50000")}
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTable(retention time.Duration, max int) (*Table, *clock) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	t := NewTable(retention, max)
	t.now = c.now
	return t, c
}

func TestLookupBothSides(t *testing.T) {
	tb, _ := newTable(time.Minute, 10)
	tb.Add(snat)
	tb.Add(dnat)
	for _, c := range []struct {
		name           string
		client, server string
		typ            string
		inside, public string
	}{
		// Captured on the WAN: after SNAT, before DNAT.
		{"outbound on the WAN", "125.131.127.16:40123", "162.243.103.246:443", "snat", "192.168.1.50:51515", "125.131.127.16:40123"},
		{"port forward on the WAN", "198.51.100.4:50000", "125.131.127.16:587", "dnat", "192.168.1.20:2587", "125.131.127.16:587"},
		// Captured inside (IPS on forward): before SNAT, after DNAT.
		{"outbound inside", "192.168.1.50:51515", "162.243.103.246:443", "snat", "192.168.1.50:51515", "125.131.127.16:40123"},
		{"port forward inside", "198.51.100.4:50000", "192.168.1.20:2587", "dnat", "192.168.1.20:2587", "125.131.127.16:587"},
	} {
		m, ok := tb.Lookup(ProtoTCP, ep(c.client), ep(c.server))
		if !ok || m.Type != c.typ || m.Inside != ep(c.inside) || m.Public != ep(c.public) {
			t.Errorf("%s: %+v %v", c.name, m, ok)
		}
	}
	if _, ok := tb.Lookup(ProtoUDP, ep("125.131.127.16:40123"), ep("162.243.103.246:443")); ok {
		t.Error("another protocol matched")
	}
	if _, ok := tb.Lookup(ProtoTCP, ep("162.243.103.246:443"), ep("125.131.127.16:40123")); ok {
		t.Error("the server -> client view matched")
	}
}

func TestRetentionAndLimit(t *testing.T) {
	tb, c := newTable(10*time.Minute, 2)
	tb.Add(snat)
	tb.End(snat.ID)
	c.t = c.t.Add(9 * time.Minute)
	tb.Add(dnat)
	if _, ok := tb.Lookup(ProtoTCP, ep("125.131.127.16:40123"), ep("162.243.103.246:443")); !ok {
		t.Fatal("ended flow forgotten within the retention")
	}
	// Full: the oldest ended flow makes room.
	third := snat
	third.ID, third.OrigSrc, third.ReplyDst = 3, ep("192.168.1.51:1000"), ep("125.131.127.16:40124")
	tb.Add(third)
	if _, ok := tb.Lookup(ProtoTCP, ep("125.131.127.16:40123"), ep("162.243.103.246:443")); ok {
		t.Fatal("ended flow kept beyond the limit")
	}
	if _, ok := tb.Lookup(ProtoTCP, ep("125.131.127.16:40124"), ep("162.243.103.246:443")); !ok {
		t.Fatal("new flow not added")
	}
	// Full of live flows: new ones are dropped and counted.
	fourth := third
	fourth.ID = 4
	tb.Add(fourth)
	if st := tb.Stats(); st.Flows != 2 || st.Dropped != 1 {
		t.Fatalf("stats = %+v", st)
	}
	// Past the retention, ended flows go.
	tb.End(dnat.ID)
	c.t = c.t.Add(11 * time.Minute)
	tb.Add(fourth)
	if _, ok := tb.Lookup(ProtoTCP, ep("198.51.100.4:50000"), ep("125.131.127.16:587")); ok {
		t.Fatal("ended flow kept past the retention")
	}
}

func TestSyncEndsMissingFlows(t *testing.T) {
	tb, c := newTable(time.Minute, 10)
	tb.Add(snat)
	tb.Add(dnat)
	// The DESTROY of snat was lost: the listing no longer has it.
	tb.Sync([]Flow{dnat})
	c.t = c.t.Add(2 * time.Minute)
	tb.Add(dnat)
	if _, ok := tb.Lookup(ProtoTCP, ep("125.131.127.16:40123"), ep("162.243.103.246:443")); ok {
		t.Fatal("a flow missing from the listing was kept")
	}
	if _, ok := tb.Lookup(ProtoTCP, ep("198.51.100.4:50000"), ep("125.131.127.16:587")); !ok {
		t.Fatal("a listed flow was dropped")
	}
	// An id reused by a new flow replaces the old one's index.
	reused := dnat
	reused.OrigSrc, reused.ReplyDst = ep("198.51.100.5:1"), ep("198.51.100.5:1")
	tb.Add(reused)
	if _, ok := tb.Lookup(ProtoTCP, ep("198.51.100.4:50000"), ep("125.131.127.16:587")); ok {
		t.Fatal("stale index after an id was reused")
	}
}
