package enforcer

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/openpicket/openpicket/agent/nft"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
)

var t0 = time.Unix(1_800_000_000, 0)

func rangeEntry(v string, d time.Duration) Entry {
	return Entry{Value: v, Range: true, Deadline: t0.Add(d)}
}

func pieces(ps []Piece) map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, p := range ps {
		out[p.Prefix.String()] = p.Deadline.Sub(t0)
	}
	return out
}

func TestDecomposeNested(t *testing.T) {
	// The review case: a long /25 inside a short /24.
	got := pieces(Decompose([]Entry{rangeEntry("198.51.100.0/24", time.Minute), rangeEntry("198.51.100.0/25", time.Hour)}))
	want := map[string]time.Duration{"198.51.100.0/25": time.Hour, "198.51.100.128/25": time.Minute}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// A short range inside a long one adds nothing.
	got = pieces(Decompose([]Entry{rangeEntry("198.51.100.0/24", time.Hour), rangeEntry("198.51.100.64/26", time.Minute)}))
	if len(got) != 1 || got["198.51.100.0/24"] != time.Hour {
		t.Fatalf("contained shorter range: %v", got)
	}
	// Deeply nested, IPv6 too.
	got = pieces(Decompose([]Entry{rangeEntry("2001:db8::/32", time.Minute), rangeEntry("2001:db8:1::/48", time.Hour)}))
	// 16 complementary prefixes and the /48 itself.
	if got["2001:db8:1::/48"] != time.Hour || len(got) != 17 {
		t.Fatalf("ipv6: %d pieces %v", len(got), got)
	}
}

// TestDecomposeProperty checks every address of a small space against a
// brute-force maximum.
func TestDecomposeProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	base := netip.MustParseAddr("10.0.0.0").As4()
	for round := 0; round < 300; round++ {
		var es []Entry
		for i := 0; i < 1+r.IntN(12); i++ {
			bits := 24 + r.IntN(9)
			a := base
			a[3] = byte(r.IntN(256))
			p := netip.PrefixFrom(netip.AddrFrom4(a), bits).Masked()
			es = append(es, rangeEntry(p.String(), time.Duration(1+r.IntN(5))*time.Minute))
		}
		ps := Decompose(es)
		for host := 0; host < 256; host++ {
			a := base
			a[3] = byte(host)
			addr := netip.AddrFrom4(a)
			var want time.Time
			for _, e := range es {
				if netip.MustParsePrefix(e.Value).Contains(addr) && e.Deadline.After(want) {
					want = e.Deadline
				}
			}
			var hits int
			var got time.Time
			for _, p := range ps {
				if p.Prefix.Contains(addr) {
					hits++
					got = p.Deadline
				}
			}
			if want.IsZero() && hits != 0 || !want.IsZero() && (hits != 1 || !got.Equal(want)) {
				t.Fatalf("round %d, %s: %d pieces, deadline %v, want %v\nranges %v\npieces %v", round, addr, hits, got, want, es, pieces(ps))
			}
		}
	}
}

func BenchmarkDecompose(b *testing.B) {
	r := rand.New(rand.NewPCG(3, 4))
	var es []Entry
	for i := 0; i < 100_000; i++ {
		a := netip.AddrFrom4([4]byte{byte(1 + r.IntN(220)), byte(r.IntN(256)), byte(r.IntN(256)), 0})
		es = append(es, rangeEntry(netip.PrefixFrom(a, 16+r.IntN(9)).Masked().String(), time.Duration(1+r.IntN(1000))*time.Minute))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decompose(es)
	}
}

// largeEnforcer holds 100,000 addresses and 20,000 ranges.
func largeEnforcer(b *testing.B) *Enforcer {
	r := rand.New(rand.NewPCG(5, 6))
	var ds []*dataplanev1.Decision
	for i := 0; i < 100_000; i++ {
		a := netip.AddrFrom4([4]byte{byte(1 + r.IntN(220)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256))})
		ds = append(ds, &dataplanev1.Decision{Value: a.String(), Scope: dataplanev1.Scope_SCOPE_IP, TtlMs: int64(1+r.IntN(1000)) * 60_000, Origin: "crowdsec"})
	}
	for i := 0; i < 20_000; i++ {
		a := netip.AddrFrom4([4]byte{byte(1 + r.IntN(220)), byte(r.IntN(256)), byte(r.IntN(256)), 0})
		p := netip.PrefixFrom(a, 16+r.IntN(9)).Masked()
		ds = append(ds, &dataplanev1.Decision{Value: p.String(), Scope: dataplanev1.Scope_SCOPE_RANGE, TtlMs: int64(1+r.IntN(1000)) * 60_000, Origin: "crowdsec"})
	}
	c := &clock{t: t0}
	e := New(Config{Host: &nft.Host{Exec: &recExec{}}, Table: nft.BanConfig{WAN: nft.NewWAN("wan")}, Now: c.now, MaxElements: 200_000,
		Logger: slog.New(slog.DiscardHandler)})
	ctx := context.Background()
	_ = e.Restore(ctx)
	if _, err := e.ApplySnapshot(ctx, &dataplanev1.DecisionSnapshot{Version: 1, Decisions: ds}); err != nil {
		b.Fatal(err)
	}
	return e
}

// BenchmarkApplyDelta measures one delta against the large set (nft itself
// not included): an address, then a range (its set is decomposed again).
func BenchmarkApplyDelta(b *testing.B) {
	for _, kind := range []string{"address", "range"} {
		b.Run(kind, func(b *testing.B) {
			e := largeEnforcer(b)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				v := uint64(i + 1)
				up := &dataplanev1.Decision{Value: fmt.Sprintf("203.0.%d.%d", (i/250)%250, i%250), Scope: dataplanev1.Scope_SCOPE_IP, TtlMs: 3_600_000}
				if kind == "range" {
					up = &dataplanev1.Decision{Value: fmt.Sprintf("203.%d.%d.0/24", (i/250)%250, i%250), Scope: dataplanev1.Scope_SCOPE_RANGE, TtlMs: 3_600_000}
				}
				if _, err := e.ApplyDelta(ctx, &dataplanev1.DecisionDelta{FromVersion: v, ToVersion: v + 1, Upserts: []*dataplanev1.Decision{up}}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEnsure measures the full recomputation (every minute, and on
// network changes).
func BenchmarkEnsure(b *testing.B) {
	e := largeEnforcer(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := e.Ensure(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
