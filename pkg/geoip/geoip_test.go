package geoip

import (
	"bytes"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// testDB builds a small database (MaxMind databases are not shipped).
func testDB(t *testing.T, typ string, entries map[string]mmdbtype.Map) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: typ, RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, rec := range entries {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.Insert(n, rec); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func country(cc string) mmdbtype.Map {
	return mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(cc)}}
}

func asn(n uint32, org string) mmdbtype.Map {
	return mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(n), "autonomous_system_organization": mmdbtype.String(org)}
}

// TestDatabases builds the databases used by other tests too.
func TestDatabases(t *testing.T) {
	cdata := testDB(t, "GeoLite2-Country", map[string]mmdbtype.Map{
		"1.0.0.0/25": country("CN"), "1.0.0.128/25": country("CN"), // siblings: merged
		"1.0.2.0/24": country("CN"), "2.0.0.0/16": country("KR"), "2001:db8:aa::/48": country("KR"),
	})
	adata := testDB(t, "GeoLite2-ASN", map[string]mmdbtype.Map{
		"8.8.8.0/24": asn(15169, "GOOGLE"), "8.8.4.0/24": asn(15169, "GOOGLE"), "2.0.1.0/24": asn(4766, "KT"),
	})
	ci, err := Inspect(cdata)
	if err != nil || ci.Kind != KindCountry {
		t.Fatalf("inspect country: %+v %v", ci, err)
	}
	if ai, err := Inspect(adata); err != nil || ai.Kind != KindASN {
		t.Fatalf("inspect asn: %+v %v", ai, err)
	}
	if _, err := Inspect([]byte("nope")); err == nil {
		t.Fatal("garbage accepted")
	}
	db, err := Open(cdata, adata)
	if err != nil {
		t.Fatal(err)
	}
	if l := db.Lookup("2.0.1.5"); l == nil || l.Country != "KR" || l.ASN != 4766 || l.ASOrg != "KT" {
		t.Fatalf("lookup = %+v", l)
	}
	if l := db.Lookup("::ffff:1.0.0.9"); l == nil || l.Country != "CN" {
		t.Fatalf("mapped lookup = %+v", l)
	}
	if db.Lookup("9.9.9.9") != nil {
		t.Fatal("unknown address found")
	}
	cn, _ := db.Country("cn")
	if want := []netip.Prefix{netip.MustParsePrefix("1.0.0.0/24"), netip.MustParsePrefix("1.0.2.0/24")}; !slices.Equal(cn, want) {
		t.Fatalf("CN = %v", cn)
	}
	kr, _ := db.Country("KR")
	if len(kr) != 2 {
		t.Fatalf("KR = %v", kr)
	}
	g, _ := db.ASN(15169)
	if len(g) != 2 {
		t.Fatalf("AS15169 = %v", g)
	}
	empty, _ := Open(nil, nil)
	if _, err := empty.Country("CN"); err != ErrNoDatabase {
		t.Fatalf("no db: %v", err)
	}
}

func TestAggregate(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/25"), netip.MustParsePrefix("10.0.0.128/25"), // -> /24
		netip.MustParsePrefix("10.0.1.0/24"),    // -> with above /23
		netip.MustParsePrefix("10.0.0.5/32"),    // contained
		netip.MustParsePrefix("192.168.1.7/24"), // masked
	}
	got := Aggregate(in)
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/23"), netip.MustParsePrefix("192.168.1.0/24")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
}
