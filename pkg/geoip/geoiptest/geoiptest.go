// Package geoiptest builds small MaxMind databases for tests (real MaxMind
// data is uploaded by users, never shipped).
package geoiptest

import (
	"bytes"
	"net"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// Country builds a Country database from CIDR -> ISO code.
func Country(t testing.TB, nets map[string]string) []byte {
	t.Helper()
	m := map[string]mmdbtype.Map{}
	for cidr, cc := range nets {
		m[cidr] = mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(cc)}}
	}
	return build(t, "GeoLite2-Country", m)
}

// ASN builds an ASN database from CIDR -> AS number.
func ASN(t testing.TB, nets map[string]uint32) []byte {
	t.Helper()
	m := map[string]mmdbtype.Map{}
	for cidr, n := range nets {
		m[cidr] = mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(n), "autonomous_system_organization": mmdbtype.String("AS-TEST")}
	}
	return build(t, "GeoLite2-ASN", m)
}

func build(t testing.TB, typ string, entries map[string]mmdbtype.Map) []byte {
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
