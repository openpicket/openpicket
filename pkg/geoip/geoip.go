// Package geoip reads the MaxMind databases uploaded to OpenPicket
// (docs/ARCHITECTURE.md §5.6): address lookups for enrichment, and the
// networks of a country or an AS for port policies.
package geoip

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Kinds of database.
const (
	KindCountry = "country" // GeoLite2/GeoIP2 Country or City
	KindASN     = "asn"
)

// Info describes an uploaded database.
type Info struct {
	Kind         string
	DatabaseType string
	BuildEpoch   uint64
	Networks     uint
}

// Inspect validates mmdb data and reports what it is.
func Inspect(data []byte) (*Info, error) {
	r, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, fmt.Errorf("geoip: not a MaxMind database: %w", err)
	}
	defer r.Close()
	t := r.Metadata.DatabaseType
	info := &Info{DatabaseType: t, BuildEpoch: uint64(r.Metadata.BuildEpoch), Networks: r.Metadata.NodeCount}
	switch {
	case strings.Contains(t, "ASN"):
		info.Kind = KindASN
	case strings.Contains(t, "Country") || strings.Contains(t, "City"):
		info.Kind = KindCountry
	default:
		return nil, fmt.Errorf("geoip: unsupported database type %q (want Country, City or ASN)", t)
	}
	return info, nil
}

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// Location of an address.
type Location struct {
	Country string
	ASN     uint32
	ASOrg   string
}

// DB holds the current databases. Either may be missing.
type DB struct {
	country, asn *maxminddb.Reader

	countryOnce sync.Once
	byCountry   map[string][]netip.Prefix
	asnOnce     sync.Once
	byASN       map[uint32][]netip.Prefix
}

// Open loads the databases (nil data: not uploaded).
func Open(countryData, asnData []byte) (*DB, error) {
	d := &DB{}
	var err error
	if countryData != nil {
		if d.country, err = maxminddb.OpenBytes(countryData); err != nil {
			return nil, err
		}
	}
	if asnData != nil {
		if d.asn, err = maxminddb.OpenBytes(asnData); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// HasCountry reports whether a country database is loaded.
func (d *DB) HasCountry() bool { return d != nil && d.country != nil }

// HasASN reports whether an ASN database is loaded.
func (d *DB) HasASN() bool { return d != nil && d.asn != nil }

// Lookup returns the location of an address, or nil.
func (d *DB) Lookup(ip string) *Location {
	if d == nil {
		return nil
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	a = a.Unmap()
	var loc Location
	found := false
	if d.country != nil {
		var rec countryRecord
		if res := d.country.Lookup(a); res.Found() && res.Decode(&rec) == nil {
			loc.Country = rec.Country.ISOCode
			if loc.Country == "" {
				loc.Country = rec.RegisteredCountry.ISOCode
			}
			found = found || loc.Country != ""
		}
	}
	if d.asn != nil {
		var rec asnRecord
		if res := d.asn.Lookup(a); res.Found() && res.Decode(&rec) == nil && rec.Number != 0 {
			loc.ASN, loc.ASOrg, found = rec.Number, rec.Org, true
		}
	}
	if !found {
		return nil
	}
	return &loc
}

// ErrNoDatabase is returned when a policy needs a database that is not
// uploaded.
var ErrNoDatabase = errors.New("geoip: database not uploaded")

func normalize(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked()
	}
	return p.Masked()
}

// Country returns the aggregated networks of an ISO country code.
func (d *DB) Country(cc string) ([]netip.Prefix, error) {
	if !d.HasCountry() {
		return nil, ErrNoDatabase
	}
	d.countryOnce.Do(func() {
		idx := map[string][]netip.Prefix{}
		for res := range d.country.Networks() {
			var rec countryRecord
			if res.Decode(&rec) != nil {
				continue
			}
			c := rec.Country.ISOCode
			if c == "" {
				c = rec.RegisteredCountry.ISOCode
			}
			if c != "" {
				idx[c] = append(idx[c], normalize(res.Prefix()))
			}
		}
		for c, ps := range idx {
			idx[c] = Aggregate(ps)
		}
		d.byCountry = idx
	})
	return d.byCountry[strings.ToUpper(cc)], nil
}

// ASN returns the aggregated networks of an autonomous system.
func (d *DB) ASN(asn uint32) ([]netip.Prefix, error) {
	if !d.HasASN() {
		return nil, ErrNoDatabase
	}
	d.asnOnce.Do(func() {
		idx := map[uint32][]netip.Prefix{}
		for res := range d.asn.Networks() {
			var rec asnRecord
			if res.Decode(&rec) != nil || rec.Number == 0 {
				continue
			}
			idx[rec.Number] = append(idx[rec.Number], normalize(res.Prefix()))
		}
		for n, ps := range idx {
			idx[n] = Aggregate(ps)
		}
		d.byASN = idx
	})
	return d.byASN[asn], nil
}

// Aggregate removes duplicate and contained prefixes and merges sibling
// halves, returning a sorted minimal list.
func Aggregate(in []netip.Prefix) []netip.Prefix {
	ps := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if p.IsValid() {
			ps = append(ps, normalize(p))
		}
	}
	for {
		sort.Slice(ps, func(i, j int) bool {
			if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
				return c < 0
			}
			return ps[i].Bits() < ps[j].Bits()
		})
		out := ps[:0:0]
		for _, p := range ps {
			if n := len(out); n > 0 && out[n-1].Contains(p.Addr()) && out[n-1].Bits() <= p.Bits() {
				continue // contained (or duplicate)
			}
			out = append(out, p)
		}
		merged := false
		res := out[:0:0]
		for i := 0; i < len(out); i++ {
			if i+1 < len(out) && out[i].Bits() == out[i+1].Bits() && out[i].Bits() > 0 {
				parent := netip.PrefixFrom(out[i].Addr(), out[i].Bits()-1).Masked()
				if parent.Addr() == out[i].Addr() && parent.Contains(out[i+1].Addr()) {
					res = append(res, parent)
					i++
					merged = true
					continue
				}
			}
			res = append(res, out[i])
		}
		ps = res
		if !merged {
			return ps
		}
	}
}
