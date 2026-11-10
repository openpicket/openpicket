// Package allowsync is the protocol keeping a CrowdSec LAPI allowlist equal
// to the central allowlist (docs/ARCHITECTURE.md §4.7): openpicket-manager
// PUTs the whole state to the openpicket-crowdsec-sync of a LAPI container,
// which applies the difference with cscli (the LAPI API only reads
// allowlists).
package allowsync

import (
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// Path of the allowlist endpoint of openpicket-crowdsec-sync.
const Path = "/allowlist"

// Name and Description of the LAPI allowlist the manager owns. Other
// allowlists (Helm, cscli, the console) are left alone.
const (
	Name        = "openpicket"
	Description = "Managed by openpicket-manager (central allowlist); changes made here are overwritten."
)

// Tolerance between a wanted and a stored expiry: cscli takes a duration,
// so the stored one moves by the time the command takes.
const Tolerance = 2 * time.Minute

// Item is one allowlisted value.
type Item struct {
	// Value is an address or a CIDR range (Value).
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
	// ExpiresAt is nil for an item that never expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// State is the content of the allowlist.
type State struct {
	Items []Item `json:"items"`
}

// Result reports what applying a state changed.
type Result struct {
	// Created is set when the allowlist did not exist.
	Created bool `json:"created,omitempty"`
	Added   int  `json:"added"`
	Removed int  `json:"removed"`
	// Items in the allowlist afterwards.
	Items int `json:"items"`
}

// Value returns the form CrowdSec stores for a network: the bare address
// of a single address, the CIDR otherwise.
func Value(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// Check validates an item value: a canonical address or CIDR range
// (cscli refuses invalid values with exit status 0).
func Check(v string) error {
	if p, err := netip.ParsePrefix(v); err == nil {
		if p.Masked() != p || Value(p) != v || p.Addr().Is4In6() {
			return fmt.Errorf("allowlist value %q is not canonical", v)
		}
		return nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil || a.Zone() != "" || a.Is4In6() || a.String() != v {
		return fmt.Errorf("allowlist value %q is not an address or a CIDR range", v)
	}
	return nil
}

func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	d := a.Sub(*b)
	return d <= Tolerance && d >= -Tolerance
}

// Diff returns the values to remove from have and the items to add to
// reach want. An item whose description or expiry changed is removed and
// added again (cscli does not update items). Items of want that already
// ran out at now are left out.
func Diff(want, have []Item, now time.Time) (remove []string, add []Item) {
	cur := map[string]Item{}
	for _, it := range have {
		cur[it.Value] = it
	}
	wanted := map[string]bool{}
	for _, it := range want {
		if it.ExpiresAt != nil && !it.ExpiresAt.After(now) {
			continue
		}
		wanted[it.Value] = true
		h, ok := cur[it.Value]
		if ok && h.Description == it.Description && sameExpiry(h.ExpiresAt, it.ExpiresAt) {
			continue
		}
		if ok {
			remove = append(remove, it.Value)
		}
		add = append(add, it)
	}
	for v := range cur {
		if !wanted[v] {
			remove = append(remove, v)
		}
	}
	sort.Strings(remove)
	sort.Slice(add, func(i, j int) bool { return add[i].Value < add[j].Value })
	return remove, add
}
