package allowsync

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestValueAndCheck(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.7/32": "192.0.2.7", "192.0.2.0/24": "192.0.2.0/24", "2001:db8::1/128": "2001:db8::1", "2001:db8::/32": "2001:db8::/32"} {
		if got := Value(netip.MustParsePrefix(in)); got != want {
			t.Errorf("Value(%s) = %s", in, got)
		}
		if err := Check(want); err != nil {
			t.Errorf("Check(%s): %v", want, err)
		}
	}
	for _, bad := range []string{"", "-e", "--comment=x", "192.0.2.7/24", "192.0.2.7/32", "::ffff:192.0.2.7", "fe80::1%eth0", "2001:DB8::1", "example.com"} {
		if Check(bad) == nil {
			t.Errorf("Check(%q) accepted", bad)
		}
	}
}

func TestDiff(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	want := []Item{
		{Value: "192.0.2.0/24", Description: "office"},                 // unchanged
		{Value: "198.51.100.0/24", ExpiresAt: at(30 * 24 * time.Hour)}, // within the tolerance
		{Value: "203.0.113.0/24", Description: "new text"},             // description changed
		{Value: "10.0.0.0/8", ExpiresAt: at(time.Hour)},                // expiry changed
		{Value: "2001:db8::/32"},                                       // missing
		{Value: "198.18.0.0/15", ExpiresAt: at(-time.Minute)},          // ran out: left out
	}
	have := []Item{
		{Value: "192.0.2.0/24", Description: "office"},
		{Value: "198.51.100.0/24", ExpiresAt: at(30*24*time.Hour + 40*time.Second)},
		{Value: "203.0.113.0/24", Description: "old text"},
		{Value: "10.0.0.0/8"},
		{Value: "100.64.0.0/10"}, // not wanted
		{Value: "198.18.0.0/15", ExpiresAt: at(-time.Minute)},
	}
	remove, add := Diff(want, have, now)
	if wantRemove := []string{"10.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15", "203.0.113.0/24"}; !reflect.DeepEqual(remove, wantRemove) {
		t.Fatalf("remove = %v", remove)
	}
	var added []string
	for _, it := range add {
		added = append(added, it.Value)
	}
	if !reflect.DeepEqual(added, []string{"10.0.0.0/8", "2001:db8::/32", "203.0.113.0/24"}) {
		t.Fatalf("add = %v", added)
	}
	if r, a := Diff(want[:2], have[:2], now); len(r)+len(a) != 0 {
		t.Fatalf("in sync: remove %v add %v", r, a)
	}
}
