package allowlist

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
	"github.com/openpicket/openpicket/pkg/allowsync"
)

func TestParseNetwork(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":            "192.0.2.7/32",
		" 192.0.2.7/24 ":       "192.0.2.0/24",
		"::ffff:192.0.2.7":     "192.0.2.7/32",
		"::ffff:192.0.2.0/120": "192.0.2.0/24",
		"2001:db8::1":          "2001:db8::1/128",
		"2001:db8::1/32":       "2001:db8::/32",
	} {
		p, err := ParseNetwork(in)
		if err != nil || p.String() != want {
			t.Errorf("ParseNetwork(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for _, in := range []string{"", "example.com", "192.0.2.0/33", "fe80::1%eth0", "::ffff:0:0/90"} {
		if _, err := ParseNetwork(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseNetwork(%q) err = %v", in, err)
		}
	}
}

func TestValidate(t *testing.T) {
	for _, c := range []struct {
		network string
		wide    bool
		ok      bool
	}{
		{"10.0.0.0/8", false, true},
		{"10.0.0.0/7", false, false},
		{"10.0.0.0/7", true, true},
		{"0.0.0.0/0", true, false},
		{"2001:db8::/32", false, true},
		{"2001::/16", false, false},
		{"2001::/16", true, true},
		{"::/0", true, false},
	} {
		err := Validate(netip.MustParsePrefix(c.network), c.wide)
		if (err == nil) != c.ok {
			t.Errorf("Validate(%s, wide=%v) = %v", c.network, c.wide, err)
		}
	}
}

func TestSetCovering(t *testing.T) {
	s := Set{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	for v, want := range map[string]int{
		"192.0.2.7":       1, // inside
		"192.0.0.0/16":    1, // contains an entry
		"198.51.100.4":    0,
		"2001:db8:1::/48": 1,
		"CN":              0, // not a network
	} {
		if got := len(s.Covering(v)); got != want {
			t.Errorf("Covering(%q) = %d entries, want %d", v, got, want)
		}
	}
}

func TestStore(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	s := New(pool, func() time.Time { return now })

	net := netip.MustParsePrefix("192.0.2.0/24")
	if err := s.Put(ctx, Entry{Network: net, Description: "office"}, false, "alice"); err != nil {
		t.Fatal(err)
	}
	exp := now.Add(time.Hour)
	if err := s.Put(ctx, Entry{Network: netip.MustParsePrefix("2001:db8::/32"), ExpiresAt: exp}, false, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, Entry{Network: netip.MustParsePrefix("198.51.100.0/24"), ExpiresAt: now.Add(-time.Minute)}, false, "alice"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("past expiry: %v", err)
	}
	if err := s.Put(ctx, Entry{Network: netip.MustParsePrefix("10.0.0.0/7")}, false, "alice"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wide network: %v", err)
	}

	// Replacing keeps the author and creation time.
	now = now.Add(time.Minute)
	if err := s.Put(ctx, Entry{Network: net, Description: "office LAN"}, false, "bob"); err != nil {
		t.Fatal(err)
	}

	// Decisions kept off the edge, per entry.
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.lapi_decisions (id, value, scope, type, origin, scenario, until, eligible, both_ways, received_at) VALUES
		(1, '192.0.2.7', 'Ip', 'ban', 'crowdsec', 's', $1, true, false, $2),
		(2, '192.0.2.7', 'Ip', 'ban', 'cscli', 's', $1, true, false, $2),
		(3, '192.0.0.0/16', 'Range', 'ban', 'cscli', 's', $1, true, false, $2),
		(4, '192.0.2.8', 'Ip', 'ban', 'crowdsec', 's', $2, true, false, $2),
		(5, 'CN', 'Country', 'ban', 'cscli', 's', $1, false, false, $2)`, now.Add(4*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
	e := list[0]
	if e.Network != net || e.Description != "office LAN" || e.CreatedBy != "alice" || e.UpdatedBy != "bob" || !e.UpdatedAt.After(e.CreatedAt) || !e.ExpiresAt.IsZero() {
		t.Fatalf("entry = %+v", e)
	}
	// 192.0.2.7 (twice) and the /16; 192.0.2.8 has run out.
	if e.Excluded != 2 {
		t.Fatalf("excluded = %d", e.Excluded)
	}
	if !list[1].ExpiresAt.Equal(exp) || !list[1].Active(now) || list[1].Active(exp) {
		t.Fatalf("expiring entry = %+v", list[1])
	}

	cov, err := s.Covering(ctx, "2001:db8::1")
	if err != nil || len(cov) != 1 {
		t.Fatalf("covering = %v, %v", cov, err)
	}
	now = exp
	if cov, _ := s.Covering(ctx, "2001:db8::1"); len(cov) != 0 {
		t.Fatal("an expired entry still covers")
	}

	if err := s.Delete(ctx, net); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, net); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestLAPISync(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	s := New(pool, func() time.Time { return now })
	exp := now.Add(time.Hour)
	for _, e := range []Entry{
		{Network: netip.MustParsePrefix("192.0.2.0/24"), Description: "office"},
		{Network: netip.MustParsePrefix("198.51.100.7/32"), ExpiresAt: exp},
	} {
		if err := s.Put(ctx, e, false, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	var (
		got  []allowsync.State
		fail bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != allowsync.Path || r.Header.Get("X-OpenPicket-Token") != "tok" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if fail {
			http.Error(w, "cscli: boom", http.StatusInternalServerError)
			return
		}
		var st allowsync.State
		_ = json.NewDecoder(r.Body).Decode(&st)
		got = append(got, st)
		_ = json.NewEncoder(w).Encode(allowsync.Result{Added: len(st.Items), Items: len(st.Items)})
	}))
	defer srv.Close()
	ls := &LAPISync{Store: s, Targets: []Target{{Instance: "default", URL: srv.URL + "/"}}, Header: "X-OpenPicket-Token", Token: "tok"}
	ls.Init()
	if err := ls.Pass(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Items) != 2 {
		t.Fatalf("pushed = %+v", got)
	}
	if it := got[0].Items[1]; it.Value != "198.51.100.7" || it.ExpiresAt == nil || !it.ExpiresAt.Equal(exp) || got[0].Items[0].Description != "office" {
		t.Fatalf("items = %+v", got[0].Items)
	}
	st, err := s.SyncStatuses(ctx)
	if err != nil || st["default"].Error != "" || !st["default"].SyncedAt.Equal(now) || !st["default"].ChangedAt.Equal(now) || st["default"].Items != 2 {
		t.Fatalf("status = %+v %v", st, err)
	}

	// A failed push keeps the last success; expired entries are not sent.
	fail = true
	now = exp
	if err := ls.Pass(ctx, nil); err != nil {
		t.Fatal(err)
	}
	st, _ = s.SyncStatuses(ctx)
	if d := st["default"]; !strings.Contains(d.Error, "boom") || !d.AttemptAt.Equal(exp) || !d.SyncedAt.Equal(exp.Add(-time.Hour)) {
		t.Fatalf("after failure = %+v", d)
	}
	fail = false
	if err := ls.Pass(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got[1].Items) != 1 {
		t.Fatalf("after expiry = %+v", got)
	}
	if st, _ := s.SyncStatuses(ctx); st["default"].Error != "" {
		t.Fatalf("error not cleared: %+v", st)
	}
}
