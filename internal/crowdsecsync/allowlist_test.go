package crowdsecsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openpicket/openpicket/pkg/allowsync"
)

// fakeCSCLI keeps an allowlist the way cscli does: add skips known values,
// refused values only log.
type fakeCSCLI struct {
	now     time.Time
	exists  bool
	items   map[string]allowsync.Item
	calls   []string
	refuse  string
	lapiOff bool
}

func (f *fakeCSCLI) run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if args[0] != "allowlists" || args[2] != allowsync.Name {
		return nil, errors.New("unexpected command")
	}
	switch args[1] {
	case "inspect":
		if f.lapiOff {
			return nil, errors.New("cscli allowlists inspect: exit status 1: dial tcp 127.0.0.1:8080: connect: connection refused")
		}
		if !f.exists {
			return nil, errors.New("cscli allowlists inspect: exit status 1: unable to get allowlist: API error: allowlist 'openpicket' not found")
		}
		type item struct {
			Value       string    `json:"value"`
			Description string    `json:"description,omitempty"`
			Expiration  time.Time `json:"expiration"`
		}
		var out struct {
			Items []item `json:"items"`
		}
		for _, it := range f.items {
			i := item{Value: it.Value, Description: it.Description}
			if it.ExpiresAt != nil {
				i.Expiration = *it.ExpiresAt
			}
			out.Items = append(out.Items, i)
		}
		return json.Marshal(out)
	case "create":
		f.exists = true
	case "remove":
		for _, v := range args[3:] {
			delete(f.items, v)
		}
	case "add":
		var vals []string
		it := allowsync.Item{}
		for _, a := range args[3:] {
			switch {
			case strings.HasPrefix(a, "--expiration="):
				d, err := time.ParseDuration(strings.TrimPrefix(a, "--expiration="))
				if err != nil {
					return nil, err
				}
				exp := f.now.Add(d)
				it.ExpiresAt = &exp
			case strings.HasPrefix(a, "--comment="):
				it.Description = strings.TrimPrefix(a, "--comment=")
			default:
				vals = append(vals, a)
			}
		}
		for _, v := range vals {
			if _, ok := f.items[v]; ok || v == f.refuse {
				continue
			}
			it.Value = v
			f.items[v] = it
		}
	}
	return nil, nil
}

func TestAllowlisterApply(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	f := &fakeCSCLI{now: now, items: map[string]allowsync.Item{}}
	a := &Allowlister{Run: f.run, Now: func() time.Time { return now }}
	ctx := context.Background()
	exp := now.Add(48 * time.Hour)
	st := allowsync.State{Items: []allowsync.Item{
		{Value: "192.0.2.0/24", Description: "office"},
		{Value: "198.51.100.7", Description: "partner", ExpiresAt: &exp},
		{Value: "2001:db8::/32", Description: "office"},
	}}
	res, err := a.Apply(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.Added != 3 || res.Removed != 0 || res.Items != 3 {
		t.Fatalf("first apply = %+v (calls %v)", res, f.calls)
	}
	// The two office networks share one command.
	var adds int
	for _, c := range f.calls {
		if strings.HasPrefix(c, "allowlists add") {
			adds++
		}
	}
	if adds != 2 || !strings.Contains(strings.Join(f.calls, "\n"), "allowlists add openpicket 198.51.100.7 --expiration=172800s --comment=partner") {
		t.Fatalf("calls = %v", f.calls)
	}

	// In sync: one inspect, nothing else.
	f.calls = nil
	if res, err := a.Apply(ctx, st); err != nil || res.Added+res.Removed != 0 || len(f.calls) != 1 {
		t.Fatalf("in sync: %+v %v %v", res, err, f.calls)
	}

	// A changed description, a removed entry and a value added by hand.
	f.items["203.0.113.9"] = allowsync.Item{Value: "203.0.113.9"}
	st.Items = []allowsync.Item{{Value: "192.0.2.0/24", Description: "office LAN"}, st.Items[1]}
	res, err = a.Apply(ctx, st)
	if err != nil || res.Added != 1 || res.Removed != 3 || res.Items != 2 {
		t.Fatalf("change: %+v %v", res, err)
	}
	if f.items["192.0.2.0/24"].Description != "office LAN" {
		t.Fatalf("items = %v", f.items)
	}

	// cscli refusing a value is caught by the check after it.
	f.refuse = "10.0.0.0/8"
	st.Items = append(st.Items, allowsync.Item{Value: "10.0.0.0/8"})
	if _, err := a.Apply(ctx, st); err == nil || !strings.Contains(err.Error(), "out of sync") {
		t.Fatalf("refused value: %v", err)
	}
	// Values that could pass as flags never reach cscli.
	f.calls = nil
	if _, err := a.Apply(ctx, allowsync.State{Items: []allowsync.Item{{Value: "--help"}}}); err == nil || len(f.calls) != 0 {
		t.Fatalf("bad value: %v %v", err, f.calls)
	}
	f.lapiOff = true
	if _, err := a.Apply(ctx, st); !errors.Is(err, ErrNoLAPI) {
		t.Fatalf("LAPI down: %v", err)
	}
}

func TestAllowlistEndpoint(t *testing.T) {
	f := &fakeCSCLI{now: time.Now(), items: map[string]allowsync.Item{}}
	h := Handler(nil, &Allowlister{Run: f.run, Now: func() time.Time { return f.now }}, "X-OpenPicket-Token", "secret")
	put := func(token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, allowsync.Path, bytes.NewBufferString(body))
		r.Header.Set("X-OpenPicket-Token", token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := put("nope", `{"items":[]}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized: %d", w.Code)
	}
	w := put("secret", `{"items":[{"value":"192.0.2.0/24"}]}`)
	var res allowsync.Result
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &res) != nil || res.Added != 1 {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	f.lapiOff = true
	if w := put("secret", `{"items":[]}`); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("LAPI down: %d", w.Code)
	}
	// No content routes in a LAPI-only container.
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("healthz: %d", rec.Code)
	}
}
