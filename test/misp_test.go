package test

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/openpicket/openpicket/manager/misp"
)

// TestMISPClient runs the client against a real MISP (scripts/misp-test.sh).
func TestMISPClient(t *testing.T) {
	base := os.Getenv("OPENPICKET_TEST_MISP_URL")
	if base == "" {
		t.Skip("OPENPICKET_TEST_MISP_URL not set (scripts/misp-test.sh)")
	}
	ctx := context.Background()
	c, err := misp.NewClient(misp.ClientConfig{URL: base, APIKey: os.Getenv("OPENPICKET_TEST_MISP_KEY"), InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	info := "OpenPicket sightings test"
	ev, err := c.FindEvent(ctx, info)
	if err != nil || ev != nil {
		t.Fatalf("find before add: %v %v", ev, err)
	}
	if ev, err = c.AddEvent(ctx, info); err != nil || ev.ID == "" {
		t.Fatalf("add event: %v %v", ev, err)
	}
	if found, err := c.FindEvent(ctx, info); err != nil || found == nil || found.ID != ev.ID {
		t.Fatalf("find: %v %v", found, err)
	}
	a, err := c.AddAttribute(ctx, ev.ID, misp.Attribute{Type: "ip-src", Value: "198.51.100.7", Comment: "OpenPicket: 3 alerts"})
	if err != nil || a.UUID == "" || a.ID == "" {
		t.Fatalf("add attribute: %+v %v", a, err)
	}
	if err := c.AttachTag(ctx, a.UUID, misp.StateTag(misp.StateProposed)); err != nil {
		t.Fatal(err)
	}
	// An attribute without our tags is not returned.
	if _, err := c.AddAttribute(ctx, ev.ID, misp.Attribute{Type: "ip-dst", Value: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	find := func() *misp.Attribute {
		t.Helper()
		attrs, err := c.SearchOpenPicket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for i := range attrs {
			if attrs[i].Value == "203.0.113.9" {
				t.Fatal("untagged attribute returned")
			}
			if attrs[i].UUID == a.UUID {
				return &attrs[i]
			}
		}
		return nil
	}
	got := find()
	if got == nil || got.Machine("state") != misp.StateProposed || got.ToIDS || got.Event == nil || got.Event.Info != info {
		t.Fatalf("proposed: %+v", got)
	}
	// Approval: swap the state tag, add a ttl, turn on to_ids.
	if err := c.RemoveTag(ctx, a.UUID, misp.StateTag(misp.StateProposed)); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{misp.StateTag(misp.StateApproved), misp.TTLTag("30d")} {
		if err := c.AttachTag(ctx, a.UUID, tag); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.SetToIDS(ctx, a.ID, true); err != nil {
		t.Fatal(err)
	}
	got = find()
	var names []string
	for _, tg := range got.Tags {
		names = append(names, tg.Name)
	}
	if got.Machine("state") != misp.StateApproved || got.Machine("ttl") != "30d" || !got.ToIDS || slices.Contains(names, misp.StateTag(misp.StateProposed)) {
		t.Fatalf("approved: %+v", got)
	}
	if got.Modified().IsZero() {
		t.Fatal("no timestamp")
	}
	if err := c.SetToIDS(ctx, a.ID, false); err != nil {
		t.Fatal(err)
	}
	if find().ToIDS {
		t.Fatal("to_ids still on")
	}
}
