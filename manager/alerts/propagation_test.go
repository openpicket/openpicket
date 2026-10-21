package alerts

import (
	"context"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
)

func TestCovering(t *testing.T) {
	c := covering("::ffff:203.0.113.7")
	if len(c) != 34 || c[0] != "203.0.113.7" || c[1] != "203.0.113.7/32" || !slices.Contains(c, "203.0.113.0/24") || c[33] != "0.0.0.0/0" {
		t.Fatalf("covering = %v", c)
	}
	if c := covering("2001:db8::/33"); len(c) != 35 || c[0] != "2001:db8::/33" {
		t.Fatalf("covering = %v", c)
	}
	if c := covering("bogus"); len(c) != 1 {
		t.Fatalf("covering = %v", c)
	}
}

// TestPropagationExplainsNodes: an address banned by a range containing
// it is at the edge, and a node that received it but refuses it (or has
// its enforcer off) is not counted as applied.
func TestPropagationExplainsNodes(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, sql := range []string{
		`INSERT INTO openpicket.edge_decisions (value, scope, direction, until, origin, scenario, version) VALUES
			('203.0.113.0/24', 'range', 'inbound', now() + interval '1 hour', 'crowdsec', 's', 5),
			('203.0.0.0/16', 'range', 'both', now() + interval '1 minute', 'crowdsec', 's', 6)`,
		`INSERT INTO openpicket.edge_decisions (value, scope, direction, until, origin, scenario, version, deleted) VALUES
			('203.0.113.7', 'ip', 'inbound', now() + interval '2 hours', 'crowdsec', 's', 7, true)`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	status := func(enf *dataplanev1.EnforcerStatus) []byte {
		b, _ := proto.Marshal(&dataplanev1.Status{Enforcer: enf})
		return b
	}
	nodes := []struct {
		id      string
		version int64
		status  []byte
	}{
		{"applied", 7, status(&dataplanev1.EnforcerStatus{Enabled: true, Rejected: 1, Refused: []*dataplanev1.RefusedDecision{{Value: "198.51.100.1", Reason: "x"}}})},
		{"local", 7, status(&dataplanev1.EnforcerStatus{Enabled: true, Rejected: 1, Refused: []*dataplanev1.RefusedDecision{{Value: "203.0.113.0/24", Reason: "overlaps a local network (203.0.113.0/24)"}}})},
		{"off", 7, status(&dataplanev1.EnforcerStatus{})},
		{"capped", 7, status(&dataplanev1.EnforcerStatus{Enabled: true, Rejected: 5000})},
		{"behind", 4, status(&dataplanev1.EnforcerStatus{Enabled: true})},
	}
	for i, n := range nodes {
		if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint) VALUES ($1, 'k', $2, $1)`, n.id, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO openpicket.node_decision_state (node_id, version, set_size, acked_at) VALUES ($1, $2, 1, now())`, n.id, n.version); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO openpicket.node_sessions (node_id, session_id, replica, connected_at, heartbeat_at, status) VALUES ($1, 's', 'r', $2, $2, $3)`, n.id, now, n.status); err != nil {
			t.Fatal(err)
		}
	}
	p, err := (&Querier{DB: pool}).Propagation(ctx, "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if !p.AtEdge || p.EdgeValue != "203.0.113.0/24" || p.Version != 5 || p.Direction != "inbound" {
		t.Fatalf("edge = %v %s v%d %s", p.AtEdge, p.EdgeValue, p.Version, p.Direction)
	}
	got := map[string]string{}
	for _, n := range p.Nodes {
		s := "pending"
		switch {
		case n.Applied && n.MaybeRefused:
			s = "maybe"
		case n.Applied:
			s = "applied"
		case n.Refused != "":
			s = n.Refused
		}
		got[n.NodeId] = s
	}
	want := map[string]string{"applied": "applied", "local": "overlaps a local network (203.0.113.0/24)", "off": "ban enforcer disabled on this node",
		"capped": "maybe", "behind": "pending"}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: got %q, want %q", k, got[k], v)
		}
	}
}
