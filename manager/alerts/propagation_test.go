package alerts

import (
	"context"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
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

func TestEvaluate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	block := func(v, dir string, version uint64, ttl time.Duration) *apiv1.EdgeBlock {
		return &apiv1.EdgeBlock{Value: v, Direction: dir, Version: version, Until: timestamppb.New(now.Add(ttl))}
	}
	rangeIn := block("203.0.113.0/24", "inbound", 5, time.Hour)
	ipIn := block("203.0.113.7", "inbound", 6, 30*time.Minute)
	ipBoth := block("203.0.113.7", "both", 6, 10*time.Minute)
	online := func(enf *dataplanev1.EnforcerStatus) nodeEvidence {
		return nodeEvidence{connectedAt: at(-time.Hour), heartbeatAt: at(-10 * time.Second), statusAt: at(-20 * time.Second),
			status: &dataplanev1.Status{Enforcer: enf}}
	}
	localRange := []*dataplanev1.RefusedDecision{{Value: "203.0.113.0/24", Reason: "overlaps a local network (203.0.113.0/26)"}}
	cases := []struct {
		name    string
		edge    []*apiv1.EdgeBlock
		ev      nodeEvidence
		state   string
		dir     string
		until   time.Duration
		refused int
	}{
		{"range refused, address applied (review)", []*apiv1.EdgeBlock{rangeIn, ipIn},
			online(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 6, Rejected: 1, Refused: localRange}), StateApplied, "inbound", 30 * time.Minute, 1},
		{"strongest direction, latest expiry", []*apiv1.EdgeBlock{rangeIn, ipBoth},
			online(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 6}), StateApplied, "both", time.Hour, 0},
		{"only the refused range", []*apiv1.EdgeBlock{rangeIn},
			online(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 6, Rejected: 1, Refused: localRange}), StateRefused, "", 0, 1},
		{"enforcer off", []*apiv1.EdgeBlock{rangeIn, ipIn}, online(&dataplanev1.EnforcerStatus{}), StateRefused, "", 0, 2},
		{"not reported among thousands refused", []*apiv1.EdgeBlock{ipIn},
			online(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 6, Rejected: 5000}), StateMaybe, "inbound", 30 * time.Minute, 0},
		{"not received yet", []*apiv1.EdgeBlock{ipIn}, online(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 5}), StatePending, "", 0, 0},
		{"acknowledged in this session after the report", []*apiv1.EdgeBlock{ipIn},
			func() nodeEvidence {
				ev := online(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 5})
				ev.ackVersion, ev.ackedAt = 6, at(-time.Second)
				return ev
			}(), StateApplied, "inbound", 30 * time.Minute, 0},
		{"old acknowledgement, restore failed (review)", []*apiv1.EdgeBlock{block("198.51.100.4", "inbound", 2, time.Hour)},
			func() nodeEvidence {
				ev := online(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 0, LastError: "nft restore failed"})
				ev.ackVersion, ev.ackedAt = 2, at(-2*time.Hour)
				return ev
			}(), StateError, "", 0, 0},
		{"offline", []*apiv1.EdgeBlock{ipIn}, func() nodeEvidence {
			ev := online(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 6})
			ev.connectedAt, ev.heartbeatAt = nil, nil
			return ev
		}(), StateUnknown, "", 0, 0},
		{"no report in this session", []*apiv1.EdgeBlock{ipIn}, func() nodeEvidence {
			ev := online(nil)
			ev.status, ev.statusAt = nil, nil
			return ev
		}(), StateUnknown, "", 0, 0},
		{"stale report", []*apiv1.EdgeBlock{ipIn}, func() nodeEvidence {
			ev := online(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 6})
			ev.statusAt = at(-5 * time.Minute)
			return ev
		}(), StateUnknown, "", 0, 0},
	}
	for _, c := range cases {
		np := evaluate(c.edge, c.ev, now, 90*time.Second)
		applied := c.state == StateApplied || c.state == StateMaybe
		if np.State != c.state || np.Applied != applied || np.Direction != c.dir || len(np.Refusals) != c.refused {
			t.Errorf("%s: state=%s applied=%v dir=%q refusals=%v", c.name, np.State, np.Applied, np.Direction, np.Refusals)
			continue
		}
		if applied && np.Until.AsTime().Sub(now) != c.until {
			t.Errorf("%s: until %v", c.name, np.Until.AsTime().Sub(now))
		}
	}
	if np := evaluate(nil, online(nil), now, time.Minute); np.State != "" {
		t.Errorf("nothing at the edge: %s", np.State)
	}
}

// TestPropagationExplainsNodes runs the query: every active edge decision
// containing the address counts, and each node is judged from the status
// report of its current session.
func TestPropagationExplainsNodes(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`INSERT INTO openpicket.edge_decisions (value, scope, direction, until, origin, scenario, version) VALUES
			('203.0.113.0/24', 'range', 'inbound', now() + interval '1 hour', 'crowdsec', 's', 5),
			('203.0.0.0/16', 'range', 'both', now() + interval '1 minute', 'crowdsec', 's', 6),
			('203.0.113.7', 'ip', 'inbound', now() - interval '1 minute', 'crowdsec', 's', 3)`,
		`INSERT INTO openpicket.edge_decisions (value, scope, direction, until, origin, scenario, version, deleted) VALUES
			('203.0.113.7/32', 'range', 'inbound', now() + interval '2 hours', 'crowdsec', 's', 7, true)`,
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
		id     string
		status []byte
		online bool
	}{
		{"applied", status(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 7}), true},
		{"local", status(&dataplanev1.EnforcerStatus{Enabled: true, DecisionsVersion: 7, Rejected: 2, Refused: []*dataplanev1.RefusedDecision{
			{Value: "203.0.113.0/24", Reason: "overlaps a local network (203.0.113.0/26)"}, {Value: "203.0.0.0/16", Reason: "overlaps a local network (203.0.113.0/26)"}}}), true},
		{"offline", nil, false},
	}
	for i, n := range nodes {
		if _, err := pool.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint) VALUES ($1, 'k', $2, $1)`, n.id, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO openpicket.node_decision_state (node_id, version, set_size, acked_at) VALUES ($1, 7, 1, now() - interval '1 day')`, n.id); err != nil {
			t.Fatal(err)
		}
		if n.online {
			if _, err := pool.Exec(ctx, `INSERT INTO openpicket.node_sessions (node_id, session_id, replica, connected_at, heartbeat_at, status, status_at)
				VALUES ($1, 's', 'r', now() - interval '1 hour', now(), $2, now())`, n.id, n.status); err != nil {
				t.Fatal(err)
			}
		}
	}
	p, err := (&Querier{DB: pool}).Propagation(ctx, "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	// The expired address and the deleted /32 do not count.
	if !p.AtEdge || len(p.Edge) != 2 || p.Edge[0].Value != "203.0.113.0/24" || p.Version != 6 || p.Direction != "both" {
		t.Fatalf("edge = %v v%d %s", p.Edge, p.Version, p.Direction)
	}
	got := map[string]*apiv1.NodePropagation{}
	for _, n := range p.Nodes {
		got[n.NodeId] = n
	}
	if n := got["applied"]; n.State != StateApplied || n.Direction != "both" || n.Until.AsTime().Before(time.Now().Add(59*time.Minute)) {
		t.Fatalf("applied: %v", n)
	}
	if n := got["local"]; n.State != StateRefused || len(n.Refusals) != 2 || n.Applied {
		t.Fatalf("local: %v", n)
	}
	if n := got["offline"]; n.State != StateUnknown || n.Applied || n.AckedVersion != 7 {
		t.Fatalf("offline: %v", n)
	}
}
