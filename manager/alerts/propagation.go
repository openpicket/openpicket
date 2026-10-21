package alerts

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
)

// Node propagation states (apiv1.NodePropagation.state).
const (
	StateApplied = "applied"
	StateMaybe   = "maybe"
	StateRefused = "refused"
	StatePending = "pending"
	StateError   = "error"
	StateUnknown = "unknown"
)

const reasonEnforcerOff = "ban enforcer disabled on this node"

// Propagation reports how the edge decisions blocking a value reached the
// nodes and whether each node has one in force.
func (q *Querier) Propagation(ctx context.Context, value string) (*apiv1.GetPropagationResponse, error) {
	res := &apiv1.GetPropagationResponse{}
	// The value itself and every range containing it: any of them blocks
	// it, so all count.
	rows, err := q.DB.Query(ctx, `SELECT value, direction, version, until FROM openpicket.edge_decisions
		WHERE value = ANY($1) AND NOT deleted AND until > $2 ORDER BY until DESC, value`, covering(value), q.now())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var (
			b     apiv1.EdgeBlock
			v     int64
			until time.Time
		)
		if err := rows.Scan(&b.Value, &b.Direction, &v, &until); err != nil {
			rows.Close()
			return nil, err
		}
		b.Version, b.Until = uint64(v), timestamppb.New(until)
		res.Edge = append(res.Edge, &b)
		res.AtEdge = true
		res.Version = max(res.Version, b.Version)
		if res.Until == nil || until.After(res.Until.AsTime()) {
			res.Until = b.Until
		}
		res.Direction = strongest(res.Direction, b.Direction)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.DB.Query(ctx, `SELECT n.id, COALESCE(st.version, 0), COALESCE(st.error, ''), st.acked_at,
			s.connected_at, s.heartbeat_at, s.status, s.status_at
		FROM openpicket.nodes n
		LEFT JOIN openpicket.node_decision_state st ON st.node_id = n.id LEFT JOIN openpicket.node_sessions s ON s.node_id = n.id ORDER BY n.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	maxAge := q.StatusMaxAge
	if maxAge <= 0 {
		maxAge = 90 * time.Second
	}
	now := q.now()
	for rows.Next() {
		var (
			ev     nodeEvidence
			raw    []byte
			ackV   int64
			nodeID string
		)
		if err := rows.Scan(&nodeID, &ackV, &ev.ackErr, &ev.ackedAt, &ev.connectedAt, &ev.heartbeatAt, &raw, &ev.statusAt); err != nil {
			return nil, err
		}
		ev.ackVersion = uint64(ackV)
		if len(raw) > 0 {
			st := &dataplanev1.Status{}
			if proto.Unmarshal(raw, st) == nil {
				ev.status = st
			}
		}
		np := evaluate(res.Edge, ev, now, maxAge)
		np.NodeId = nodeID
		res.Nodes = append(res.Nodes, np)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	query := `value="` + strings.ReplaceAll(value, `"`, ``) + `"`
	for _, b := range res.Edge {
		if b.Value != value {
			query += ` OR value="` + b.Value + `"`
		}
	}
	ds, _, err := q.Decisions(ctx, DecisionFilter{Query: query, IncludeExpired: true}, 50, 0)
	if err != nil {
		return nil, err
	}
	res.Decisions = ds
	return res, nil
}

// nodeEvidence is what the manager knows about a node's enforcement.
type nodeEvidence struct {
	ackVersion  uint64
	ackErr      string
	ackedAt     *time.Time
	connectedAt *time.Time // current session; nil when offline
	heartbeatAt *time.Time
	status      *dataplanev1.Status // latest report of the current session
	statusAt    *time.Time
}

// evaluate decides what a node enforces for the edge decisions blocking a
// value. Only the current session counts: an acknowledgement or a report
// from an earlier one says nothing about the table now (the node may have
// rebooted and failed to restore it).
func evaluate(edge []*apiv1.EdgeBlock, ev nodeEvidence, now time.Time, maxAge time.Duration) *apiv1.NodePropagation {
	np := &apiv1.NodePropagation{AckedVersion: ev.ackVersion, AckedAt: ts(ev.ackedAt), StatusAt: ts(ev.statusAt)}
	np.Connected = ev.connectedAt != nil && ev.heartbeatAt != nil && now.Sub(*ev.heartbeatAt) < 90*time.Second
	if len(edge) == 0 {
		return np
	}
	if !np.Connected || ev.status == nil || ev.statusAt == nil || now.Sub(*ev.statusAt) > maxAge {
		np.State = StateUnknown
		return np
	}
	enf := ev.status.GetEnforcer()
	if !enf.GetEnabled() {
		np.State = StateRefused
		for _, b := range edge {
			np.Refusals = append(np.Refusals, &apiv1.NodeRefusal{Value: b.Value, Reason: reasonEnforcerOff})
		}
		return np
	}
	// The version in force: the enforcer's, or an acknowledgement of this
	// session (sent once applied; the report may be older).
	ackNow := ev.ackedAt != nil && !ev.ackedAt.Before(*ev.connectedAt)
	inForce := enf.GetDecisionsVersion()
	if ackNow && ev.ackErr == "" {
		inForce = max(inForce, ev.ackVersion)
	}
	reasons := map[string]string{}
	for _, r := range enf.GetRefused() {
		reasons[r.GetValue()] = r.GetReason()
	}
	unlisted := enf.GetRejected() > uint64(len(enf.GetRefused()))
	var (
		pending, definite bool
		until             time.Time
	)
	for _, b := range edge {
		switch {
		case b.Version > inForce:
			pending = true
		case reasons[b.Value] != "":
			np.Refusals = append(np.Refusals, &apiv1.NodeRefusal{Value: b.Value, Reason: reasons[b.Value]})
		default:
			np.Applied = true
			definite = definite || !unlisted
			np.Direction = strongest(np.Direction, b.Direction)
			if t := b.Until.AsTime(); t.After(until) {
				until = t
			}
		}
	}
	errMsg := enf.GetLastError()
	if errMsg == "" && ackNow {
		errMsg = ev.ackErr
	}
	switch {
	case np.Applied && definite:
		np.State, np.Until = StateApplied, timestamppb.New(until)
	case np.Applied:
		np.State, np.Until = StateMaybe, timestamppb.New(until)
	case errMsg != "":
		np.State, np.Error = StateError, errMsg
	case pending:
		np.State = StatePending
	default:
		np.State = StateRefused
	}
	return np
}

// strongest is "both" if either direction is.
func strongest(a, b string) string {
	if a == "both" || b == "both" {
		return "both"
	}
	if a == "" {
		return b
	}
	return a
}

// covering returns the edge values that block value: itself and every
// range containing it, in their canonical forms (relay.Normalize).
func covering(value string) []string {
	out := []string{value}
	var p netip.Prefix
	if a, err := netip.ParseAddr(value); err == nil {
		a = a.Unmap()
		out[0] = a.String()
		p = netip.PrefixFrom(a, a.BitLen())
	} else if pp, err := netip.ParsePrefix(value); err == nil {
		p = pp.Masked()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
		}
		out[0] = p.String()
	} else {
		return out
	}
	for bits := p.Bits(); bits >= 0; bits-- {
		r, _ := p.Addr().Prefix(bits)
		out = append(out, r.String())
	}
	return out
}
