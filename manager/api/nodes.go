package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jc-lab/suricontroller/pkg/nodeid"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/dpwire"
)

// sessionTimeout: a session whose heartbeat is older is shown offline (the
// replica holding it died). Heartbeats are written every 30s.
const sessionTimeout = 90 * time.Second

type nodeService struct{ s *Server }

const nodeQuery = `SELECT n.id, n.description, n.enabled, n.labels, n.public_key, n.fingerprint, n.created_at, n.suri_last_seen_at, n.dp_last_seen_at,
	s.replica, s.remote_addr, s.boot_id, s.connected_at, s.heartbeat_at, s.hello, s.status,
	d.version, d.set_size, d.error, d.acked_at,
	p.version, p.error, p.skipped, p.acked_at,
	(SELECT COALESCE(max(version), 0) FROM openpicket.edge_decisions),
	(SELECT version FROM openpicket.policy_meta WHERE id = 1)
	FROM openpicket.nodes n
	LEFT JOIN openpicket.node_sessions s ON s.node_id = n.id
	LEFT JOIN openpicket.node_decision_state d ON d.node_id = n.id
	LEFT JOIN openpicket.node_policy_state p ON p.node_id = n.id`

func (n *nodeService) scan(row pgx.Row) (*apiv1.Node, error) {
	var (
		out                         apiv1.Node
		labels                      []byte
		createdAt                   time.Time
		suriSeen, dpSeen            *time.Time
		replica, remoteAddr, bootID *string
		connectedAt, heartbeatAt    *time.Time
		hello, status               []byte
		decVersion, polVersion      *int64
		setSize                     *int32
		decErr, polErr              *string
		skipped                     []byte
		decAcked, polAcked          *time.Time
		edgeCurrent, policyCurrent  int64
	)
	if err := row.Scan(&out.Id, &out.Description, &out.Enabled, &labels, &out.PublicKey, &out.Fingerprint, &createdAt, &suriSeen, &dpSeen,
		&replica, &remoteAddr, &bootID, &connectedAt, &heartbeatAt, &hello, &status,
		&decVersion, &setSize, &decErr, &decAcked,
		&polVersion, &polErr, &skipped, &polAcked,
		&edgeCurrent, &policyCurrent); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(labels, &out.Labels)
	out.CreatedAt = timestamppb.New(createdAt)
	out.SuricataLastSeenAt = ts(suriSeen)
	dp := &apiv1.DataPlaneState{LastSeenAt: ts(dpSeen)}
	if replica != nil {
		dp.Connected = heartbeatAt != nil && n.s.cfg.Now().Sub(*heartbeatAt) < sessionTimeout
		dp.Replica, dp.RemoteAddr, dp.BootId = *replica, *remoteAddr, *bootID
		dp.ConnectedAt = ts(connectedAt)
		if dp.Connected {
			dp.LastSeenAt = ts(heartbeatAt)
		}
		h := &dataplanev1.Hello{}
		if len(hello) > 0 && proto.Unmarshal(hello, h) == nil {
			dp.AgentVersion, dp.Capabilities, dp.WanInterfaces = h.GetAgentVersion(), h.GetCapabilities(), h.GetWanInterfaces()
			for _, w := range h.GetWarnings() {
				dp.Warnings = append(dp.Warnings, &apiv1.SimpleWarning{Code: w.GetCode(), Message: w.GetMessage()})
			}
		}
		st := &dataplanev1.Status{}
		if len(status) > 0 && proto.Unmarshal(status, st) == nil {
			dp.Status = st
			if st.WanInterfaces != nil {
				// Current (fw4 zones); the hello has the list at connect.
				dp.WanInterfaces = st.WanInterfaces
			}
		}
	}
	out.DataPlane = dp
	out.Decisions = &apiv1.SyncState{Current: uint64(edgeCurrent)}
	if decVersion != nil {
		out.Decisions.Version, out.Decisions.SetSize, out.Decisions.Error, out.Decisions.AckedAt = uint64(*decVersion), uint32(*setSize), *decErr, ts(decAcked)
	}
	out.Policy = &apiv1.SyncState{Current: uint64(policyCurrent)}
	if polVersion != nil {
		out.Policy.Version, out.Policy.Error, out.Policy.AckedAt = uint64(*polVersion), *polErr, ts(polAcked)
		var sk []struct {
			ID    string
			Stale bool
		}
		_ = json.Unmarshal(skipped, &sk)
		for _, s := range sk {
			out.Policy.Skipped = append(out.Policy.Skipped, s.ID)
			if s.Stale {
				out.Policy.Stale = append(out.Policy.Stale, s.ID)
			}
		}
	}
	return &out, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

func (n *nodeService) get(ctx context.Context, id string) (*apiv1.Node, error) {
	node, err := n.scan(n.s.cfg.DB.QueryRow(ctx, nodeQuery+` WHERE n.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("node %q not found", id))
	}
	return node, err
}

func (n *nodeService) ListNodes(ctx context.Context, _ *connect.Request[apiv1.ListNodesRequest]) (*connect.Response[apiv1.ListNodesResponse], error) {
	rows, err := n.s.cfg.DB.Query(ctx, nodeQuery+` ORDER BY n.id`)
	if err != nil {
		return nil, toConnectError(err)
	}
	defer rows.Close()
	res := &apiv1.ListNodesResponse{}
	for rows.Next() {
		node, err := n.scan(rows)
		if err != nil {
			return nil, toConnectError(err)
		}
		res.Nodes = append(res.Nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(res), nil
}

func (n *nodeService) GetNode(ctx context.Context, req *connect.Request[apiv1.GetNodeRequest]) (*connect.Response[apiv1.GetNodeResponse], error) {
	node, err := n.get(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.GetNodeResponse{Node: node}), nil
}

var labelKeyRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9_.\-/]{0,62})$`)

func validateLabels(l map[string]string) error {
	if len(l) > 32 {
		return fmt.Errorf("%w: at most 32 labels", errInvalid)
	}
	for k, v := range l {
		if !labelKeyRe.MatchString(k) {
			return fmt.Errorf("%w: label key %q must match %s", errInvalid, k, labelKeyRe)
		}
		if len(v) > 128 {
			return fmt.Errorf("%w: label %q: value longer than 128 bytes", errInvalid, k)
		}
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (n *nodeService) RegisterNode(ctx context.Context, req *connect.Request[apiv1.RegisterNodeRequest]) (*connect.Response[apiv1.RegisterNodeResponse], error) {
	pk, err := sshkey.ParsePublicKey(req.Msg.GetPublicKey())
	if err != nil {
		return nil, toConnectError(fmt.Errorf("%w: %v", errInvalid, err))
	}
	if pk.Comment == "" {
		return nil, toConnectError(fmt.Errorf("%w: the public key must end with the node id as comment", errInvalid))
	}
	if err := nodeid.Validate(pk.Comment); err != nil {
		return nil, toConnectError(fmt.Errorf("%w: %v", errInvalid, err))
	}
	if err := validateLabels(req.Msg.GetLabels()); err != nil {
		return nil, toConnectError(err)
	}
	x, err := pk.X25519()
	if err != nil {
		return nil, toConnectError(fmt.Errorf("%w: %v", errInvalid, err))
	}
	labels, _ := json.Marshal(nonNil(req.Msg.GetLabels()))
	_, err = n.s.cfg.DB.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint, description, labels) VALUES ($1,$2,$3,$4,$5,$6)`,
		pk.Comment, pk.String(), x, pk.Fingerprint(), req.Msg.GetDescription(), labels)
	if isUniqueViolation(err) {
		return nil, toConnectError(fmt.Errorf("%w: a node with this id or key exists", errExists))
	}
	if err != nil {
		return nil, toConnectError(err)
	}
	node, err := n.get(ctx, pk.Comment)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.RegisterNodeResponse{Node: node}), nil
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func (n *nodeService) UpdateNode(ctx context.Context, req *connect.Request[apiv1.UpdateNodeRequest]) (*connect.Response[apiv1.UpdateNodeResponse], error) {
	m := req.Msg
	if m.SetLabels {
		if err := validateLabels(m.GetLabels()); err != nil {
			return nil, toConnectError(err)
		}
	}
	var labels []byte
	if m.SetLabels {
		labels, _ = json.Marshal(nonNil(m.GetLabels()))
	}
	tag, err := n.s.cfg.DB.Exec(ctx, `UPDATE openpicket.nodes SET
		enabled = COALESCE($2, enabled), description = COALESCE($3, description), labels = COALESCE($4, labels), updated_at = now()
		WHERE id = $1`, m.GetId(), m.Enabled, m.Description, labels)
	if err != nil {
		return nil, toConnectError(err)
	}
	if tag.RowsAffected() == 0 {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("node %q not found", m.GetId()))
	}
	node, err := n.get(ctx, m.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.UpdateNodeResponse{Node: node}), nil
}

func (n *nodeService) DeleteNode(ctx context.Context, req *connect.Request[apiv1.DeleteNodeRequest]) (*connect.Response[apiv1.DeleteNodeResponse], error) {
	tag, err := n.s.cfg.DB.Exec(ctx, `DELETE FROM openpicket.nodes WHERE id = $1`, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	if tag.RowsAffected() == 0 {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("node %q not found", req.Msg.GetId()))
	}
	return connect.NewResponse(&apiv1.DeleteNodeResponse{}), nil
}

func (n *nodeService) GetConnectionInfo(context.Context, *connect.Request[apiv1.GetConnectionInfoRequest]) (*connect.Response[apiv1.GetConnectionInfoResponse], error) {
	return connect.NewResponse(&apiv1.GetConnectionInfoResponse{ManagerHostKey: n.s.cfg.HostKey(), DataPlanePath: dpwire.Path}), nil
}
