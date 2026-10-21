// Package suristore implements suricontroller's store.Store on PostgreSQL.
//
// Nodes live in openpicket.nodes, the registry shared with
// openpicket-manager: a node registered or disabled in OpenPicket is seen by
// suricontroller on the next handshake (LookupNodeByX25519 is implemented,
// so the controller does not keep its own key index). suricontroller's own
// node state is kept in the suri_state column; registry columns it does not
// know (labels, data plane presence) are never touched here. Audit entries go
// to the shared openpicket.audit table with source "suricontroller".
package suristore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jc-lab/suricontroller/controller/store"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
)

// AuditSource marks audit entries written through this store.
const AuditSource = "suricontroller"

// Store is a PostgreSQL store.Store. The caller owns the pool and must have
// applied the schema (internal/schema.Migrate).
type Store struct {
	db *pgxpool.Pool
}

var _ store.Store = (*Store)(nil)

// New wraps a pool.
func New(db *pgxpool.Pool) *Store { return &Store{db: db} }

// Close implements store.Store. The pool belongs to the caller.
func (s *Store) Close() error { return nil }

// suriState is the JSON layout of openpicket.nodes.suri_state. Protobuf
// messages are stored in their protojson form.
type suriState struct {
	Hello          json.RawMessage   `json:"hello,omitempty"`
	InterfaceModes map[string]string `json:"interface_modes,omitempty"`
	LogPolicy      json.RawMessage   `json:"log_policy,omitempty"`
	Desired        json.RawMessage   `json:"desired,omitempty"`
	DesiredError   string            `json:"desired_error,omitempty"`
	Applied        json.RawMessage   `json:"applied,omitempty"`
	LastReport     json.RawMessage   `json:"last_report,omitempty"`
	LastReportAtMs int64             `json:"last_report_at_ms,omitempty"`
}

func marshalProto(m proto.Message) (json.RawMessage, error) {
	if m == nil || !m.ProtoReflect().IsValid() {
		return nil, nil
	}
	return protojson.Marshal(m)
}

func unmarshalProto[T proto.Message](raw json.RawMessage, newT func() T) (T, error) {
	var zero T
	if len(raw) == 0 || string(raw) == "null" {
		return zero, nil
	}
	m := newT()
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, m); err != nil {
		return zero, err
	}
	return m, nil
}

func encodeState(n *store.Node) ([]byte, error) {
	var (
		st  suriState
		err error
	)
	if st.Hello, err = marshalProto(n.Hello); err != nil {
		return nil, err
	}
	if st.LogPolicy, err = marshalProto(n.LogPolicy); err != nil {
		return nil, err
	}
	if st.Desired, err = marshalProto(n.Desired); err != nil {
		return nil, err
	}
	if st.Applied, err = marshalProto(n.Applied); err != nil {
		return nil, err
	}
	if st.LastReport, err = marshalProto(n.LastReport); err != nil {
		return nil, err
	}
	if len(n.InterfaceModes) > 0 {
		st.InterfaceModes = make(map[string]string, len(n.InterfaceModes))
		for k, v := range n.InterfaceModes {
			st.InterfaceModes[k] = v.String()
		}
	}
	st.DesiredError = n.DesiredError
	if !n.LastReportAt.IsZero() {
		st.LastReportAtMs = n.LastReportAt.UnixMilli()
	}
	return json.Marshal(st)
}

func decodeState(raw []byte, n *store.Node) error {
	var st suriState
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &st); err != nil {
			return err
		}
	}
	var err error
	if n.Hello, err = unmarshalProto(st.Hello, func() *agentv1.Hello { return &agentv1.Hello{} }); err != nil {
		return err
	}
	if n.LogPolicy, err = unmarshalProto(st.LogPolicy, func() *agentv1.LogCollectionPolicy { return &agentv1.LogCollectionPolicy{} }); err != nil {
		return err
	}
	if n.Desired, err = unmarshalProto(st.Desired, func() *agentv1.DesiredState { return &agentv1.DesiredState{} }); err != nil {
		return err
	}
	if n.Applied, err = unmarshalProto(st.Applied, func() *agentv1.AppliedState { return &agentv1.AppliedState{} }); err != nil {
		return err
	}
	if n.LastReport, err = unmarshalProto(st.LastReport, func() *agentv1.ApplyReport { return &agentv1.ApplyReport{} }); err != nil {
		return err
	}
	if len(st.InterfaceModes) > 0 {
		n.InterfaceModes = make(map[string]agentv1.InterfaceMode, len(st.InterfaceModes))
		for k, v := range st.InterfaceModes {
			n.InterfaceModes[k] = agentv1.InterfaceMode(agentv1.InterfaceMode_value[v])
		}
	}
	n.DesiredError = st.DesiredError
	if st.LastReportAtMs != 0 {
		n.LastReportAt = time.UnixMilli(st.LastReportAtMs)
	}
	return nil
}

// X25519 returns the X25519 form of an authorized key line, the identity
// agents authenticate with on both channels.
func X25519(publicKey string) ([]byte, error) {
	pk, err := sshkey.ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return pk.X25519()
}

const nodeColumns = `id, public_key, fingerprint, enabled, description, created_at, updated_at, suri_last_seen_at, suri_state`

func scanNode(r pgx.Row) (*store.Node, error) {
	var (
		n        store.Node
		lastSeen *time.Time
		state    []byte
	)
	if err := r.Scan(&n.ID, &n.PublicKey, &n.Fingerprint, &n.Enabled, &n.Description, &n.CreatedAt, &n.UpdatedAt, &lastSeen, &state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if lastSeen != nil {
		n.LastSeenAt = *lastSeen
	}
	if err := decodeState(state, &n); err != nil {
		return nil, fmt.Errorf("suristore: node %s: %w", n.ID, err)
	}
	return &n, nil
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func timeOrNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now()
	}
	return t
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// CreateNode implements store.Store.
func (s *Store) CreateNode(ctx context.Context, n *store.Node) error {
	x, err := X25519(n.PublicKey)
	if err != nil {
		return err
	}
	state, err := encodeState(n)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO openpicket.nodes
		(id, public_key, x25519, fingerprint, enabled, description, created_at, updated_at, suri_last_seen_at, suri_state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		n.ID, n.PublicKey, x, n.Fingerprint, n.Enabled, n.Description, timeOrNow(n.CreatedAt), timeOrNow(n.UpdatedAt), nullTime(n.LastSeenAt), state)
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	return err
}

// GetNode implements store.Store.
func (s *Store) GetNode(ctx context.Context, id string) (*store.Node, error) {
	return scanNode(s.db.QueryRow(ctx, `SELECT `+nodeColumns+` FROM openpicket.nodes WHERE id = $1`, id))
}

// ListNodes implements store.Store.
func (s *Store) ListNodes(ctx context.Context) ([]*store.Node, error) {
	rows, err := s.db.Query(ctx, `SELECT `+nodeColumns+` FROM openpicket.nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UpdateNode implements store.Store. The row is locked for the duration of
// fn, so updates from suricontroller and openpicket-manager serialize.
func (s *Store) UpdateNode(ctx context.Context, id string, fn func(n *store.Node) error) (*store.Node, error) {
	var out *store.Node
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		n, err := scanNode(tx.QueryRow(ctx, `SELECT `+nodeColumns+` FROM openpicket.nodes WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if err := fn(n); err != nil {
			return err
		}
		n.ID = id
		x, err := X25519(n.PublicKey)
		if err != nil {
			return err
		}
		state, err := encodeState(n)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE openpicket.nodes SET public_key=$2, x25519=$3, fingerprint=$4, enabled=$5, description=$6,
			created_at=$7, updated_at=$8, suri_last_seen_at=$9, suri_state=$10 WHERE id=$1`,
			id, n.PublicKey, x, n.Fingerprint, n.Enabled, n.Description, timeOrNow(n.CreatedAt), timeOrNow(n.UpdatedAt), nullTime(n.LastSeenAt), state)
		if isUniqueViolation(err) {
			return store.ErrAlreadyExists
		}
		out = n
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteNode implements store.Store.
func (s *Store) DeleteNode(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM openpicket.nodes WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// LookupNodeByX25519 implements store.Store.
func (s *Store) LookupNodeByX25519(ctx context.Context, key []byte) (string, bool, error) {
	var (
		id      string
		enabled bool
	)
	err := s.db.QueryRow(ctx, `SELECT id, enabled FROM openpicket.nodes WHERE x25519 = $1`, key).Scan(&id, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, store.ErrNotFound
	}
	return id, enabled, err
}

// --- apply history -----------------------------------------------------------

// AppendApplyHistory implements store.Store.
func (s *Store) AppendApplyHistory(ctx context.Context, e *store.ApplyHistoryEntry) error {
	rep, err := marshalProto(e.Report)
	if err != nil {
		return err
	}
	if rep == nil {
		rep = json.RawMessage("{}")
	}
	return s.db.QueryRow(ctx, `INSERT INTO suricontroller.apply_history (node_id, report, created_at) VALUES ($1,$2,$3) RETURNING id`,
		e.NodeID, []byte(rep), timeOrNow(e.CreatedAt)).Scan(&e.ID)
}

// ListApplyHistory implements store.Store.
func (s *Store) ListApplyHistory(ctx context.Context, nodeID string, limit int) ([]*store.ApplyHistoryEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(ctx, `SELECT id, node_id, report, created_at FROM suricontroller.apply_history
		WHERE node_id = $1 ORDER BY id DESC LIMIT $2`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.ApplyHistoryEntry
	for rows.Next() {
		var (
			e   store.ApplyHistoryEntry
			rep []byte
		)
		if err := rows.Scan(&e.ID, &e.NodeID, &rep, &e.CreatedAt); err != nil {
			return nil, err
		}
		if e.Report, err = unmarshalProto(rep, func() *agentv1.ApplyReport { return &agentv1.ApplyReport{} }); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// PruneApplyHistory implements store.Store.
func (s *Store) PruneApplyHistory(ctx context.Context, keep int) error {
	_, err := s.db.Exec(ctx, `DELETE FROM suricontroller.apply_history WHERE id IN (
		SELECT id FROM (
			SELECT id, row_number() OVER (PARTITION BY node_id ORDER BY id DESC) AS rn FROM suricontroller.apply_history
		) ranked WHERE rn > $1)`, keep)
	return err
}

// --- deploy policies ---------------------------------------------------------

// GetDeployPolicy implements store.Store.
func (s *Store) GetDeployPolicy(ctx context.Context, kind string) (*store.DeployPolicy, error) {
	var p store.DeployPolicy
	err := s.db.QueryRow(ctx, `SELECT kind, mode, pinned_commit, effective_commit, updated_at, updated_by
		FROM suricontroller.deploy_policies WHERE kind = $1`, kind).
		Scan(&p.Kind, &p.Mode, &p.PinnedCommit, &p.EffectiveCommit, &p.UpdatedAt, &p.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// PutDeployPolicy implements store.Store.
func (s *Store) PutDeployPolicy(ctx context.Context, p *store.DeployPolicy) error {
	_, err := s.db.Exec(ctx, `INSERT INTO suricontroller.deploy_policies (kind, mode, pinned_commit, effective_commit, updated_at, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (kind) DO UPDATE SET mode=excluded.mode, pinned_commit=excluded.pinned_commit,
			effective_commit=excluded.effective_commit, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		p.Kind, p.Mode, p.PinnedCommit, p.EffectiveCommit, timeOrNow(p.UpdatedAt), p.UpdatedBy)
	return err
}

// --- providers ---------------------------------------------------------------

const providerColumns = `name, type, enabled, interval_seconds, options, last_fetch_at, last_success_at, last_error, last_commit, checksum`

func scanProvider(r pgx.Row) (*store.Provider, error) {
	var (
		p                   store.Provider
		interval            int64
		options             []byte
		lastFetch, lastSucc *time.Time
	)
	if err := r.Scan(&p.Name, &p.Type, &p.Enabled, &interval, &options, &lastFetch, &lastSucc, &p.LastError, &p.LastCommit, &p.Checksum); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	p.Interval = time.Duration(interval) * time.Second
	if lastFetch != nil {
		p.LastFetchAt = *lastFetch
	}
	if lastSucc != nil {
		p.LastSuccessAt = *lastSucc
	}
	if len(options) > 0 {
		if err := json.Unmarshal(options, &p.Options); err != nil {
			return nil, err
		}
	}
	if len(p.Options) == 0 {
		p.Options = nil
	}
	return &p, nil
}

// ListProviders implements store.Store.
func (s *Store) ListProviders(ctx context.Context) ([]*store.Provider, error) {
	rows, err := s.db.Query(ctx, `SELECT `+providerColumns+` FROM suricontroller.providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Provider
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetProvider implements store.Store.
func (s *Store) GetProvider(ctx context.Context, name string) (*store.Provider, error) {
	return scanProvider(s.db.QueryRow(ctx, `SELECT `+providerColumns+` FROM suricontroller.providers WHERE name = $1`, name))
}

// PutProvider implements store.Store.
func (s *Store) PutProvider(ctx context.Context, p *store.Provider) error {
	opts := []byte("{}")
	if len(p.Options) > 0 {
		b, err := json.Marshal(p.Options)
		if err != nil {
			return err
		}
		opts = b
	}
	_, err := s.db.Exec(ctx, `INSERT INTO suricontroller.providers (`+providerColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (name) DO UPDATE SET type=excluded.type, enabled=excluded.enabled, interval_seconds=excluded.interval_seconds,
			options=excluded.options, last_fetch_at=excluded.last_fetch_at, last_success_at=excluded.last_success_at,
			last_error=excluded.last_error, last_commit=excluded.last_commit, checksum=excluded.checksum`,
		p.Name, p.Type, p.Enabled, int64(p.Interval/time.Second), opts, nullTime(p.LastFetchAt), nullTime(p.LastSuccessAt),
		p.LastError, p.LastCommit, p.Checksum)
	return err
}

// DeleteProvider implements store.Store.
func (s *Store) DeleteProvider(ctx context.Context, name string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM suricontroller.providers WHERE name = $1`, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// --- settings ----------------------------------------------------------------

// GetSetting implements store.Store.
func (s *Store) GetSetting(ctx context.Context, key string, v any) (bool, error) {
	var raw []byte
	err := s.db.QueryRow(ctx, `SELECT value FROM suricontroller.settings WHERE key = $1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if m, ok := v.(proto.Message); ok {
		return true, (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, m)
	}
	return true, json.Unmarshal(raw, v)
}

// PutSetting implements store.Store.
func (s *Store) PutSetting(ctx context.Context, key string, v any) error {
	var (
		b   []byte
		err error
	)
	if m, ok := v.(proto.Message); ok {
		b, err = protojson.Marshal(m)
	} else {
		b, err = json.Marshal(v)
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO suricontroller.settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value=excluded.value`, key, b)
	return err
}

// --- audit -------------------------------------------------------------------

// AppendAudit implements store.Store.
func (s *Store) AppendAudit(ctx context.Context, e *store.AuditEntry) error {
	return s.db.QueryRow(ctx, `INSERT INTO openpicket.audit (time, source, principal, action, target, detail)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		timeOrNow(e.Time), AuditSource, e.Principal, e.Action, e.Target, e.Detail).Scan(&e.ID)
}

// ListAudit implements store.Store. It lists the shared log (OpenPicket and
// suricontroller entries).
func (s *Store) ListAudit(ctx context.Context, limit int) ([]*store.AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(ctx, `SELECT id, time, principal, action, target, detail FROM openpicket.audit ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.AuditEntry
	for rows.Next() {
		var e store.AuditEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.Principal, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}
