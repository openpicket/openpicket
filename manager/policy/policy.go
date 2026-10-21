// Package policy stores port policies and address lists, compiles each
// node's bundle and streams it to the node (docs/ARCHITECTURE.md §4.4).
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/manager/geo"
	"github.com/openpicket/openpicket/manager/registry"
	"github.com/openpicket/openpicket/pkg/portpolicy"
)

// ErrNotFound is returned for an unknown policy or list.
var ErrNotFound = errors.New("policy: not found")

// ErrInvalid wraps validation errors.
var ErrInvalid = errors.New("policy: invalid")

// Service manages policies and serves bundles.
type Service struct {
	db  *pgxpool.Pool
	geo *geo.Store
	log *slog.Logger

	mu      sync.Mutex
	changed chan struct{}
	cache   *snapshot
	// loadMu serializes compilations (many nodes reconnect at once).
	loadMu sync.Mutex
}

// snapshot is everything bundles are compiled from, at one version.
type snapshot struct {
	version  uint64
	policies []portpolicy.Policy
	lists    map[string]portpolicy.List
	// results of compiling every policy (with last good versions).
	results map[string]portpolicy.Result
}

// New creates the service. Call Notified on openpicket_policy.
func New(pool *pgxpool.Pool, g *geo.Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{db: pool, geo: g, log: log.With("component", "policy"), changed: make(chan struct{})}
}

// Notified wakes the policy streams.
func (s *Service) Notified(string) {
	s.mu.Lock()
	close(s.changed)
	s.changed = make(chan struct{})
	s.cache = nil
	s.mu.Unlock()
}

func (s *Service) wait() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}

// Version returns the current policy generation.
func (s *Service) Version(ctx context.Context) (uint64, error) {
	var v int64
	err := s.db.QueryRow(ctx, `SELECT version FROM openpicket.policy_meta WHERE id = 1`).Scan(&v)
	return uint64(v), err
}

func (s *Service) load(ctx context.Context) (*snapshot, error) {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	s.mu.Lock()
	c := s.cache
	s.mu.Unlock()
	var (
		out  *snapshot
		prev map[string]stored
	)
	err := pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var v int64
		if err := tx.QueryRow(ctx, `SELECT version FROM openpicket.policy_meta WHERE id = 1`).Scan(&v); err != nil {
			return err
		}
		if c != nil && c.version == uint64(v) {
			out = c
			return nil
		}
		snap := &snapshot{version: uint64(v), lists: map[string]portpolicy.List{}}
		rows, err := tx.Query(ctx, `SELECT spec FROM openpicket.port_policies ORDER BY position, id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var raw []byte
			var p portpolicy.Policy
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			if err := json.Unmarshal(raw, &p); err != nil {
				rows.Close()
				return err
			}
			snap.policies = append(snap.policies, p)
		}
		rows.Close()
		rows, err = tx.Query(ctx, `SELECT spec FROM openpicket.ip_lists`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var raw []byte
			var l portpolicy.List
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return err
			}
			if err := json.Unmarshal(raw, &l); err != nil {
				rows.Close()
				return err
			}
			snap.lists[l.Name] = l
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if prev, err = loadStored(ctx, tx); err != nil {
			return err
		}
		out = snap
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out.results == nil {
		s.compileAll(ctx, out, prev)
	}
	s.mu.Lock()
	s.cache = out
	s.mu.Unlock()
	return out, nil
}

// Policies returns the policies in order.
func (s *Service) Policies(ctx context.Context) ([]portpolicy.Policy, error) {
	snap, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	return append([]portpolicy.Policy(nil), snap.policies...), nil
}

// Lists returns the address lists.
func (s *Service) Lists(ctx context.Context) ([]portpolicy.List, error) {
	snap, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]portpolicy.List, 0, len(snap.lists))
	for _, l := range snap.lists {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Service) listNames(ctx context.Context, tx pgx.Tx) (map[string]bool, error) {
	rows, err := tx.Query(ctx, `SELECT name FROM openpicket.ip_lists`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

func record(ctx context.Context, tx pgx.Tx, id, action string, spec any, version uint64, by string) error {
	var raw []byte
	if spec != nil {
		raw, _ = json.Marshal(spec)
	}
	_, err := tx.Exec(ctx, `INSERT INTO openpicket.policy_history (policy_id, version, action, spec, changed_at, changed_by) VALUES ($1,$2,$3,$4,now(),$5)`,
		id, int64(version), action, raw, by)
	return err
}

// PutPolicy creates or replaces a policy. position orders evaluation
// (lower first); a negative position keeps the current one or appends.
func (s *Service) PutPolicy(ctx context.Context, p portpolicy.Policy, position int, by string) (uint64, error) {
	var version uint64
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		names, err := s.listNames(ctx, tx)
		if err != nil {
			return err
		}
		if err := p.Validate(names); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if position < 0 {
			if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT position FROM openpicket.port_policies WHERE id = $1),
				(SELECT COALESCE(max(position), -1) + 1 FROM openpicket.port_policies))`, p.ID).Scan(&position); err != nil {
				return err
			}
		}
		raw, _ := json.Marshal(p)
		if _, err := tx.Exec(ctx, `INSERT INTO openpicket.port_policies (id, position, spec, updated_at, updated_by) VALUES ($1,$2,$3,now(),$4)
			ON CONFLICT (id) DO UPDATE SET position=excluded.position, spec=excluded.spec, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
			p.ID, position, raw, by); err != nil {
			return err
		}
		if version, err = geo.BumpPolicyVersion(ctx, tx); err != nil {
			return err
		}
		return record(ctx, tx, p.ID, "put", p, version, by)
	})
	return version, err
}

// DeletePolicy removes a policy.
func (s *Service) DeletePolicy(ctx context.Context, id, by string) (uint64, error) {
	var version uint64
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM openpicket.port_policies WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		// An explicit deletion removes the policy from the nodes, last good
		// version included.
		if _, err := tx.Exec(ctx, `DELETE FROM openpicket.policy_compiled WHERE policy_id = $1`, id); err != nil {
			return err
		}
		if version, err = geo.BumpPolicyVersion(ctx, tx); err != nil {
			return err
		}
		return record(ctx, tx, id, "delete", nil, version, by)
	})
	return version, err
}

// PutList creates or replaces an address list.
func (s *Service) PutList(ctx context.Context, l portpolicy.List, description, by string) (uint64, error) {
	p := portpolicy.Policy{ID: "list_check", Mode: portpolicy.ModeEnforce, Proto: "tcp", Ports: []portpolicy.PortRange{{From: 1, To: 1}},
		Default: portpolicy.ActionAccept, Rules: []portpolicy.Rule{{Source: portpolicy.Source{CIDRs: l.CIDRs, ASNs: l.ASNs}, Action: portpolicy.ActionAccept}}}
	if l.Name == "" || len(l.Name) > 64 {
		return 0, fmt.Errorf("%w: list name must be 1-64 characters", ErrInvalid)
	}
	if err := p.Validate(nil); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var version uint64
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		raw, _ := json.Marshal(l)
		if _, err := tx.Exec(ctx, `INSERT INTO openpicket.ip_lists (name, description, spec, updated_at, updated_by) VALUES ($1,$2,$3,now(),$4)
			ON CONFLICT (name) DO UPDATE SET description=excluded.description, spec=excluded.spec, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
			l.Name, description, raw, by); err != nil {
			return err
		}
		var err error
		if version, err = geo.BumpPolicyVersion(ctx, tx); err != nil {
			return err
		}
		return record(ctx, tx, "list:"+l.Name, "put", l, version, by)
	})
	return version, err
}

// DeleteList removes a list that no policy uses.
func (s *Service) DeleteList(ctx context.Context, name, by string) (uint64, error) {
	var version uint64
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var users []string
		rows, err := tx.Query(ctx, `SELECT spec FROM openpicket.port_policies`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var (
				raw []byte
				p   portpolicy.Policy
			)
			if rows.Scan(&raw) != nil || json.Unmarshal(raw, &p) != nil {
				continue
			}
			for _, r := range p.Rules {
				if slices.Contains(r.Source.Lists, name) {
					users = append(users, p.ID)
					break
				}
			}
		}
		rows.Close()
		if len(users) > 0 {
			return fmt.Errorf("%w: list %q is used by %v", ErrInvalid, name, users)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM openpicket.ip_lists WHERE name = $1`, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if version, err = geo.BumpPolicyVersion(ctx, tx); err != nil {
			return err
		}
		return record(ctx, tx, "list:"+name, "delete", nil, version, by)
	})
	return version, err
}

// Bundle compiles the bundle of a node.
func (s *Service) Bundle(ctx context.Context, nodeID string, labels map[string]string) (*dataplanev1.PolicyBundle, []portpolicy.Skipped, error) {
	snap, err := s.load(ctx)
	if err != nil {
		return nil, nil, err
	}
	b, skipped := portpolicy.Assemble(snap.version, snap.policies, snap.results, nodeID, labels)
	return b, skipped, nil
}

// Serve runs the policy stream of one node: the node's bundle whenever the
// generation differs from what the node has. node returns the current
// registry entry (labels select policies and may change while connected).
func (s *Service) Serve(ctx context.Context, node func() *registry.Node, ms *wire.MsgStream) error {
	up := &dataplanev1.PolicyUp{}
	if err := ms.Recv(up); err != nil {
		return err
	}
	if up.GetSubscribe() == nil {
		return errors.New("policy: first message must be a subscribe")
	}
	// What was sent: the generation and the content (a label change, or a
	// policy falling back to or recovering from its last good version,
	// changes the bundle without a new generation). The first bundle is
	// always sent.
	var (
		sent        string
		sentVersion uint64
	)
	acks := make(chan *dataplanev1.PolicyAck, 1)
	errc := make(chan error, 1)
	go func() {
		for {
			m := &dataplanev1.PolicyUp{}
			if err := ms.Recv(m); err != nil {
				errc <- err
				return
			}
			if a := m.GetAck(); a != nil {
				select {
				case acks <- a:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	periodic := time.NewTicker(time.Minute)
	defer periodic.Stop()
	for {
		changed := s.wait()
		n := node()
		b, skipped, err := s.Bundle(ctx, n.ID, n.Labels)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.log.Warn("compile policy bundle", "node", n.ID, "err", err)
		case b.Version != sentVersion || bundleKey(b) != sent:
			if len(skipped) > 0 {
				s.log.Warn("policies left out of the bundle", "node", n.ID, "skipped", skipped)
			}
			if err := ms.Send(b); err != nil {
				return err
			}
			select {
			case a := <-acks:
				s.record(ctx, n.ID, a, skipped)
				// Do not resend a refused bundle until something changes.
				sent, sentVersion = bundleKey(b), b.Version
			case err := <-errc:
				return err
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Minute):
				return errors.New("policy: no acknowledgement")
			}
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			return err
		case <-changed:
		case <-periodic.C:
		}
	}
}

func (s *Service) record(ctx context.Context, nodeID string, a *dataplanev1.PolicyAck, skipped []portpolicy.Skipped) {
	if skipped == nil {
		skipped = []portpolicy.Skipped{}
	}
	raw, _ := json.Marshal(skipped)
	if _, err := s.db.Exec(ctx, `INSERT INTO openpicket.node_policy_state (node_id, version, error, skipped, acked_at) VALUES ($1,$2,$3,$4,now())
		ON CONFLICT (node_id) DO UPDATE SET version=excluded.version, error=excluded.error, skipped=excluded.skipped, acked_at=excluded.acked_at`,
		nodeID, int64(a.Version), a.Error, raw); err != nil {
		s.log.Debug("record policy ack", "node", nodeID, "err", err)
	}
	if a.Error != "" {
		s.log.Warn("node refused its policy bundle", "node", nodeID, "version", a.Version, "err", a.Error)
	}
}

// bundleKey identifies the content of a bundle.
func bundleKey(b *dataplanev1.PolicyBundle) string {
	raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(b)
	sum := sha256.Sum256(raw)
	return string(sum[:])
}
