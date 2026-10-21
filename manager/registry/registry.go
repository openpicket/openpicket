// Package registry is the manager's view of the node registry
// (openpicket.nodes): key lookups for channel B handshakes and the node
// labels used for enrichment.
//
// Lookups always query the database. Successful answers are cached so that
// new connections are still accepted while the database is unavailable
// (§3.1); a node removed or disabled leaves the cache on its notification.
package registry

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned for an unknown key.
var ErrNotFound = errors.New("registry: unknown node key")

// Node is the registry information the data plane needs.
type Node struct {
	ID      string
	Enabled bool
	Labels  map[string]string
}

// Site returns the "site" label.
func (n *Node) Site() string { return n.Labels["site"] }

// Registry answers node lookups.
type Registry struct {
	db  *pgxpool.Pool
	log *slog.Logger

	mu    sync.RWMutex
	byKey map[string]*Node // hex x25519 -> node
	byID  map[string]*Node
	keyOf map[string]string // id -> hex x25519

	// OnRevoked is called when a node is removed or disabled.
	OnRevoked func(nodeID string)
}

// New creates a registry.
func New(db *pgxpool.Pool, log *slog.Logger) *Registry {
	if log == nil {
		log = slog.Default()
	}
	return &Registry{db: db, log: log.With("component", "registry"), byKey: map[string]*Node{}, byID: map[string]*Node{}, keyOf: map[string]string{}}
}

func (r *Registry) store(key string, n *Node) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.keyOf[n.ID]; ok && old != key {
		delete(r.byKey, old)
	}
	r.byKey[key], r.byID[n.ID], r.keyOf[n.ID] = n, n, key
}

func (r *Registry) forget(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.keyOf[id]; ok {
		delete(r.byKey, k)
	}
	delete(r.byID, id)
	delete(r.keyOf, id)
}

func scanNode(row pgx.Row) (*Node, []byte, error) {
	var (
		n      Node
		labels []byte
		key    []byte
	)
	if err := row.Scan(&n.ID, &n.Enabled, &labels, &key); err != nil {
		return nil, nil, err
	}
	if len(labels) > 0 {
		_ = json.Unmarshal(labels, &n.Labels)
	}
	if n.Labels == nil {
		n.Labels = map[string]string{}
	}
	return &n, key, nil
}

// Lookup finds the node of an X25519 key. Database errors fall back to the
// cache; without a cached answer they are returned as is.
func (r *Registry) Lookup(ctx context.Context, x25519 []byte) (*Node, error) {
	k := hex.EncodeToString(x25519)
	n, _, err := scanNode(r.db.QueryRow(ctx, `SELECT id, enabled, labels, x25519 FROM openpicket.nodes WHERE x25519 = $1`, x25519))
	switch {
	case err == nil:
		r.store(k, n)
		return n, nil
	case errors.Is(err, pgx.ErrNoRows):
		r.mu.Lock()
		if c, ok := r.byKey[k]; ok {
			delete(r.byKey, k)
			delete(r.byID, c.ID)
			delete(r.keyOf, c.ID)
		}
		r.mu.Unlock()
		return nil, ErrNotFound
	}
	r.mu.RLock()
	c, ok := r.byKey[k]
	r.mu.RUnlock()
	if ok {
		r.log.Warn("node lookup failed; using cached registry entry", "node", c.ID, "err", err)
		return c, nil
	}
	return nil, err
}

// Node returns the cached registry entry of a connected node.
func (r *Registry) Node(id string) *Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

// Changed reloads one node after a registry notification.
func (r *Registry) Changed(ctx context.Context, id string) {
	n, key, err := scanNode(r.db.QueryRow(ctx, `SELECT id, enabled, labels, x25519 FROM openpicket.nodes WHERE id = $1`, id))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		r.forget(id)
		if r.OnRevoked != nil {
			r.OnRevoked(id)
		}
		return
	case err != nil:
		r.log.Warn("reload node", "node", id, "err", err)
		return
	}
	if !n.Enabled {
		r.forget(id)
		if r.OnRevoked != nil {
			r.OnRevoked(id)
		}
		return
	}
	r.store(hex.EncodeToString(key), n)
}

// Resync reloads every cached node (after missed notifications).
func (r *Registry) Resync(ctx context.Context) {
	r.mu.RLock()
	ids := make([]string, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	r.mu.RUnlock()
	for _, id := range ids {
		r.Changed(ctx, id)
	}
}
