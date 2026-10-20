// Package settings stores runtime settings edited in the UI
// (openpicket.settings). Values are cached per replica and reloaded on the
// openpicket_settings notification.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

// Keys.
const (
	KeyLogPolicy = "logs.policy"
)

// DefaultLogPolicy collects every eve event type, the Suricata log and the
// agent log.
func DefaultLogPolicy() *agentv1.LogCollectionPolicy {
	return &agentv1.LogCollectionPolicy{
		Enabled:     true,
		Types:       []agentv1.LogType{agentv1.LogType_LOG_TYPE_EVE, agentv1.LogType_LOG_TYPE_SURICATA, agentv1.LogType_LOG_TYPE_AGENT},
		EveAllTypes: true,
	}
}

// Store reads and writes settings.
type Store struct {
	db *pgxpool.Pool

	mu    sync.Mutex
	cache map[string]json.RawMessage

	// OnChange is called with the key after a notified change.
	OnChange func(key string)
}

// New creates a store.
func New(db *pgxpool.Pool) *Store { return &Store{db: db, cache: map[string]json.RawMessage{}} }

// Get decodes a setting into v; it reports false if unset. Database errors
// fall back to the cached value.
func (s *Store) Get(ctx context.Context, key string, v any) (bool, error) {
	var raw []byte
	err := s.db.QueryRow(ctx, `SELECT value FROM openpicket.settings WHERE key = $1`, key).Scan(&raw)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		s.mu.Lock()
		delete(s.cache, key)
		s.mu.Unlock()
		return false, nil
	case err != nil:
		s.mu.Lock()
		c, ok := s.cache[key]
		s.mu.Unlock()
		if !ok {
			return false, err
		}
		raw = c
	default:
		s.mu.Lock()
		s.cache[key] = raw
		s.mu.Unlock()
	}
	return true, decode(raw, v)
}

func decode(raw []byte, v any) error {
	if m, ok := v.(*agentv1.LogCollectionPolicy); ok {
		return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(raw, m)
	}
	return json.Unmarshal(raw, v)
}

// Put stores a setting.
func (s *Store) Put(ctx context.Context, key string, v any) error {
	var (
		b   []byte
		err error
	)
	if m, ok := v.(*agentv1.LogCollectionPolicy); ok {
		b, err = protojson.Marshal(m)
	} else {
		b, err = json.Marshal(v)
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO openpicket.settings (key, value, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()`, key, b)
	return err
}

// LogPolicy returns the collection policy pushed to agents.
func (s *Store) LogPolicy(ctx context.Context) *agentv1.LogCollectionPolicy {
	p := &agentv1.LogCollectionPolicy{}
	if ok, err := s.Get(ctx, KeyLogPolicy, p); !ok || err != nil {
		return DefaultLogPolicy()
	}
	return p
}

// Notified handles a settings notification.
func (s *Store) Notified(key string) {
	if s.OnChange != nil {
		s.OnChange(key)
	}
}
