package allowlist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openpicket/openpicket/pkg/allowsync"
)

// State returns the active entries as the LAPI allowlist content.
func (s *Store) State(ctx context.Context) (allowsync.State, error) {
	rows, err := s.db.Query(ctx, `SELECT network, description, expires_at FROM openpicket.allowlist
		WHERE expires_at IS NULL OR expires_at > $1 ORDER BY network`, s.now())
	if err != nil {
		return allowsync.State{}, err
	}
	st := allowsync.State{Items: []allowsync.Item{}}
	for rows.Next() {
		var e Entry
		var exp *time.Time
		if err := rows.Scan(&e.Network, &e.Description, &exp); err != nil {
			rows.Close()
			return allowsync.State{}, err
		}
		st.Items = append(st.Items, allowsync.Item{Value: allowsync.Value(e.Network), Description: e.Description, ExpiresAt: exp})
	}
	rows.Close()
	return st, rows.Err()
}

// SyncStatus is the last push to one LAPI.
type SyncStatus struct {
	Instance  string
	AttemptAt time.Time
	// SyncedAt and ChangedAt are zero until a push succeeded (changed).
	SyncedAt  time.Time
	ChangedAt time.Time
	Items     int
	// Error of the last attempt ("" when it succeeded).
	Error string
}

// SyncStatuses returns the last push to every LAPI, by instance.
func (s *Store) SyncStatuses(ctx context.Context) (map[string]SyncStatus, error) {
	rows, err := s.db.Query(ctx, `SELECT instance, attempt_at, synced_at, changed_at, items, error FROM openpicket.allowlist_lapi_sync`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SyncStatus{}
	for rows.Next() {
		var (
			st              SyncStatus
			synced, changed *time.Time
		)
		if err := rows.Scan(&st.Instance, &st.AttemptAt, &synced, &changed, &st.Items, &st.Error); err != nil {
			return nil, err
		}
		if synced != nil {
			st.SyncedAt = *synced
		}
		if changed != nil {
			st.ChangedAt = *changed
		}
		out[st.Instance] = st
	}
	return out, rows.Err()
}

// Target is a LAPI whose openpicket allowlist follows the entries.
type Target struct {
	Instance string
	// URL of the instance's openpicket-crowdsec-sync (http://lapi:8082).
	URL string
}

// Fencer runs a transaction that commits only while this replica leads.
type Fencer interface {
	Fenced(ctx context.Context, fn func(tx pgx.Tx) error) error
}

// LAPISync pushes the entries to the LAPIs (leader task): after every
// change and every Interval, since entries run out and the LAPI may be
// changed by hand. A push that finds the allowlist in sync changes nothing.
type LAPISync struct {
	Store   *Store
	Targets []Target
	// Header and Token authenticate to openpicket-crowdsec-sync (the
	// datasource token).
	Header, Token string
	Client        *http.Client
	// Interval between pushes without a change (default 1m).
	Interval time.Duration
	Logger   *slog.Logger

	poke chan struct{}
}

// Init must be called before Run and Notified.
func (s *LAPISync) Init() {
	s.poke = make(chan struct{}, 1)
	if s.Client == nil {
		s.Client = &http.Client{Timeout: 2 * time.Minute}
	}
	if s.Interval <= 0 {
		s.Interval = time.Minute
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	s.Logger = s.Logger.With("component", "allowlist-sync")
}

// Notified reports an allowlist change (openpicket_allowlist).
func (s *LAPISync) Notified(string) {
	select {
	case s.poke <- struct{}{}:
	default:
	}
}

// Run pushes until ctx ends.
func (s *LAPISync) Run(ctx context.Context, l Fencer) {
	for {
		if err := s.Pass(ctx, l); err != nil && ctx.Err() == nil {
			s.Logger.Warn("allowlist sync", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-s.poke:
		case <-time.After(s.Interval):
		}
	}
}

// Pass pushes the current entries to every target once.
func (s *LAPISync) Pass(ctx context.Context, l Fencer) error {
	if len(s.Targets) == 0 {
		return nil
	}
	st, err := s.Store.State(ctx)
	if err != nil {
		return err
	}
	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	for _, t := range s.Targets {
		res, err := s.push(ctx, t.URL, body)
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			s.Logger.Warn("push the allowlist to a LAPI", "instance", t.Instance, "err", err)
		} else if res.Created || res.Added+res.Removed > 0 {
			s.Logger.Info("LAPI allowlist updated", "instance", t.Instance, "added", res.Added, "removed", res.Removed, "items", res.Items)
		}
		if rerr := s.record(ctx, l, t.Instance, res, err); rerr != nil {
			return rerr
		}
	}
	return nil
}

func (s *LAPISync) push(ctx context.Context, base string, body []byte) (allowsync.Result, error) {
	var res allowsync.Result
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, strings.TrimRight(base, "/")+allowsync.Path, bytes.NewReader(body))
	if err != nil {
		return res, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(s.Header, s.Token)
	resp, err := s.Client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(b))
		if resp.StatusCode == http.StatusNotFound {
			msg = "no allowlist endpoint (is the local API in this container, and the image up to date?)"
		}
		return res, fmt.Errorf("status %d: %s", resp.StatusCode, msg)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return res, fmt.Errorf("bad response: %w", err)
	}
	return res, nil
}

func (s *LAPISync) record(ctx context.Context, l Fencer, instance string, res allowsync.Result, perr error) error {
	fn := func(tx pgx.Tx) error {
		now := s.Store.now()
		if perr != nil {
			_, err := tx.Exec(ctx, `INSERT INTO openpicket.allowlist_lapi_sync (instance, attempt_at, error) VALUES ($1, $2, $3)
				ON CONFLICT (instance) DO UPDATE SET attempt_at = excluded.attempt_at, error = excluded.error`, instance, now, perr.Error())
			return err
		}
		var changed *time.Time
		if res.Created || res.Added+res.Removed > 0 {
			changed = &now
		}
		_, err := tx.Exec(ctx, `INSERT INTO openpicket.allowlist_lapi_sync (instance, attempt_at, synced_at, changed_at, items, error) VALUES ($1, $2, $2, $3, $4, '')
			ON CONFLICT (instance) DO UPDATE SET attempt_at = excluded.attempt_at, synced_at = excluded.synced_at,
				changed_at = COALESCE(excluded.changed_at, openpicket.allowlist_lapi_sync.changed_at), items = excluded.items, error = ''`,
			instance, now, changed, res.Items)
		return err
	}
	var err error
	if l == nil {
		err = pgx.BeginFunc(ctx, s.Store.db, fn)
	} else {
		err = l.Fenced(ctx, fn)
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
