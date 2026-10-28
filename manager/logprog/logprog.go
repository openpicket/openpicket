// Package logprog keeps track of the generic log programs the nodes send
// (counts per node, for the UI) and of the ones not stored in Loki.
package logprog

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/manager/settings"
	"github.com/openpicket/openpicket/pkg/record"
)

// KeyStorage is the setting naming the programs kept out of Loki.
const KeyStorage = "logs.storage"

// Storage is the KeyStorage setting.
type Storage struct {
	// LokiSkip lists programs whose lines go to CrowdSec but not to Loki
	// (high volume access logs).
	LokiSkip []string `json:"loki_skip"`
}

// Store counts programs and holds the storage setting.
type Store struct {
	db       *pgxpool.Pool
	settings *settings.Store
	log      *slog.Logger

	mu      sync.Mutex
	pending map[[2]string]int64

	skip atomic.Pointer[[]string]
}

// New creates a store; call Load, then Run.
func New(pool *pgxpool.Pool, st *settings.Store, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{db: pool, settings: st, log: log.With("component", "logprog"), pending: map[[2]string]int64{}}
	s.skip.Store(&[]string{})
	return s
}

// Seen implements pipeline.ProgramCounter.
func (s *Store) Seen(nodeID, program string, lines int) {
	s.mu.Lock()
	s.pending[[2]string{nodeID, program}] += int64(lines)
	s.mu.Unlock()
}

// Skip reports a program kept out of Loki.
func (s *Store) Skip(program string) bool { return slices.Contains(*s.skip.Load(), program) }

// Load reads the storage setting (and again on a settings notification).
func (s *Store) Load(ctx context.Context) {
	var st Storage
	if _, err := s.settings.Get(ctx, KeyStorage, &st); err != nil {
		s.log.Warn("read log storage settings", "err", err)
		return
	}
	s.skip.Store(&st.LokiSkip)
}

// Storage returns the setting.
func (s *Store) Storage() Storage { return Storage{LokiSkip: slices.Clone(*s.skip.Load())} }

// SetLoki stores (or not) a program's lines in Loki.
func (s *Store) SetLoki(ctx context.Context, program string, store bool) error {
	program = record.NormalizeProgram(program)
	st := s.Storage()
	st.LokiSkip = slices.DeleteFunc(st.LokiSkip, func(p string) bool { return p == program })
	if !store && program != "" {
		st.LokiSkip = append(st.LokiSkip, program)
		slices.Sort(st.LokiSkip)
	}
	if err := s.settings.Put(ctx, KeyStorage, st); err != nil {
		return err
	}
	s.skip.Store(&st.LokiSkip)
	return nil
}

// Run flushes the counts every 30 seconds and prunes old rows daily.
func (s *Store) Run(ctx context.Context) {
	flush := time.NewTicker(30 * time.Second)
	defer flush.Stop()
	prune := time.NewTicker(24 * time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.Flush(fctx)
			cancel()
			return
		case <-flush.C:
			s.Flush(ctx)
		case <-prune.C:
			if _, err := s.db.Exec(ctx, `DELETE FROM openpicket.log_programs WHERE last_seen < now() - interval '30 days'`); err != nil {
				s.log.Warn("prune log programs", "err", err)
			}
		}
	}
}

// Flush writes the pending counts.
func (s *Store) Flush(ctx context.Context) {
	s.mu.Lock()
	pending := s.pending
	s.pending = map[[2]string]int64{}
	s.mu.Unlock()
	for k, n := range pending {
		if _, err := s.db.Exec(ctx, `INSERT INTO openpicket.log_programs (node_id, program, lines) VALUES ($1, $2, $3)
			ON CONFLICT (node_id, program) DO UPDATE SET lines = log_programs.lines + excluded.lines, last_seen = now()`, k[0], k[1], n); err != nil {
			s.log.Warn("record log program", "node", k[0], "program", k[1], "err", err)
		}
	}
}

// Program is a program seen on some nodes.
type Program struct {
	Program  string
	Nodes    []string
	Lines    int64
	LastSeen time.Time
	// Loki: its lines are stored in Loki.
	Loki bool
}

// List returns the programs seen, most recent first.
func (s *Store) List(ctx context.Context) ([]Program, error) {
	rows, err := s.db.Query(ctx, `SELECT program, array_agg(node_id ORDER BY node_id), sum(lines)::bigint, max(last_seen)
		FROM openpicket.log_programs GROUP BY program ORDER BY max(last_seen) DESC, program`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Program
	for rows.Next() {
		var p Program
		if err := rows.Scan(&p.Program, &p.Nodes, &p.Lines, &p.LastSeen); err != nil {
			return nil, err
		}
		p.Loki = !s.Skip(p.Program)
		out = append(out, p)
	}
	return out, rows.Err()
}
