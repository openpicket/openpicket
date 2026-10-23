// Package hub manages the CrowdSec content (docs/ARCHITECTURE.md §8):
// items in PostgreSQL with their state, the built-in items written at
// start, and the rollout of bundles to the log processors.
package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	builtin "github.com/openpicket/openpicket/hub"
	"github.com/openpicket/openpicket/manager/db"
	"github.com/openpicket/openpicket/pkg/hubitem"
)

// Errors returned to the API.
var (
	ErrNotFound = errors.New("hub: not found")
	ErrInvalid  = errors.New("hub: invalid")
)

// Store keeps the items.
type Store struct {
	db  *pgxpool.Pool
	log *slog.Logger
}

// NewStore creates a store.
func NewStore(pool *pgxpool.Pool, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	return &Store{db: pool, log: log.With("component", "hub")}
}

// Ref names an item.
type Ref struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// Item is a stored item with its state.
type Item struct {
	Ref
	Source      string
	Version     string
	Stage       string
	Digest      string
	Description string
	Members     []Ref
	Data        []string
	Explicit    bool
	State       string
	UpdatedAt   time.Time
	UpdatedBy   string
	// MemberOf lists the collections having the item.
	MemberOf []string
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// DefaultState of a new item: OpenPicket's own content runs; added
// scenarios start in simulation (alerts, no decisions) until reviewed.
func DefaultState(typ, source string) string {
	if source != hubitem.SourceBuiltin && (typ == hubitem.Scenarios || typ == hubitem.Collections) {
		return hubitem.Simulation
	}
	return hubitem.Enabled
}

// seedLock serializes the built-in seeding of replicas starting together.
const seedLock = 0x6f70686275 // "ophub"

// SeedBuiltin writes the built-in items, unless a newer manager already
// wrote a higher revision (a rolling upgrade: this replica is the old
// one). Items of other sources are left alone; a built-in item takes over
// a hub or custom item of the same name.
func (s *Store) SeedBuiltin(ctx context.Context) error {
	items, err := builtin.Builtin()
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(seedLock)); err != nil {
			return err
		}
		var stored int
		if err := tx.QueryRow(ctx, `SELECT builtin_revision FROM openpicket.hub_meta WHERE id = 1`).Scan(&stored); err != nil {
			return err
		}
		if stored > builtin.BuiltinRevision {
			s.log.Warn("built-in content of a newer manager is stored; leaving it", "stored", stored, "mine", builtin.BuiltinRevision)
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT type, name, source, digest FROM openpicket.hub_items`)
		if err != nil {
			return err
		}
		type cur struct{ source, digest string }
		have := map[Ref]cur{}
		for rows.Next() {
			var r Ref
			var c cur
			if err := rows.Scan(&r.Type, &r.Name, &c.source, &c.digest); err != nil {
				rows.Close()
				return err
			}
			have[r] = c
		}
		rows.Close()
		changed := 0
		want := map[Ref]bool{}
		for _, it := range items {
			ref := Ref{it.Type, it.Name}
			want[ref] = true
			d := digest(it.Content)
			if c, ok := have[ref]; ok && c.source == hubitem.SourceBuiltin && c.digest == d {
				continue
			}
			changed++
			if _, err := tx.Exec(ctx, `INSERT INTO openpicket.hub_items (type, name, source, version, stage, content, digest, description, explicit, updated_by)
				VALUES ($1,$2,'builtin',$3,$4,$5,$6,$7,true,'openpicket')
				ON CONFLICT (type, name) DO UPDATE SET source='builtin', version=excluded.version, stage=excluded.stage, content=excluded.content,
					digest=excluded.digest, description=excluded.description, members='[]', data='[]', explicit=true, updated_at=now(), updated_by='openpicket'`,
				it.Type, it.Name, it.Version, it.Stage, it.Content, d, it.Description); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openpicket.hub_item_state (type, name, state, updated_by) VALUES ($1,$2,$3,'openpicket')
				ON CONFLICT DO NOTHING`, it.Type, it.Name, DefaultState(it.Type, hubitem.SourceBuiltin)); err != nil {
				return err
			}
		}
		for ref, c := range have {
			if c.source == hubitem.SourceBuiltin && !want[ref] {
				changed++
				if err := deleteItem(ctx, tx, ref); err != nil {
					return err
				}
			}
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT revision FROM openpicket.hub_meta WHERE id = 1`).Scan(&revision); err != nil {
			return err
		}
		if changed == 0 && stored == builtin.BuiltinRevision && revision > 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE openpicket.hub_meta SET builtin_revision = $1 WHERE id = 1`, builtin.BuiltinRevision); err != nil {
			return err
		}
		s.log.Info("built-in CrowdSec content stored", "revision", builtin.BuiltinRevision, "changed", changed)
		return bump(ctx, tx)
	})
}

func deleteItem(ctx context.Context, tx pgx.Tx, ref Ref) error {
	if _, err := tx.Exec(ctx, `DELETE FROM openpicket.hub_items WHERE type = $1 AND name = $2`, ref.Type, ref.Name); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM openpicket.hub_item_state WHERE type = $1 AND name = $2`, ref.Type, ref.Name)
	return err
}

// bump takes the next content revision and tells the replicas.
func bump(ctx context.Context, tx pgx.Tx) error {
	var rev int64
	if err := tx.QueryRow(ctx, `UPDATE openpicket.hub_meta SET revision = nextval('openpicket.hub_revision') WHERE id = 1 RETURNING revision`).Scan(&rev); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, db.ChannelHub, strconv.FormatInt(rev, 10))
	return err
}

// Items lists the stored items (all types when typ is "").
func (s *Store) Items(ctx context.Context, typ string) ([]Item, error) {
	rows, err := s.db.Query(ctx, `SELECT i.type, i.name, i.source, i.version, i.stage, i.digest, i.description, i.members, i.data, i.explicit,
			COALESCE(st.state, ''), i.updated_at, i.updated_by
		FROM openpicket.hub_items i LEFT JOIN openpicket.hub_item_state st ON st.type = i.type AND st.name = i.name
		WHERE $1 = '' OR i.type = $1 ORDER BY i.type, i.name`, typ)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var (
			it            Item
			members, data []byte
		)
		if err := rows.Scan(&it.Type, &it.Name, &it.Source, &it.Version, &it.Stage, &it.Digest, &it.Description, &members, &data, &it.Explicit,
			&it.State, &it.UpdatedAt, &it.UpdatedBy); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(members, &it.Members)
		_ = json.Unmarshal(data, &it.Data)
		if it.State == "" {
			it.State = DefaultState(it.Type, it.Source)
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Collection membership (for typ == "", or the members' own type).
	cols := out
	if typ != "" && typ != hubitem.Collections {
		if cols, err = s.Items(ctx, hubitem.Collections); err != nil {
			return nil, err
		}
	}
	memberOf := map[Ref][]string{}
	for _, c := range cols {
		if c.Type != hubitem.Collections {
			continue
		}
		for _, m := range c.Members {
			memberOf[m] = append(memberOf[m], c.Name)
		}
	}
	for i := range out {
		out[i].MemberOf = memberOf[out[i].Ref]
	}
	return out, nil
}

// Content returns an item's file.
func (s *Store) Content(ctx context.Context, ref Ref) ([]byte, error) {
	var b []byte
	err := s.db.QueryRow(ctx, `SELECT content FROM openpicket.hub_items WHERE type = $1 AND name = $2`, ref.Type, ref.Name).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

// SetState changes an item's state; a collection's state goes to its
// members too (simulation applies to its scenarios, the others run).
func (s *Store) SetState(ctx context.Context, ref Ref, state, by string) error {
	if !hubitem.ValidState(ref.Type, state) {
		return fmt.Errorf("%w: state %q does not apply to %s", ErrInvalid, state, ref.Type)
	}
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var members []byte
		err := tx.QueryRow(ctx, `SELECT members FROM openpicket.hub_items WHERE type = $1 AND name = $2 FOR UPDATE`, ref.Type, ref.Name).Scan(&members)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		targets := map[Ref]string{ref: state}
		if ref.Type == hubitem.Collections {
			if err := s.collectMembers(ctx, tx, members, state, targets, 0); err != nil {
				return err
			}
		}
		for r, st := range targets {
			if _, err := tx.Exec(ctx, `INSERT INTO openpicket.hub_item_state (type, name, state, updated_by) VALUES ($1,$2,$3,$4)
				ON CONFLICT (type, name) DO UPDATE SET state=excluded.state, updated_at=now(), updated_by=excluded.updated_by`,
				r.Type, r.Name, st, by); err != nil {
				return err
			}
		}
		return bump(ctx, tx)
	})
}

// collectMembers adds a collection's members (nested collections too)
// with the state they take.
func (s *Store) collectMembers(ctx context.Context, tx pgx.Tx, raw []byte, state string, out map[Ref]string, depth int) error {
	if depth > 8 {
		return nil
	}
	var members []Ref
	_ = json.Unmarshal(raw, &members)
	for _, m := range members {
		if _, seen := out[m]; seen {
			continue
		}
		st := state
		if state == hubitem.Simulation && m.Type != hubitem.Scenarios && m.Type != hubitem.Collections {
			st = hubitem.Enabled
		}
		out[m] = st
		if m.Type == hubitem.Collections {
			var nested []byte
			if err := tx.QueryRow(ctx, `SELECT members FROM openpicket.hub_items WHERE type = $1 AND name = $2`, m.Type, m.Name).Scan(&nested); err == nil {
				if err := s.collectMembers(ctx, tx, nested, state, out, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Bundle renders the current content: the items not disabled, the data
// files they read and the scenarios in simulation. Read in one snapshot,
// with the revision it is.
func (s *Store) Bundle(ctx context.Context) (*hubitem.Bundle, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	b := &hubitem.Bundle{}
	if err := tx.QueryRow(ctx, `SELECT revision FROM openpicket.hub_meta WHERE id = 1`).Scan(&b.Revision); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT i.type, i.name, i.source, i.stage, i.content, i.data, COALESCE(st.state, '')
		FROM openpicket.hub_items i LEFT JOIN openpicket.hub_item_state st ON st.type = i.type AND st.name = i.name
		WHERE i.type <> 'collections' ORDER BY i.type, i.name`)
	if err != nil {
		return nil, err
	}
	dataSet := map[string]bool{}
	for rows.Next() {
		var (
			typ, name, source, stage, state string
			content, data                   []byte
		)
		if err := rows.Scan(&typ, &name, &source, &stage, &content, &data, &state); err != nil {
			rows.Close()
			return nil, err
		}
		if state == "" {
			state = DefaultState(typ, source)
		}
		if state == hubitem.Disabled {
			continue
		}
		p, err := hubitem.ItemPath(typ, stage, name)
		if err != nil {
			s.log.Warn("skipping an item with an invalid path", "type", typ, "name", name, "err", err)
			continue
		}
		b.Items = append(b.Items, hubitem.File{Path: p, Content: content})
		if typ == hubitem.Scenarios && state == hubitem.Simulation {
			// simulation.yaml names buckets: an item file can hold several.
			names := []string{name}
			if doc, err := hubitem.ParseDoc(typ, content); err == nil && len(doc.Names) > 0 {
				names = doc.Names
			}
			for _, n := range names {
				if hubitem.ValidName(n) && !slices.Contains(b.Simulation, n) {
					b.Simulation = append(b.Simulation, n)
				}
			}
		}
		var files []string
		_ = json.Unmarshal(data, &files)
		for _, f := range files {
			dataSet[f] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(dataSet) > 0 {
		names := make([]string, 0, len(dataSet))
		for f := range dataSet {
			names = append(names, f)
		}
		sort.Strings(names)
		rows, err := tx.Query(ctx, `SELECT dest_file, content FROM openpicket.hub_data WHERE dest_file = ANY($1) ORDER BY dest_file`, names)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var f hubitem.File
			if err := rows.Scan(&f.Path, &f.Content); err != nil {
				rows.Close()
				return nil, err
			}
			b.Data = append(b.Data, f)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return b, b.Check()
}

// Compatibility of a scenario with the parsers enabled.
type Compatibility struct {
	Status string
	// Missing log types: read by the scenario, set by no enabled parser.
	Missing []string
}

// Produced returns the log types the enabled parsers set.
func (s *Store) Produced(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT i.content FROM openpicket.hub_items i LEFT JOIN openpicket.hub_item_state st ON st.type = i.type AND st.name = i.name
		WHERE i.type = 'parsers' AND COALESCE(st.state, 'enabled') <> 'disabled'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if doc, err := hubitem.ParseDoc(hubitem.Parsers, b); err == nil {
			out = append(out, doc.Produces...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), rows.Err()
}

// Compatibilities judges every stored scenario.
func (s *Store) Compatibilities(ctx context.Context) (map[string]Compatibility, error) {
	produced, err := s.Produced(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT name, content FROM openpicket.hub_items WHERE type = 'scenarios'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Compatibility{}
	for rows.Next() {
		var (
			name string
			b    []byte
		)
		if err := rows.Scan(&name, &b); err != nil {
			return nil, err
		}
		var required []string
		if doc, err := hubitem.ParseDoc(hubitem.Scenarios, b); err == nil {
			required = doc.LogTypes
		}
		st, missing := hubitem.Compat(required, produced)
		out[name] = Compatibility{Status: st, Missing: missing}
	}
	return out, rows.Err()
}

// Meta is the rollout state.
type Meta struct {
	Revision       int64
	GoodRevision   int64
	FailedRevision int64
	FailedError    string
}

// LPState is what a log processor runs.
type LPState struct {
	Endpoint string
	Revision int64
	Running  bool
	Error    string
	SeenAt   time.Time
}

// Status returns the rollout state and the log processors.
func (s *Store) Status(ctx context.Context) (Meta, []LPState, error) {
	var m Meta
	if err := s.db.QueryRow(ctx, `SELECT revision, good_revision, failed_revision, failed_error FROM openpicket.hub_meta WHERE id = 1`).
		Scan(&m.Revision, &m.GoodRevision, &m.FailedRevision, &m.FailedError); err != nil {
		return m, nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT endpoint, revision, running, error, seen_at FROM openpicket.hub_lp_state ORDER BY endpoint`)
	if err != nil {
		return m, nil, err
	}
	defer rows.Close()
	var out []LPState
	for rows.Next() {
		var l LPState
		if err := rows.Scan(&l.Endpoint, &l.Revision, &l.Running, &l.Error, &l.SeenAt); err != nil {
			return m, nil, err
		}
		out = append(out, l)
	}
	return m, out, rows.Err()
}

// encodeBundle is the wire and storage form of a bundle (gzip JSON).
func encodeBundle(b *hubitem.Bundle) ([]byte, error) {
	var buf bytes.Buffer
	zw := newGzip(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
