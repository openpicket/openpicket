// Package allowlist is the central allowlist (docs/ARCHITECTURE.md §4.7):
// networks that CrowdSec decisions never block at the edge, whatever made
// them (scenarios, cscli, MISP, the API). The relay leaves the decisions
// overlapping an active entry out of the edge view, and the API and MISP
// refuse to add them. An entry and a decision overlap when either contains
// the other: a range that covers an allowlisted address is left out whole,
// as the agents do with their local allowlist.
//
// Unlike an agent's allowlist, the central one only keeps decisions off
// the edge: port policies still apply to its networks.
package allowlist

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openpicket/openpicket/manager/db"
)

var (
	// ErrInvalid wraps validation errors.
	ErrInvalid = errors.New("allowlist: invalid")
	// ErrNotFound is returned when deleting a missing entry.
	ErrNotFound = errors.New("allowlist: not found")
)

// Networks shorter than these need Wide: an entry that large unblocks a
// large part of the Internet.
const (
	minBits4 = 8
	minBits6 = 32
)

// Entry is one allowlisted network.
type Entry struct {
	Network     netip.Prefix
	Description string
	// ExpiresAt is zero for an entry that never expires.
	ExpiresAt time.Time
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
	// Excluded counts the active edge-eligible LAPI decisions the entry
	// keeps off the edge (List only).
	Excluded int64
}

// Active reports whether the entry applies at t.
func (e Entry) Active(t time.Time) bool { return e.ExpiresAt.IsZero() || e.ExpiresAt.After(t) }

// ParseNetwork parses an address or a CIDR into its canonical prefix (an
// address is a /32 or /128; IPv4-mapped IPv6 becomes IPv4).
func ParseNetwork(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%w: %q is not a network", ErrInvalid, s)
		}
		if p.Addr().Is4In6() {
			bits := p.Bits() - 96
			if bits < 0 {
				return netip.Prefix{}, fmt.Errorf("%w: %q is not a network", ErrInvalid, s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), bits)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%w: %q is not an address", ErrInvalid, s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Validate checks a network about to be stored. A network shorter than /8
// (IPv4) or /32 (IPv6) needs wide; the whole address space is refused.
func Validate(p netip.Prefix, wide bool) error {
	if !p.IsValid() {
		return fmt.Errorf("%w: missing network", ErrInvalid)
	}
	if p.Bits() == 0 {
		return fmt.Errorf("%w: %s covers every address", ErrInvalid, p)
	}
	least := minBits6
	if p.Addr().Is4() {
		least = minBits4
	}
	if p.Bits() < least && !wide {
		return fmt.Errorf("%w: %s is wider than /%d; confirm it as a wide network", ErrInvalid, p, least)
	}
	return nil
}

// Covered returns a SQL condition, true when an active entry overlaps the
// inet expression value at the timestamptz expression at.
func Covered(value, at string) string {
	return `EXISTS (SELECT 1 FROM openpicket.allowlist a WHERE a.network && (` + value + `)
		AND (a.expires_at IS NULL OR a.expires_at > ` + at + `))`
}

// Store reads and changes the allowlist.
type Store struct {
	db  *pgxpool.Pool
	now func() time.Time
}

// New creates a store; now defaults to time.Now.
func New(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{db: pool, now: now}
}

// List returns every entry (expired ones included), with the decisions
// each active one keeps off the edge.
func (s *Store) List(ctx context.Context) ([]Entry, error) {
	now := s.now()
	rows, err := s.db.Query(ctx, `SELECT network, description, expires_at, created_at, created_by, updated_at, updated_by
		FROM openpicket.allowlist ORDER BY network`)
	if err != nil {
		return nil, err
	}
	var out []Entry
	idx := map[netip.Prefix]int{}
	for rows.Next() {
		var (
			e   Entry
			exp *time.Time
		)
		if err := rows.Scan(&e.Network, &e.Description, &exp, &e.CreatedAt, &e.CreatedBy, &e.UpdatedAt, &e.UpdatedBy); err != nil {
			rows.Close()
			return nil, err
		}
		if exp != nil {
			e.ExpiresAt = *exp
		}
		idx[e.Network] = len(out)
		out = append(out, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	// Edge-eligible values are canonical addresses or ranges (relay.Normalize).
	rows, err = s.db.Query(ctx, `SELECT a.network, count(DISTINCT d.value) FROM openpicket.lapi_decisions d
		JOIN openpicket.allowlist a ON a.network && (CASE WHEN d.eligible THEN d.value::inet END)
		WHERE d.eligible AND d.until > $1 AND (a.expires_at IS NULL OR a.expires_at > $1)
		GROUP BY a.network`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			p netip.Prefix
			n int64
		)
		if err := rows.Scan(&p, &n); err != nil {
			return nil, err
		}
		if i, ok := idx[p]; ok {
			out[i].Excluded = n
		}
	}
	return out, rows.Err()
}

// Put creates or replaces the entry of e.Network. A replaced entry keeps
// its creation time and author.
func (s *Store) Put(ctx context.Context, e Entry, wide bool, by string) error {
	if err := Validate(e.Network, wide); err != nil {
		return err
	}
	if len(e.Description) > 512 {
		return fmt.Errorf("%w: description longer than 512 characters", ErrInvalid)
	}
	now := s.now()
	var exp *time.Time
	if !e.ExpiresAt.IsZero() {
		if !e.ExpiresAt.After(now) {
			return fmt.Errorf("%w: the expiry is in the past", ErrInvalid)
		}
		exp = &e.ExpiresAt
	}
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO openpicket.allowlist (network, description, expires_at, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $4, $5)
			ON CONFLICT (network) DO UPDATE SET description = excluded.description, expires_at = excluded.expires_at,
				updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
			e.Network, e.Description, exp, now, by); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, db.ChannelAllowlist, e.Network.String())
		return err
	})
}

// Delete removes the entry of network.
func (s *Store) Delete(ctx context.Context, network netip.Prefix) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM openpicket.allowlist WHERE network = $1`, network)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s", ErrNotFound, network)
		}
		_, err = tx.Exec(ctx, `SELECT pg_notify($1, $2)`, db.ChannelAllowlist, network.String())
		return err
	})
}

// Active returns the entries in force now.
func (s *Store) Active(ctx context.Context) (Set, error) {
	rows, err := s.db.Query(ctx, `SELECT network FROM openpicket.allowlist WHERE expires_at IS NULL OR expires_at > $1`, s.now())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[netip.Prefix])
}

// Set is a list of allowlisted networks.
type Set []netip.Prefix

// Covering returns the networks overlapping value (an address or a CIDR);
// none for a value that is neither.
func (s Set) Covering(value string) []netip.Prefix {
	p, err := ParseNetwork(value)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, n := range s {
		if n.Overlaps(p) {
			out = append(out, n)
		}
	}
	return out
}

// Covering returns the active entries overlapping value.
func (s *Store) Covering(ctx context.Context, value string) ([]netip.Prefix, error) {
	set, err := s.Active(ctx)
	if err != nil {
		return nil, err
	}
	return set.Covering(value), nil
}
