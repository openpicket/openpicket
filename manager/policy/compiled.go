package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/portpolicy"
)

// stored is a policy_compiled row.
type stored struct {
	version   uint64
	compiled  []byte
	lastError string
}

// marshalCompiled stores a compiled policy as a bundle holding it and its
// sets.
func marshalCompiled(c *portpolicy.Compiled) []byte {
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(&dataplanev1.PolicyBundle{Policies: []*dataplanev1.PortPolicy{c.Policy}, Sets: c.Sets})
	return b
}

func unmarshalCompiled(raw []byte) (*portpolicy.Compiled, error) {
	b := &dataplanev1.PolicyBundle{}
	if err := proto.Unmarshal(raw, b); err != nil || len(b.Policies) != 1 {
		return nil, errors.New("policy: unreadable compiled policy")
	}
	return &portpolicy.Compiled{Policy: b.Policies[0], Sets: b.Sets}, nil
}

func loadStored(ctx context.Context, tx pgx.Tx) (map[string]stored, error) {
	rows, err := tx.Query(ctx, `SELECT policy_id, version, compiled, last_error FROM openpicket.policy_compiled`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]stored{}
	for rows.Next() {
		var (
			id string
			v  int64
			st stored
		)
		if err := rows.Scan(&id, &v, &st.compiled, &st.lastError); err != nil {
			return nil, err
		}
		st.version = uint64(v)
		out[id] = st
	}
	return out, rows.Err()
}

// compileAll compiles every policy of a snapshot. A policy that does not
// compile keeps its last good version (from PostgreSQL). Results are
// written back, so every replica, and a replica whose GeoIP failed to
// load, has the same last good versions; failures are only recorded when
// this replica's GeoIP databases are loaded (otherwise the failure is
// local).
func (s *Service) compileAll(ctx context.Context, snap *snapshot, prev map[string]stored) {
	snap.results = map[string]portpolicy.Result{}
	geoLoaded := s.geo.Loaded()
	for _, p := range snap.policies {
		c, err := portpolicy.CompilePolicy(p, snap.lists, s.geo.Current())
		st := prev[p.ID]
		if err == nil {
			snap.results[p.ID] = portpolicy.Result{Compiled: c}
			raw := marshalCompiled(c)
			if !bytes.Equal(raw, st.compiled) || st.lastError != "" {
				s.storeCompiled(ctx, snap.version, p.ID, raw)
			}
			continue
		}
		r := portpolicy.Result{Err: err.Error()}
		if len(st.compiled) > 0 {
			if lg, uerr := unmarshalCompiled(st.compiled); uerr == nil {
				r.Compiled = lg
			}
		}
		if !geoLoaded {
			r.Err = "GeoIP databases not loaded on this replica: " + r.Err
		} else if st.lastError != r.Err {
			s.storeError(ctx, snap.version, p.ID, r.Err)
		}
		snap.results[p.ID] = r
		if r.Compiled != nil {
			s.log.Warn("policy does not compile; its last good version stays on the nodes", "policy", p.ID, "err", r.Err)
		} else {
			s.log.Warn("policy does not compile and never did; it is not deployed", "policy", p.ID, "err", r.Err)
		}
	}
}

func (s *Service) storeCompiled(ctx context.Context, version uint64, id string, raw []byte) {
	if _, err := s.db.Exec(ctx, `INSERT INTO openpicket.policy_compiled (policy_id, version, compiled, compiled_at, last_error, error_at)
		VALUES ($1,$2,$3,now(),'',NULL)
		ON CONFLICT (policy_id) DO UPDATE SET version=excluded.version, compiled=excluded.compiled, compiled_at=excluded.compiled_at,
			last_error='', error_at=NULL
		WHERE policy_compiled.version <= excluded.version`, id, int64(version), raw); err != nil {
		s.log.Warn("store compiled policy", "policy", id, "err", err)
	}
}

func (s *Service) storeError(ctx context.Context, version uint64, id, msg string) {
	if _, err := s.db.Exec(ctx, `INSERT INTO openpicket.policy_compiled (policy_id, version, last_error, error_at)
		VALUES ($1,$2,$3,now())
		ON CONFLICT (policy_id) DO UPDATE SET version=excluded.version, last_error=excluded.last_error,
			error_at=CASE WHEN policy_compiled.last_error = '' THEN now() ELSE policy_compiled.error_at END
		WHERE policy_compiled.version <= excluded.version`, id, int64(version), msg); err != nil {
		s.log.Warn("store policy compile error", "policy", id, "err", err)
	}
}

// CompileStatus is the compilation state of a policy.
type CompileStatus struct {
	// Error is why the current version does not compile ("" when it does).
	Error string
	// ErrorSince is when it stopped compiling.
	ErrorSince time.Time
	// Stale: a last good version is deployed instead.
	Stale bool
}

// CompileStatuses returns the state of every policy that ever compiled
// or failed.
func (s *Service) CompileStatuses(ctx context.Context) (map[string]CompileStatus, error) {
	rows, err := s.db.Query(ctx, `SELECT policy_id, last_error, error_at, compiled IS NOT NULL FROM openpicket.policy_compiled`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]CompileStatus{}
	for rows.Next() {
		var (
			id       string
			st       CompileStatus
			since    *time.Time
			compiled bool
		)
		if err := rows.Scan(&id, &st.Error, &since, &compiled); err != nil {
			return nil, err
		}
		if since != nil {
			st.ErrorSince = *since
		}
		st.Stale = st.Error != "" && compiled
		out[id] = st
	}
	return out, rows.Err()
}

// GeoDependents returns the enabled policies that need a GeoIP database
// kind ("country" or "asn"): deleting it would freeze them at their last
// good version.
func (s *Service) GeoDependents(ctx context.Context, kind string) ([]string, error) {
	snap, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range snap.policies {
		if !p.Enabled {
			continue
		}
		uses := false
		for _, r := range p.Rules {
			switch kind {
			case "country":
				uses = uses || len(r.Source.Countries) > 0
			case "asn":
				uses = uses || len(r.Source.ASNs) > 0
				for _, l := range r.Source.Lists {
					uses = uses || len(snap.lists[l].ASNs) > 0
				}
			default:
				return nil, fmt.Errorf("%w: unknown database kind %q", ErrInvalid, kind)
			}
		}
		if uses && !slices.Contains(out, p.ID) {
			out = append(out, p.ID)
		}
	}
	return out, nil
}
