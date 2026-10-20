package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openpicket/openpicket/manager/geo"
	"github.com/openpicket/openpicket/pkg/portpolicy"
)

// PolicyRecord is a stored policy with its metadata.
type PolicyRecord struct {
	Policy    portpolicy.Policy
	Position  int
	UpdatedAt time.Time
	UpdatedBy string
}

// ListRecord is a stored address list with its metadata.
type ListRecord struct {
	List        portpolicy.List
	Description string
	UpdatedAt   time.Time
	UpdatedBy   string
	// UsedBy lists the policies referencing the list.
	UsedBy []string
}

// Change is a policy_history entry.
type Change struct {
	PolicyID  string
	Version   uint64
	Action    string
	Spec      json.RawMessage
	ChangedAt time.Time
	ChangedBy string
}

// PolicyRecords returns the policies in evaluation order with metadata.
func (s *Service) PolicyRecords(ctx context.Context) ([]PolicyRecord, uint64, error) {
	var (
		out     []PolicyRecord
		version int64
	)
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT version FROM openpicket.policy_meta WHERE id = 1`).Scan(&version); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT spec, position, updated_at, updated_by FROM openpicket.port_policies ORDER BY position, id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				raw []byte
				r   PolicyRecord
			)
			if err := rows.Scan(&raw, &r.Position, &r.UpdatedAt, &r.UpdatedBy); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &r.Policy); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, uint64(version), err
}

// ListRecords returns the address lists with metadata.
func (s *Service) ListRecords(ctx context.Context) ([]ListRecord, error) {
	policies, _, err := s.PolicyRecords(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT spec, description, updated_at, updated_by FROM openpicket.ip_lists ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ListRecord
	for rows.Next() {
		var (
			raw []byte
			r   ListRecord
		)
		if err := rows.Scan(&raw, &r.Description, &r.UpdatedAt, &r.UpdatedBy); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &r.List); err != nil {
			return nil, err
		}
		for _, p := range policies {
			for _, rule := range p.Policy.Rules {
				if slices.Contains(rule.Source.Lists, r.List.Name) {
					r.UsedBy = append(r.UsedBy, p.Policy.ID)
					break
				}
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Reorder sets the evaluation order; ids must name every policy once.
func (s *Service) Reorder(ctx context.Context, ids []string, by string) (uint64, error) {
	var version uint64
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var current []string
		rows, err := tx.Query(ctx, `SELECT id FROM openpicket.port_policies ORDER BY id FOR UPDATE`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			current = append(current, id)
		}
		rows.Close()
		sorted := slices.Clone(ids)
		slices.Sort(sorted)
		if !slices.Equal(sorted, current) {
			return fmt.Errorf("%w: the order must list every policy exactly once", ErrInvalid)
		}
		for i, id := range ids {
			if _, err := tx.Exec(ctx, `UPDATE openpicket.port_policies SET position = $2 WHERE id = $1`, id, i); err != nil {
				return err
			}
		}
		if version, err = geo.BumpPolicyVersion(ctx, tx); err != nil {
			return err
		}
		return record(ctx, tx, "*", "reorder", ids, version, by)
	})
	return version, err
}

// History returns the newest changes, of one policy ("list:<name>" for a
// list) or of all.
func (s *Service) History(ctx context.Context, policyID string, limit int) ([]Change, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Query(ctx, `SELECT policy_id, version, action, spec, changed_at, changed_by FROM openpicket.policy_history
		WHERE $1 = '' OR policy_id = $1 ORDER BY id DESC LIMIT $2`, policyID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Change
	for rows.Next() {
		var (
			c Change
			v int64
		)
		if err := rows.Scan(&c.PolicyID, &v, &c.Action, &c.Spec, &c.ChangedAt, &c.ChangedBy); err != nil {
			return nil, err
		}
		c.Version = uint64(v)
		out = append(out, c)
	}
	return out, rows.Err()
}
