// Package dbroles restricts the gateway's database account (docs/
// ARCHITECTURE.md §5.10): the gateway faces the agents (and syslog senders)
// and must not reach what the UI and API manage (node registration, port
// policies, CrowdSec content, audit, notifications, MISP).
package dbroles

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Gateway grants: what channel B, the log pipeline and the decision and
// policy streams read and write.
var (
	gatewayRead = []string{
		"nodes", "node_sessions", "edge_decisions", "edge_meta", "port_policies", "ip_lists", "policy_meta",
		"policy_compiled", "geo_databases", "settings", "sink_watermarks", "log_programs", "gateway_info", "node_decision_state", "node_policy_state",
		"syslog_devices", "syslog_sources",
	}
	gatewayWrite = []string{
		"node_sessions", "node_decision_state", "node_policy_state", "sink_watermarks", "log_programs", "gateway_info", "syslog_sources",
	}
	// Columns of other tables a gateway updates.
	gatewayColumns = map[string][]string{"nodes": {"dp_last_seen_at"}}
	// probe is a table a restricted gateway account cannot write.
	probe = "hub_items"
)

var roleRe = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// EnsureGateway creates (or updates the password of) the gateway role and
// grants it what a gateway needs, nothing more. The caller's account owns
// the schema; creating a role needs CREATEROLE: without it an existing
// role is still granted. Run it after the migrations, on every start (new
// tables need their grants).
func EnsureGateway(ctx context.Context, pool *pgxpool.Pool, role, password string, log *slog.Logger) error {
	if !roleRe.MatchString(role) {
		return fmt.Errorf("dbroles: invalid role name %q", role)
	}
	ident := pgx.Identifier{role}.Sanitize()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
		return err
	}
	if password != "" {
		verb := "CREATE"
		if exists {
			verb = "ALTER"
		}
		// The password is a literal in DDL; quote it as one.
		lit := "'" + strings.ReplaceAll(password, "'", "''") + "'"
		if _, err := pool.Exec(ctx, fmt.Sprintf("%s ROLE %s LOGIN PASSWORD %s", verb, ident, lit)); err != nil {
			var pe *pgconn.PgError
			if !exists || !errors.As(err, &pe) {
				return fmt.Errorf("dbroles: %s role %s: %w", strings.ToLower(verb), role, err)
			}
			log.Warn("cannot set the gateway role's password; keeping it", "role", role, "err", err)
		}
		exists = true
	}
	if !exists {
		return fmt.Errorf("dbroles: role %s does not exist (create it, or set its password so the manager creates it)", role)
	}
	stmts := []string{fmt.Sprintf("GRANT USAGE ON SCHEMA openpicket TO %s", ident),
		fmt.Sprintf("GRANT SELECT ON public.openpicket_schema_migrations TO %s", ident)}
	for _, t := range gatewayRead {
		stmts = append(stmts, fmt.Sprintf("GRANT SELECT ON openpicket.%s TO %s", t, ident))
	}
	for _, t := range gatewayWrite {
		stmts = append(stmts, fmt.Sprintf("GRANT INSERT, UPDATE, DELETE ON openpicket.%s TO %s", t, ident))
	}
	for t, cols := range gatewayColumns {
		stmts = append(stmts, fmt.Sprintf("GRANT UPDATE (%s) ON openpicket.%s TO %s", strings.Join(cols, ", "), t, ident))
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return fmt.Errorf("dbroles: %s: %w", s, err)
			}
		}
		return nil
	})
}

// Restricted reports whether the connected account is limited to a
// gateway's needs (it cannot write the CrowdSec content).
func Restricted(ctx context.Context, pool *pgxpool.Pool) (bool, string, error) {
	var user string
	var can bool
	err := pool.QueryRow(ctx, `SELECT current_user, has_table_privilege('openpicket.`+probe+`', 'INSERT')`).Scan(&user, &can)
	return !can, user, err
}
