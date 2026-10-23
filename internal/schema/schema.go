// Package schema owns the PostgreSQL schema of OpenPicket: the openpicket
// schema (node registry, data plane, UI state) and the suricontroller
// schema (store of openpicket-suricontroller). Every binary that uses the
// database calls Migrate at startup; concurrent callers serialize on an
// advisory lock.
package schema

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// lockID is the advisory lock key serializing migrations.
const lockID = 0x6f70_6963_6b65_7401 // "opicket" + 1

type migration struct {
	version int
	name    string
	sql     string
}

func load() ([]migration, error) {
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil {
			return nil, fmt.Errorf("schema: bad migration name %q", e.Name())
		}
		b, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// Latest returns the newest schema version this build knows.
func Latest() int {
	ms, _ := load()
	if len(ms) == 0 {
		return 0
	}
	return ms[len(ms)-1].version
}

// Migrate applies pending migrations, each in its own transaction.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	ms, err := load()
	if err != nil {
		return err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(lockID)); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(lockID)) }()
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS public.openpicket_schema_migrations (
		version int PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	var current int
	if err := conn.QueryRow(ctx, "SELECT COALESCE(max(version), 0) FROM public.openpicket_schema_migrations").Scan(&current); err != nil {
		return err
	}
	if latest := Latest(); current > latest {
		return fmt.Errorf("schema: database is at version %d, newer than this build (%d)", current, latest)
	}
	for _, m := range ms {
		if m.version <= current {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO public.openpicket_schema_migrations (version, name) VALUES ($1, $2)", m.version, m.name)
			return err
		})
		if err != nil {
			return fmt.Errorf("schema: apply %s: %w", m.name, err)
		}
	}
	// The gateways read the version through this function: their account
	// has no access to the migrations table (it runs as its owner).
	if _, err := conn.Exec(ctx, `CREATE OR REPLACE FUNCTION openpicket.schema_version() RETURNS int
		LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
		AS 'SELECT COALESCE(max(version), 0) FROM public.openpicket_schema_migrations'`); err != nil {
		return fmt.Errorf("schema: version function: %w", err)
	}
	return nil
}

// Wait blocks until the database has this binary's schema (a gateway,
// whose account cannot migrate, waits for the API replicas). A newer
// schema is fine: migrations only add.
func Wait(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	want := Latest()
	for {
		var v int
		err := pool.QueryRow(ctx, "SELECT openpicket.schema_version()").Scan(&v)
		if err == nil && v >= want {
			return nil
		}
		log.Info("waiting for the database schema (migrated by the API replicas)", "have", v, "want", want, "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}
