// Package pgtest gives tests a fresh PostgreSQL database. Tests are skipped
// unless OPENPICKET_TEST_PG points at a server where the user may create
// databases (scripts/test-pg.sh starts one).
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Env is the variable holding the admin connection string.
const Env = "OPENPICKET_TEST_PG"

// DSN creates an empty database and returns its connection string. The
// database is dropped when the test ends.
func DSN(t testing.TB) string {
	t.Helper()
	admin := os.Getenv(Env)
	if admin == "" {
		t.Skip(Env + " not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("pgtest: connect: %v", err)
	}
	defer conn.Close(ctx)
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "test_" + hex.EncodeToString(b)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("pgtest: create database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if c, err := pgx.Connect(ctx, admin); err == nil {
			_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(ctx)
		}
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("pgtest: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// Pool opens a pool on a fresh database.
func Pool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), DSN(t))
	if err != nil {
		t.Fatalf("pgtest: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
