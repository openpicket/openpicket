package schema

import (
	"context"
	"sync"
	"testing"

	"github.com/openpicket/openpicket/internal/pgtest"
)

func TestMigrateConcurrentAndIdempotent(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = Migrate(ctx, pool)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var v int
	if err := pool.QueryRow(ctx, "SELECT max(version) FROM public.openpicket_schema_migrations").Scan(&v); err != nil || v != Latest() {
		t.Fatalf("version = %d, %v", v, err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
}
