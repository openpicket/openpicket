package pipeline

import (
	"context"
	"testing"

	"github.com/openpicket/openpicket/internal/pgtest"
	"github.com/openpicket/openpicket/internal/schema"
)

// A replica taking over a node's session sees what the previous replica
// flushed.
func TestWatermarksHandOver(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	if err := schema.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	a := NewWatermarks(pool, nil)
	a.Set("n1", "b1", "crowdsec", 7)
	a.Set("n1", "b1", "crowdsec", 5) // never goes back
	a.Set("n1", "b1", "loki", 6)
	a.Flush(ctx)
	b := NewWatermarks(pool, nil)
	if got := b.Get(ctx, "n1", "b1", "crowdsec"); got != 7 {
		t.Fatalf("crowdsec = %d", got)
	}
	if got := b.Get(ctx, "n1", "b1", "loki"); got != 6 {
		t.Fatalf("loki = %d", got)
	}
	if got := b.Get(ctx, "n1", "b2", "loki"); got != 0 {
		t.Fatalf("other boot = %d", got)
	}
	// A late flush with a lower value does not lower the stored one.
	c := NewWatermarks(pool, nil)
	c.Set("n1", "b1", "crowdsec", 3)
	c.Flush(ctx)
	if got := NewWatermarks(pool, nil).Get(ctx, "n1", "b1", "crowdsec"); got != 7 {
		t.Fatalf("after lower flush = %d", got)
	}
}
