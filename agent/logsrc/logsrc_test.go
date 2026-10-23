package logsrc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// take polls until n lines came (or fails), committing each batch.
func take(t *testing.T, c *Collector, n int, commit bool) []string {
	t.Helper()
	var out []string
	deadline := time.Now().Add(5 * time.Second)
	for first := true; first || len(out) < n; first = false {
		if time.Now().After(deadline) {
			t.Fatalf("got %d lines, want %d: %q", len(out), n, out)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		bs, _ := c.Next(ctx, 1000, 1<<20)
		cancel()
		for _, b := range bs {
			for _, r := range b.Records {
				out = append(out, b.Program+":"+string(r.Line))
			}
			if commit {
				c.Commit(b)
			}
		}
	}
	return out
}

func newCollector(t *testing.T, dir, state string, sources ...Source) *Collector {
	t.Helper()
	c, err := New(Config{Sources: sources, StateFile: state, Poll: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestTailRotateTruncate(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(t.TempDir(), "pos.json")
	access := filepath.Join(dir, "access.log")
	appendFile(t, access, "old 1\nold 2\n")
	c := newCollector(t, dir, state, Source{Program: "nginx", Path: filepath.Join(dir, "*.log")})
	// First scan: the backlog is skipped.
	take(t, c, 0, true)
	appendFile(t, access, "new 1\npartial")
	if got := take(t, c, 1, true); got[0] != "nginx:new 1" {
		t.Fatalf("got %q", got)
	}
	// The partial line completes; a file appearing later is read from
	// its start.
	appendFile(t, access, " line\n")
	appendFile(t, filepath.Join(dir, "other.log"), "o 1\n")
	got := take(t, c, 2, true)
	if !contains(got, "nginx:partial line") || !contains(got, "nginx:o 1") {
		t.Fatalf("got %q", got)
	}
	// Rotation (rename + create): the end of the old file, then the new.
	appendFile(t, access, "before rotate\n")
	if err := os.Rename(access, filepath.Join(dir, "access.log.1")); err != nil {
		t.Fatal(err)
	}
	appendFile(t, filepath.Join(dir, "access.log.1"), "late write\n")
	appendFile(t, access, "after rotate\n")
	got = take(t, c, 3, true)
	if !contains(got, "nginx:before rotate") || !contains(got, "nginx:late write") || !contains(got, "nginx:after rotate") {
		t.Fatalf("rotation: %q", got)
	}
	// copytruncate: read from the start again.
	if err := os.Truncate(access, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, access, "t1\n")
	if got := take(t, c, 1, true); got[0] != "nginx:t1" {
		t.Fatalf("truncate: %q", got)
	}
	// An overlong line is cut once, the rest dropped.
	appendFile(t, access, strings.Repeat("x", MaxLine+100)+"\nshort\n")
	got = take(t, c, 2, true)
	if len(got[0]) != len("nginx:")+MaxLine || got[1] != "nginx:short" || c.Status()[0].Truncated != 1 {
		t.Fatalf("long line: %d %q %+v", len(got[0]), got[1], c.Status())
	}
}

// TestResendUnacknowledged: lines not committed are read again after a
// restart; committed ones are not.
func TestResendUnacknowledged(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(t.TempDir(), "pos.json")
	path := filepath.Join(dir, "auth.log")
	appendFile(t, path, "")
	c := newCollector(t, dir, state, Source{Program: "syslog", Path: path})
	take(t, c, 0, true) // first scan: empty file
	appendFile(t, path, "a\nb\n")
	take(t, c, 2, true)
	appendFile(t, path, "c\nd\n")
	take(t, c, 2, false) // read, never acknowledged
	c.Close()

	c2 := newCollector(t, dir, state, Source{Program: "syslog", Path: path})
	if got := take(t, c2, 2, true); got[0] != "syslog:c" || got[1] != "syslog:d" {
		t.Fatalf("after restart: %q", got)
	}
	st := c2.Status()
	if len(st) != 1 || st[0].Files != 1 || st[0].Program != "syslog" {
		t.Fatalf("status = %+v", st)
	}
}

func TestInvalidSource(t *testing.T) {
	if _, err := New(Config{Sources: []Source{{Program: "!!", Path: "/x"}}}); err == nil {
		t.Fatal("invalid program accepted")
	}
	if _, err := New(Config{Sources: []Source{{Program: "x", Path: "/a/[b"}}}); err == nil {
		t.Fatal("bad glob accepted")
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
