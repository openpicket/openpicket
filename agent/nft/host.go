// Package nft renders and applies the nftables tables OpenPicket owns on a
// node. Everything here is generated from fixed templates and validated
// values: the manager never sends nft syntax (docs/ARCHITECTURE.md §12).
package nft

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jc-lab/suricontroller/agent/platform"
)

// Host runs nft and writes host files (through chroot and the /host mount in
// the docker profile).
type Host struct {
	Exec platform.Exec
	FS   platform.HostFS
}

// Apply runs an nft script in one transaction.
func (h *Host) Apply(ctx context.Context, script string) error {
	if _, err := h.Exec.Run(ctx, "nft", []string{"-f", "-"}, []byte(script)); err != nil {
		return fmt.Errorf("nft: %w", err)
	}
	return nil
}

// Check validates an nft script without applying it (nft -c).
func (h *Host) Check(ctx context.Context, script string) error {
	if _, err := h.Exec.Run(ctx, "nft", []string{"-c", "-f", "-"}, []byte(script)); err != nil {
		return fmt.Errorf("nft: %w", err)
	}
	return nil
}

// Output runs nft with arguments and returns its output.
func (h *Host) Output(ctx context.Context, args ...string) ([]byte, error) {
	return h.Exec.Run(ctx, "nft", args, nil)
}

// WriteFile writes a host file atomically. It reports whether the content
// changed.
func (h *Host) WriteFile(path string, data []byte) (bool, error) {
	p := h.FS.Path(path)
	if old, err := os.ReadFile(p); err == nil && string(old) == string(data) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false, err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, p)
}

// RemoveFile deletes a host file; it reports whether it existed.
func (h *Host) RemoveFile(path string) (bool, error) {
	err := os.Remove(h.FS.Path(path))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// quoteSet renders names as an nft anonymous set of strings.
func quoteSet(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = `"` + n + `"`
	}
	return "{ " + strings.Join(q, ", ") + " }"
}

// replaceTable returns a script that recreates table atomically and
// idempotently (it works whether or not the table exists).
func replaceTable(family, name, body string) string {
	return fmt.Sprintf("table %[1]s %[2]s\ndelete table %[1]s %[2]s\ntable %[1]s %[2]s {\n%[3]s}\n", family, name, body)
}

// deleteTable returns a script that removes a table if present.
func deleteTable(family, name string) string {
	return fmt.Sprintf("table %[1]s %[2]s\ndelete table %[1]s %[2]s\n", family, name)
}
