// Package policy applies port policy bundles on the node
// (docs/ARCHITECTURE.md §4.4). A bundle is data only: it is validated
// against the node's contract (portpolicy.ValidateBundle and the element
// cap) and rendered from a fixed template; a bundle that fails is refused
// as a whole and the previous one stays. The last applied bundle is saved
// and re-applied at boot, before the manager is reachable.
package policy

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/openpicket/openpicket/agent/dataplane"
	"github.com/openpicket/openpicket/agent/nft"
	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/portpolicy"
)

// Config configures a Sink.
type Config struct {
	Host        *nft.Host
	Table       nft.PolicyConfig
	Allow       func() []netip.Prefix
	MaxElements int
	StateFile   string
	Logger      *slog.Logger
}

// Sink implements dataplane.PolicySink.
type Sink struct {
	cfg Config
	log *slog.Logger

	mu      sync.Mutex
	bundle  *dataplanev1.PolicyBundle
	allow   []netip.Prefix
	lastErr string
}

var _ dataplane.PolicySink = (*Sink)(nil)

// New creates a sink; call Restore, then Run.
func New(cfg Config) *Sink {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Allow == nil {
		cfg.Allow = func() []netip.Prefix { return nil }
	}
	return &Sink{cfg: cfg, log: cfg.Logger.With("component", "policy"), bundle: &dataplanev1.PolicyBundle{}}
}

// Version implements dataplane.PolicySink.
func (s *Sink) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bundle.Version
}

// Apply implements dataplane.PolicySink.
func (s *Sink) Apply(ctx context.Context, b *dataplanev1.PolicyBundle) error {
	if _, err := portpolicy.ValidateBundle(b, portpolicy.Limits{MaxElements: s.cfg.MaxElements}); err != nil {
		s.setErr(err)
		return fmt.Errorf("bundle refused: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.apply(ctx, b); err != nil {
		return err
	}
	s.bundle = b
	if err := s.save(b); err != nil {
		s.log.Warn("save policy bundle", "err", err)
	}
	s.log.Info("port policies applied", "version", b.Version, "policies", len(b.Policies))
	return nil
}

// apply renders and installs b. Callers hold mu.
func (s *Sink) apply(ctx context.Context, b *dataplanev1.PolicyBundle) error {
	allow := s.cfg.Allow()
	if err := s.cfg.Host.Apply(ctx, s.cfg.Table.PolicyScript(b, allow)); err != nil {
		s.lastErr = err.Error()
		return err
	}
	s.allow, s.lastErr = allow, ""
	return nil
}

func (s *Sink) setErr(err error) {
	s.mu.Lock()
	s.lastErr = err.Error()
	s.mu.Unlock()
}

func (s *Sink) save(b *dataplanev1.PolicyBundle) error {
	if s.cfg.StateFile == "" {
		return nil
	}
	raw, err := proto.Marshal(b)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.cfg.StateFile), 0o750); err != nil {
		return err
	}
	tmp := s.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.cfg.StateFile)
}

// Restore re-applies the saved bundle (validated again).
func (s *Sink) Restore(ctx context.Context) error {
	raw, err := os.ReadFile(s.cfg.StateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	b := &dataplanev1.PolicyBundle{}
	if err := proto.Unmarshal(raw, b); err != nil {
		return fmt.Errorf("saved policy bundle: %w", err)
	}
	if _, err := portpolicy.ValidateBundle(b, portpolicy.Limits{MaxElements: s.cfg.MaxElements}); err != nil {
		return fmt.Errorf("saved policy bundle refused: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.apply(ctx, b); err != nil {
		return err
	}
	s.bundle = b
	s.log.Info("port policies restored", "version", b.Version, "policies", len(b.Policies))
	return nil
}

// Ensure puts the table back if it disappeared or the allowlist changed.
func (s *Sink) Ensure(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bundle.Policies) == 0 {
		return nil
	}
	if s.cfg.Host.PolicyTablePresent(ctx) && slices.Equal(s.allow, s.cfg.Allow()) {
		return nil
	}
	return s.apply(ctx, s.bundle)
}

// Run keeps the table in place until ctx ends.
func (s *Sink) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.Ensure(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("ensure policy table", "err", err)
		}
	}
}

// Status returns the policy state with per-rule packet counters.
func (s *Sink) Status(ctx context.Context) *dataplanev1.PolicyStatus {
	s.mu.Lock()
	st := &dataplanev1.PolicyStatus{Enabled: true, Version: s.bundle.Version, LastError: s.lastErr}
	empty := len(s.bundle.Policies) == 0
	s.mu.Unlock()
	if !empty {
		if c, err := s.cfg.Host.PolicyCounters(ctx); err == nil {
			st.Packets = c
		}
	}
	return st
}
