// Package crowdsecsync is the content side of a CrowdSec log processor
// (openpicket-crowdsec-sync, docs/ARCHITECTURE.md §8): it receives
// bundles from openpicket-manager, checks them with `crowdsec -t`, writes
// them over the configuration and data directories and starts CrowdSec, or
// reloads it (SIGHUP). CrowdSec does not run before the first bundle, so a
// log processor without content accepts no records (the manager sends them
// to another one, or keeps them until it can).
package crowdsecsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/openpicket/openpicket/pkg/hubitem"
)

// Engine is the CrowdSec process.
type Engine interface {
	// Test checks a configuration file (crowdsec -t); output on failure.
	Test(ctx context.Context, configFile string) (string, error)
	// Start starts CrowdSec and returns when it accepts records.
	Start(ctx context.Context) error
	// Reload makes CrowdSec read its configuration again and returns when
	// it finished.
	Reload(ctx context.Context) error
	// Running reports whether CrowdSec runs.
	Running() bool
}

// Config locates the CrowdSec directories.
type Config struct {
	// ConfigFile is the main configuration (/etc/crowdsec/config.yaml);
	// its directory holds the managed subdirectories.
	ConfigFile string
	DataDir    string
	// SimulationFile (default <config dir>/simulation.yaml).
	SimulationFile string
	// WorkDir holds staged configurations (default os.TempDir()).
	WorkDir string
	Engine  Engine
	Logger  *slog.Logger
}

// managedData lists the data files written by bundles, so files of an
// earlier bundle can be removed.
const managedData = ".openpicket-managed"

// Syncer applies bundles. Bundles are applied one at a time.
type Syncer struct {
	cfg Config
	log *slog.Logger

	mu     sync.Mutex
	status hubitem.Status
}

// New creates a syncer.
func New(cfg Config) *Syncer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SimulationFile == "" {
		cfg.SimulationFile = filepath.Join(filepath.Dir(cfg.ConfigFile), "simulation.yaml")
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = os.TempDir()
	}
	return &Syncer{cfg: cfg, log: cfg.Logger}
}

// Status returns the current state.
func (s *Syncer) Status() hubitem.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	st.Running = s.cfg.Engine.Running()
	return st
}

// ErrRefused wraps a bundle CrowdSec does not accept.
var ErrRefused = errors.New("bundle refused")

// Apply checks and applies a bundle. A bundle CrowdSec refuses leaves the
// running content as it is (ErrRefused, also kept in Status).
func (s *Syncer) Apply(ctx context.Context, b *hubitem.Bundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := b.Check(); err != nil {
		return s.refuse(b.Revision, err.Error())
	}
	if b.Revision == s.status.Revision && s.cfg.Engine.Running() {
		return nil
	}
	stage, err := os.MkdirTemp(s.cfg.WorkDir, "openpicket-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	cfgFile, err := s.stage(stage, b)
	if err != nil {
		return err
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	out, err := s.cfg.Engine.Test(tctx, cfgFile)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msg := strings.ReplaceAll(strings.TrimSpace(testError(out)), filepath.Join(stage, "etc"), filepath.Dir(s.cfg.ConfigFile))
		msg = strings.ReplaceAll(msg, filepath.Join(stage, "data"), s.cfg.DataDir)
		if msg == "" {
			msg = err.Error()
		}
		return s.refuse(b.Revision, msg)
	}
	if err := s.install(stage, b); err != nil {
		return fmt.Errorf("install bundle %d: %w", b.Revision, err)
	}
	if s.cfg.Engine.Running() {
		err = s.cfg.Engine.Reload(ctx)
	} else {
		err = s.cfg.Engine.Start(ctx)
	}
	if err != nil {
		return err
	}
	s.status = hubitem.Status{Revision: b.Revision}
	s.log.Info("content applied", "revision", b.Revision, "items", len(b.Items), "data", len(b.Data), "simulation", len(b.Simulation))
	return nil
}

func (s *Syncer) refuse(rev int64, msg string) error {
	s.status.Error, s.status.ErrorRevision = msg, rev
	s.log.Warn("bundle refused", "revision", rev, "err", msg)
	return fmt.Errorf("%w: %s", ErrRefused, msg)
}

// stage writes a copy of the configuration directory with the bundle's
// content, pointing at a staged data directory, and returns its main file.
func (s *Syncer) stage(stage string, b *hubitem.Bundle) (string, error) {
	cfgDir := filepath.Dir(s.cfg.ConfigFile)
	conf := filepath.Join(stage, "etc")
	data := filepath.Join(stage, "data")
	if err := copyTree(cfgDir, conf, func(rel string) bool {
		top, _, _ := strings.Cut(rel, string(filepath.Separator))
		return slices.Contains(hubitem.ManagedDirs, top)
	}); err != nil {
		return "", fmt.Errorf("stage configuration: %w", err)
	}
	if err := writeContent(conf, data, filepath.Join(conf, filepath.Base(s.cfg.SimulationFile)), b); err != nil {
		return "", err
	}
	// The staged main file reads the staged directories.
	main := filepath.Join(conf, filepath.Base(s.cfg.ConfigFile))
	raw, err := os.ReadFile(main)
	if err != nil {
		return "", err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil || len(root.Content) == 0 {
		return "", fmt.Errorf("parse %s: %v", s.cfg.ConfigFile, err)
	}
	setPath(root.Content[0], conf, "config_paths", "config_dir")
	setPath(root.Content[0], data, "config_paths", "data_dir")
	setPath(root.Content[0], filepath.Join(conf, filepath.Base(s.cfg.SimulationFile)), "config_paths", "simulation_path")
	out, err := yaml.Marshal(&root)
	if err != nil {
		return "", err
	}
	return main, os.WriteFile(main, out, 0o600)
}

// install replaces the live content with the staged one. The managed
// directories are emptied and filled again (renaming them fails on
// overlayfs when they come from the image); CrowdSec only reads them when
// it starts or reloads, which comes after.
func (s *Syncer) install(stage string, b *hubitem.Bundle) error {
	cfgDir := filepath.Dir(s.cfg.ConfigFile)
	for _, d := range hubitem.ManagedDirs {
		live := filepath.Join(cfgDir, d)
		if err := os.MkdirAll(live, 0o755); err != nil {
			return err
		}
		entries, err := os.ReadDir(live)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(live, e.Name())); err != nil {
				return err
			}
		}
		src := filepath.Join(stage, "etc", d)
		if _, err := os.Stat(src); err == nil {
			if err := copyTree(src, live, nil); err != nil {
				return err
			}
		}
	}
	// Data files: written in place (the directory is shared with
	// CrowdSec's own files); those of earlier bundles not in this one go.
	prev, _ := os.ReadFile(filepath.Join(s.cfg.DataDir, managedData))
	keep := map[string]bool{}
	for _, f := range b.Data {
		keep[f.Path] = true
		if err := writeFile(filepath.Join(s.cfg.DataDir, f.Path), f.Content); err != nil {
			return err
		}
	}
	for _, p := range strings.Split(string(prev), "\n") {
		if p != "" && !keep[p] && hubitem.ValidDataFile(p) {
			_ = os.Remove(filepath.Join(s.cfg.DataDir, p))
		}
	}
	names := make([]string, 0, len(b.Data))
	for _, f := range b.Data {
		names = append(names, f.Path)
	}
	if err := writeFile(filepath.Join(s.cfg.DataDir, managedData), []byte(strings.Join(names, "\n"))); err != nil {
		return err
	}
	return writeFile(s.cfg.SimulationFile, simulationYAML(b.Simulation))
}

// writeContent writes a bundle under conf and data.
func writeContent(conf, data, simulation string, b *hubitem.Bundle) error {
	for _, d := range hubitem.ManagedDirs {
		if err := os.MkdirAll(filepath.Join(conf, d), 0o755); err != nil {
			return err
		}
	}
	for _, f := range b.Items {
		if err := writeFile(filepath.Join(conf, filepath.FromSlash(f.Path)), f.Content); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(data, 0o755); err != nil {
		return err
	}
	for _, f := range b.Data {
		if err := writeFile(filepath.Join(data, filepath.FromSlash(f.Path)), f.Content); err != nil {
			return err
		}
	}
	return writeFile(simulation, simulationYAML(b.Simulation))
}

// simulationYAML puts the listed scenarios in simulation (exclusions of
// a global "off").
func simulationYAML(names []string) []byte {
	var b bytes.Buffer
	b.WriteString("# Written by openpicket-crowdsec-sync.\nsimulation: off\n")
	if len(names) > 0 {
		b.WriteString("exclusions:\n")
		for _, n := range names {
			fmt.Fprintf(&b, "  - %s\n", n)
		}
	}
	return b.Bytes()
}

func writeFile(p string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// copyTree copies a directory (files, directories and symlinks), skipping
// the paths skip reports.
func copyTree(src, dst string, skip func(rel string) bool) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel != "." && skip != nil && skip(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case info.Mode().IsRegular():
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				out.Close()
				return err
			}
			return out.Close()
		}
		return nil
	})
}

// setPath sets a scalar at path in a mapping node.
func setPath(m *yaml.Node, value string, path ...string) {
	for i, key := range path {
		var child *yaml.Node
		for j := 0; j+1 < len(m.Content); j += 2 {
			if m.Content[j].Value == key {
				child = m.Content[j+1]
			}
		}
		last := i == len(path)-1
		if child == nil {
			k := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
			child = &yaml.Node{Kind: yaml.MappingNode}
			if last {
				child = &yaml.Node{Kind: yaml.ScalarNode}
			}
			m.Content = append(m.Content, k, child)
		}
		if last {
			child.Kind, child.Tag, child.Value, child.Content = yaml.ScalarNode, "!!str", value, nil
			return
		}
		if child.Kind != yaml.MappingNode {
			child.Kind, child.Tag, child.Value, child.Content = yaml.MappingNode, "!!map", "", nil
		}
		m = child
	}
}

// testError keeps the error lines of crowdsec -t (the last lines when
// there are none).
func testError(out string) string {
	var errs []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "level=fatal") || strings.Contains(l, "level=error") {
			errs = append(errs, l)
		}
	}
	if len(errs) > 0 {
		return strings.Join(errs, "\n")
	}
	return lastLines(out, 8)
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
