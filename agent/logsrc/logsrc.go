// Package logsrc tails the generic log files of a node (nginx, postgres,
// auth.log...) for the shipper: at-least-once, a file's position is saved
// only once the manager acknowledged its lines (docs/ARCHITECTURE.md §4.8).
// Suricata's logs go through the suricontroller collector instead.
package logsrc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/openpicket/openpicket/pkg/record"
)

// MaxLine bounds a line; longer lines are cut (and counted).
const MaxLine = 64 << 10

// Source is a configured log: a program and a path, which may be a glob.
type Source struct {
	Program string
	Path    string
}

// Config configures a Collector.
type Config struct {
	Sources []Source
	// Root prefixes every path (the host filesystem seen from a
	// container); "" or "/" for a direct install.
	Root string
	// StateFile keeps the acknowledged positions.
	StateFile string
	// Poll is how often files are read and globs expanded (default 1s;
	// globs every 5 polls).
	Poll   time.Duration
	Logger *slog.Logger
}

// Record is a line with its position.
type Record struct {
	Line   []byte
	Path   string
	Inode  uint64
	Offset int64
	// Time the line was read.
	Time time.Time
}

// Batch is lines of one program, in file order.
type Batch struct {
	Program string
	Records []Record
	// ends are the file positions reached, committed with the batch.
	ends map[fileKey]int64
}

type fileKey struct {
	path  string
	inode uint64
}

// file is a tailed file.
type file struct {
	src   int // index in Sources
	path  string
	f     *os.File
	inode uint64
	// read is the position read up to; partial holds a line without its
	// newline yet.
	read    int64
	partial []byte
	skip    bool // the rest of an overlong line is dropped
	// rotated: the path now names another file; this one is read to its
	// end, then closed.
	rotated bool
}

// SourceStatus is the state of a source.
type SourceStatus struct {
	Program   string
	Path      string
	Files     int
	Lines     uint64
	Truncated uint64
	LastError string
}

// Collector tails the sources.
type Collector struct {
	cfg Config
	log *slog.Logger

	mu        sync.Mutex
	files     []*file
	committed map[string]position // path -> acknowledged position
	stats     []SourceStatus
	started   bool
	polls     int
}

type position struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// New creates a collector; it reads the saved positions.
func New(cfg Config) (*Collector, error) {
	if cfg.Poll <= 0 {
		cfg.Poll = time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	c := &Collector{cfg: cfg, log: cfg.Logger.With("component", "logsrc"), committed: map[string]position{}}
	for _, s := range cfg.Sources {
		if record.NormalizeProgram(s.Program) == "" || s.Path == "" {
			return nil, fmt.Errorf("logsrc: invalid source %q %q", s.Program, s.Path)
		}
		if _, err := filepath.Match(s.Path, ""); err != nil {
			return nil, fmt.Errorf("logsrc: %s: %w", s.Path, err)
		}
		c.stats = append(c.stats, SourceStatus{Program: record.NormalizeProgram(s.Program), Path: s.Path})
	}
	if cfg.StateFile != "" {
		b, err := os.ReadFile(cfg.StateFile)
		switch {
		case err == nil:
			if err := json.Unmarshal(b, &c.committed); err != nil {
				c.log.Warn("unreadable positions; starting over", "file", cfg.StateFile, "err", err)
				c.committed = map[string]position{}
			}
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	return c, nil
}

func (c *Collector) host(p string) string {
	if c.cfg.Root == "" || c.cfg.Root == "/" {
		return p
	}
	return filepath.Join(c.cfg.Root, p)
}

// discover expands the globs. Files of the first scan without a saved
// position start at their end (no backlog flood when a source is added);
// files appearing later start at their beginning.
func (c *Collector) discover() {
	first := !c.started
	c.started = true
	tracked := map[string]*file{}
	for _, f := range c.files {
		if !f.rotated {
			tracked[f.path] = f
		}
	}
	counts := make([]int, len(c.cfg.Sources))
	for i, s := range c.cfg.Sources {
		matches, err := filepath.Glob(c.host(s.Path))
		if err != nil {
			c.stats[i].LastError = err.Error()
			continue
		}
		sort.Strings(matches)
		for _, m := range matches {
			p := m
			if c.cfg.Root != "" && c.cfg.Root != "/" {
				p = "/" + filepath.ToSlash(mustRel(c.cfg.Root, m))
			}
			if fi, err := os.Stat(m); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			counts[i]++
			if f := tracked[p]; f != nil {
				continue
			}
			f, err := c.open(i, p, first)
			if err != nil {
				c.stats[i].LastError = err.Error()
				continue
			}
			c.files = append(c.files, f)
			tracked[p] = f
		}
	}
	for i := range counts {
		c.stats[i].Files = counts[i]
	}
}

func mustRel(root, p string) string {
	r, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return r
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

func (c *Collector) open(src int, path string, first bool) (*file, error) {
	f, err := os.Open(c.host(path))
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	nf := &file{src: src, path: path, f: f, inode: inodeOf(fi)}
	pos, saved := c.committed[path]
	switch {
	case saved && pos.Inode == nf.inode && pos.Offset <= fi.Size():
		nf.read = pos.Offset
	case saved:
		// Rotated (or truncated) since: the new file from its start.
		nf.read = 0
	case first:
		nf.read = fi.Size()
	}
	if _, err := f.Seek(nf.read, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return nf, nil
}

// check notices rotation (the path names another inode) and truncation
// (copytruncate: the file is shorter than what was read).
func (c *Collector) check(f *file) {
	if f.rotated {
		return
	}
	fi, err := os.Stat(c.host(f.path))
	switch {
	case err != nil:
		// Removed: read what is left of the open file, then drop it.
		f.rotated = true
	case inodeOf(fi) != f.inode:
		f.rotated = true
	default:
		if cur, err := f.f.Stat(); err == nil && cur.Size() < f.read {
			c.log.Info("file truncated; reading it from the start", "path", f.path)
			f.read, f.partial, f.skip = 0, nil, false
			_, _ = f.f.Seek(0, io.SeekStart)
		}
	}
}

// readLines appends the complete lines of f, up to the limits. A line
// longer than MaxLine is cut; the rest of it is dropped.
func (c *Collector) readLines(f *file, out *Batch, maxRecords, maxBytes int, now time.Time, size *int) error {
	buf := make([]byte, 32<<10)
	st := &c.stats[f.src]
	for len(out.Records) < maxRecords && *size < maxBytes {
		n, err := f.f.Read(buf)
		data := buf[:n]
		for len(data) > 0 {
			lineStart := f.read - int64(len(f.partial))
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				if !f.skip {
					f.partial = append(f.partial, data...)
				}
				f.read += int64(len(data))
				if !f.skip && len(f.partial) > MaxLine {
					c.emit(f, out, f.partial[:MaxLine], lineStart, now, size)
					st.Truncated++
					f.partial, f.skip = nil, true
				}
				break
			}
			f.read += int64(i + 1)
			if f.skip {
				f.skip = false
			} else {
				line := bytes.TrimRight(append(f.partial, data[:i]...), "\r")
				f.partial = nil
				if len(line) > MaxLine {
					line = line[:MaxLine]
					st.Truncated++
				}
				if len(line) > 0 {
					c.emit(f, out, line, lineStart, now, size)
				}
			}
			data = data[i+1:]
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n == 0 {
			return nil
		}
	}
	return nil
}

func (c *Collector) emit(f *file, out *Batch, line []byte, offset int64, now time.Time, size *int) {
	out.Records = append(out.Records, Record{Line: bytes.Clone(line), Path: f.path, Inode: f.inode, Offset: offset, Time: now})
	*size += len(line)
	c.stats[f.src].Lines++
}

// Next blocks until lines are available and returns them, at most
// maxRecords lines or maxBytes per call, as one batch per program. A file
// is only read again once the previous lines of it were returned, so
// positions advance in order.
func (c *Collector) Next(ctx context.Context, maxRecords, maxBytes int) ([]*Batch, error) {
	for {
		batches := c.poll(maxRecords, maxBytes)
		if len(batches) > 0 {
			return batches, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.cfg.Poll):
		}
	}
}

func (c *Collector) poll(maxRecords, maxBytes int) []*Batch {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.polls%5 == 0 {
		c.discover()
	}
	c.polls++
	now := time.Now()
	byProgram := map[string]*Batch{}
	var order []string
	size := 0
	total := 0
	keep := c.files[:0]
	for _, f := range c.files {
		c.check(f)
		prog := c.stats[f.src].Program
		b := byProgram[prog]
		if b == nil {
			b = &Batch{Program: prog, ends: map[fileKey]int64{}}
		}
		before := len(b.Records)
		if total < maxRecords && size < maxBytes {
			if err := c.readLines(f, b, maxRecords-total+before, maxBytes, now, &size); err != nil {
				c.stats[f.src].LastError = err.Error()
			}
		}
		total += len(b.Records) - before
		if len(b.Records) > before || f.rotated {
			b.ends[fileKey{f.path, f.inode}] = f.read - int64(len(f.partial))
		}
		if len(b.Records) > 0 && byProgram[prog] == nil {
			byProgram[prog] = b
			order = append(order, prog)
		}
		// A rotated file read to its end is closed (a last line without
		// newline is complete now); its position stays for the commit.
		if f.rotated && len(b.Records) == before {
			if len(f.partial) > 0 && !f.skip {
				c.emit(f, b, f.partial, f.read-int64(len(f.partial)), now, &size)
				f.partial = nil
				b.ends[fileKey{f.path, f.inode}] = f.read
				if byProgram[prog] == nil {
					byProgram[prog] = b
					order = append(order, prog)
				}
			}
			f.f.Close()
			continue
		}
		keep = append(keep, f)
	}
	c.files = keep
	out := make([]*Batch, 0, len(order))
	for _, p := range order {
		out = append(out, byProgram[p])
	}
	return out
}

// Commit records the positions of an acknowledged batch.
func (c *Collector) Commit(b *Batch) {
	c.mu.Lock()
	current := map[string]uint64{}
	for _, f := range c.files {
		if !f.rotated {
			current[f.path] = f.inode
		}
	}
	for k, off := range b.ends {
		if ino, ok := current[k.path]; ok && ino != k.inode {
			// A rotated file: the path names its successor now, whose
			// position is the one to keep.
			continue
		}
		cur, ok := c.committed[k.path]
		if !ok || cur.Inode != k.inode || cur.Offset < off {
			c.committed[k.path] = position{Inode: k.inode, Offset: off}
		}
	}
	snapshot, _ := json.Marshal(c.committed)
	c.mu.Unlock()
	if c.cfg.StateFile == "" {
		return
	}
	if err := writeAtomic(c.cfg.StateFile, snapshot); err != nil {
		c.log.Warn("save log positions", "err", err)
	}
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Status returns the sources' state.
func (c *Collector) Status() []SourceStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]SourceStatus(nil), c.stats...)
}

// Close closes the open files.
func (c *Collector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.files {
		f.f.Close()
	}
	c.files = nil
}
