package k8slogs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openpicket/openpicket/agent/logsrc"
)

// MaxLine bounds a line; longer lines are cut (and counted).
const MaxLine = logsrc.MaxLine

// Positions of containers not seen for this long are forgotten.
const forgetAfter = 24 * time.Hour

// position is where a container's log was read or acknowledged up to.
type position struct {
	// Time of the last line; N lines carried exactly that time. With
	// Line false, Time is a bound from the collector's clock (where
	// reading started), not a line's: nothing is skipped on resume.
	// Zero: the container's log from its start.
	Time time.Time `json:"time"`
	N    int       `json:"n,omitempty"`
	Line bool      `json:"line,omitempty"`
	// Seen is when the container last matched a target.
	Seen time.Time `json:"seen"`
}

// state is the state file.
type state struct {
	// SavedAt is when every matched container was followed: pods that
	// start after it are read from it after a restart.
	SavedAt    time.Time           `json:"saved_at"`
	Containers map[string]position `json:"containers"`
}

// CollectorConfig configures a Collector.
type CollectorConfig struct {
	Kube    *Kube
	Targets []Target
	// StateFile keeps the acknowledged positions; empty: stateless.
	StateFile    string
	ScanInterval time.Duration
	Logger       *slog.Logger
}

// TargetStatus is the state of a target.
type TargetStatus struct {
	Program   string
	Path      string
	Followed  int
	Lines     uint64
	Truncated uint64
	LastError string
}

// Collector follows the containers of the targets; the shipper takes its
// batches (Next) and commits them once acknowledged (Commit).
type Collector struct {
	cfg   CollectorConfig
	log   *slog.Logger
	queue chan entry
	now   func() time.Time

	mu        sync.Mutex
	followers map[string]*follower
	committed map[string]position
	restored  bool
	savedAt   time.Time
	pending   map[*logsrc.Batch]map[string]position
	stats     []TargetStatus
	scanned   bool
	savedFile time.Time // last write of the state file
}

type follower struct {
	key, namespace, pod, container string
	target                         int
	program                        string
	// pos is the read position (the follower's own goroutine writes it;
	// others read it once done is closed).
	pos position
	// fromEnd: the first read starts at the log's current end (pos is
	// then that moment, for a restart).
	fromEnd bool
	done    chan struct{}
}

type entry struct {
	key, program string
	target       int
	line         []byte
	time         time.Time
	pos          position
	rid          string
}

// New creates a collector; it reads the state file.
func New(cfg CollectorConfig) (*Collector, error) {
	if cfg.Kube == nil {
		return nil, errors.New("k8slogs: Kube is required")
	}
	if cfg.ScanInterval <= 0 {
		cfg.ScanInterval = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	c := &Collector{cfg: cfg, log: cfg.Logger.With("component", "k8slogs"), queue: make(chan entry, 4096), now: time.Now,
		followers: map[string]*follower{}, committed: map[string]position{}, pending: map[*logsrc.Batch]map[string]position{}}
	for _, t := range cfg.Targets {
		prog := t.Program
		if prog == "" {
			prog = "(container name)"
		}
		c.stats = append(c.stats, TargetStatus{Program: prog, Path: t.Describe()})
	}
	if cfg.StateFile != "" {
		b, err := os.ReadFile(cfg.StateFile)
		switch {
		case err == nil:
			var st state
			if err := json.Unmarshal(b, &st); err != nil {
				c.log.Warn("unreadable state; starting at the containers' current ends", "file", cfg.StateFile, "err", err)
				break
			}
			c.restored, c.savedAt = true, st.SavedAt
			if st.Containers != nil {
				c.committed = st.Containers
			}
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	return c, nil
}

// Run lists the targets' pods and follows their containers until ctx
// ends.
func (c *Collector) Run(ctx context.Context) {
	t := time.NewTicker(c.cfg.ScanInterval)
	defer t.Stop()
	for {
		c.scan(ctx)
		select {
		case <-ctx.Done():
			c.mu.Lock()
			fs := make([]*follower, 0, len(c.followers))
			for _, f := range c.followers {
				fs = append(fs, f)
			}
			c.mu.Unlock()
			for _, f := range fs {
				<-f.done
			}
			return
		case <-t.C:
		}
	}
}

// selectors resolves a target's label and field selectors.
func (c *Collector) selectors(ctx context.Context, t Target) (string, string, error) {
	labels, fields := t.Selector, []string{"status.phase=Running"}
	if t.Workload != "" {
		kind, name := t.workload()
		sel, err := c.cfg.Kube.WorkloadSelector(ctx, t.Namespace, kind, name)
		if err != nil {
			return "", "", fmt.Errorf("%s: %w", t.Workload, err)
		}
		if labels != "" {
			sel += "," + labels
		}
		labels = sel
	}
	if t.FieldSelector != "" {
		fields = append(fields, t.FieldSelector)
	}
	if t.ServiceAccount != "" {
		fields = append(fields, "spec.serviceAccountName="+t.ServiceAccount)
	}
	if t.Pod != "" {
		fields = append(fields, "metadata.name="+t.Pod)
	}
	return labels, strings.Join(fields, ","), nil
}

func (c *Collector) scan(ctx context.Context) {
	started := c.now()
	type found struct {
		target                         int
		namespace, pod, container, uid string
	}
	var matched []found
	errs := make([]string, len(c.cfg.Targets))
	listOK := true
	for i, t := range c.cfg.Targets {
		labels, fields, err := c.selectors(ctx, t)
		var pods []Pod
		if err == nil {
			pods, err = c.cfg.Kube.Pods(ctx, t.Namespace, labels, fields)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			errs[i], listOK = err.Error(), false
			continue
		}
		for _, p := range pods {
			for _, ct := range t.containersOf(p) {
				matched = append(matched, found{i, p.Metadata.Namespace, p.Metadata.Name, ct, p.Metadata.UID})
			}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	first := !c.scanned
	c.scanned = true
	seen := map[string]bool{}
	counts := make([]int, len(c.cfg.Targets))
	for _, m := range matched {
		key := m.uid + "/" + m.container
		if seen[key] {
			continue // the first target matching a container names it
		}
		seen[key] = true
		counts[m.target]++
		if f := c.followers[key]; f != nil {
			select {
			case <-f.done:
			default:
				continue // still following
			}
		}
		t := c.cfg.Targets[m.target]
		f := &follower{key: key, namespace: m.namespace, pod: m.pod, container: m.container, target: m.target,
			program: t.ProgramOf(m.container), done: make(chan struct{})}
		f.pos, f.fromEnd = c.startPosition(key, first, started)
		if _, ok := c.committed[key]; !ok {
			// Where reading starts is a position too: a restart before the
			// first acknowledgement resumes from here.
			c.committed[key] = f.pos
		}
		c.followers[key] = f
		from := describe(f.pos)
		if f.fromEnd {
			from = "end"
		}
		c.log.Info("following", "namespace", f.namespace, "pod", f.pod, "container", f.container, "program", f.program, "from", from)
		go c.follow(ctx, f)
	}
	for key, f := range c.followers {
		select {
		case <-f.done:
			if !seen[key] {
				delete(c.followers, key)
			}
		default:
		}
	}
	for key, p := range c.committed {
		if seen[key] {
			p.Seen = started
			c.committed[key] = p
		} else if c.followers[key] == nil && started.Sub(p.Seen) > forgetAfter {
			delete(c.committed, key)
		}
	}
	for i := range c.stats {
		c.stats[i].Followed, c.stats[i].LastError = counts[i], errs[i]
	}
	// Every matched container is followed from here: a pod starting
	// after this is read from it after a restart. A failed list leaves
	// the previous bound.
	if listOK {
		c.savedAt = started
	}
	c.saveLocked()
}

// containersOf returns the running containers of a pod the target takes.
func (t Target) containersOf(p Pod) []string {
	var out []string
	for _, ct := range p.Spec.Containers {
		if (len(t.Containers) == 0 || slices.Contains(t.Containers, ct.Name)) && p.Running(ct.Name) {
			out = append(out, ct.Name)
		}
	}
	return out
}

func describe(p position) string {
	switch {
	case p.Time.IsZero():
		return "start"
	case p.Line:
		return "after " + p.Time.Format(time.RFC3339Nano)
	}
	return p.Time.Format(time.RFC3339)
}

// startPosition decides where a container is read from: its read or
// acknowledged position, else (first scan) the last save or its current
// end, else (a container that appeared since) its start.
func (c *Collector) startPosition(key string, first bool, now time.Time) (position, bool) {
	if f := c.followers[key]; f != nil {
		return f.pos, false // ended (restart, kubelet rotation): after what was read
	}
	if p, ok := c.committed[key]; ok {
		return p, false
	}
	if !first {
		return position{}, false
	}
	if c.restored && !c.savedAt.IsZero() {
		return position{Time: c.savedAt}, false
	}
	return position{Time: now}, true
}

// follow reads a container's log until it ends.
func (c *Collector) follow(ctx context.Context, f *follower) {
	defer close(f.done)
	opts := LogOptions{TailLines: -1}
	switch {
	case f.fromEnd:
		opts.TailLines = 0
		f.fromEnd = false
	case !f.pos.Time.IsZero():
		opts.SinceTime = f.pos.Time
	}
	rc, err := c.cfg.Kube.Logs(ctx, f.namespace, f.pod, f.container, opts)
	if err != nil {
		if ctx.Err() == nil {
			c.setError(f.target, fmt.Sprintf("%s/%s: %v", f.pod, f.container, err))
		}
		return
	}
	defer rc.Close()
	stop := context.AfterFunc(ctx, func() { rc.Close() })
	defer stop()
	skip := f.pos // lines up to it were shipped before
	skipped := 0
	r := bufio.NewReaderSize(rc, MaxLine+64)
	for {
		line, cut, err := readLine(r)
		if cut {
			c.mu.Lock()
			c.stats[f.target].Truncated++
			c.mu.Unlock()
		}
		if len(line) > 0 {
			ts, msg := splitTimestamp(line, c.now)
			if len(msg) > 0 {
				drop := false
				if skip.Line {
					switch {
					case ts.Before(skip.Time):
						drop = true
					case ts.Equal(skip.Time) && skipped < skip.N:
						skipped++
						drop = true
					}
				}
				if !drop {
					n := 1
					if f.pos.Line && ts.Equal(f.pos.Time) {
						n = f.pos.N + 1
					}
					f.pos = position{Time: ts, N: n, Line: true}
					e := entry{key: f.key, program: f.program, target: f.target, line: msg, time: ts, pos: f.pos,
						rid: f.key + "@" + ts.UTC().Format(time.RFC3339Nano) + "#" + strconv.Itoa(n)}
					select {
					case c.queue <- e:
					case <-ctx.Done():
						return
					}
				}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				c.log.Debug("log stream ended", "pod", f.pod, "container", f.container, "err", err)
			}
			return
		}
	}
}

func (c *Collector) setError(target int, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats[target].LastError = msg
}

// readLine reads a line without its newline; a line longer than MaxLine
// is cut and the rest dropped.
func readLine(r *bufio.Reader) ([]byte, bool, error) {
	line, err := r.ReadSlice('\n')
	out := bytes.Clone(line)
	cut := false
	for errors.Is(err, bufio.ErrBufferFull) {
		cut = true
		_, err = r.ReadSlice('\n')
	}
	out = bytes.TrimRight(out, "\r\n")
	if len(out) > MaxLine {
		out, cut = out[:MaxLine], true
	}
	return out, cut, err
}

// splitTimestamp cuts the timestamp the API puts before each line
// (timestamps=true).
func splitTimestamp(line []byte, now func() time.Time) (time.Time, []byte) {
	if i := bytes.IndexByte(line, ' '); i > 0 {
		if t, err := time.Parse(time.RFC3339Nano, string(line[:i])); err == nil {
			return t, line[i+1:]
		}
	}
	return now(), line
}

// Next waits for lines and returns them as one batch per program, at most
// maxRecords lines or maxBytes, gathered for up to half a second.
func (c *Collector) Next(ctx context.Context, maxRecords, maxBytes int) ([]*logsrc.Batch, error) {
	var e entry
	select {
	case e = <-c.queue:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	byProgram := map[string]*logsrc.Batch{}
	positions := map[*logsrc.Batch]map[string]position{}
	var order []*logsrc.Batch
	lines := map[int]uint64{} // per target
	total, size := 0, 0
	add := func(e entry) {
		b := byProgram[e.program]
		if b == nil {
			b = &logsrc.Batch{Program: e.program}
			byProgram[e.program] = b
			positions[b] = map[string]position{}
			order = append(order, b)
		}
		b.Records = append(b.Records, logsrc.Record{Line: e.line, Time: e.time, Key: e.rid})
		positions[b][e.key] = e.pos
		lines[e.target]++
		total++
		size += len(e.line)
	}
	add(e)
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
gather:
	for total < maxRecords && size < maxBytes {
		select {
		case e = <-c.queue:
			add(e)
		case <-timer.C:
			break gather
		case <-ctx.Done():
			break gather
		}
	}
	c.mu.Lock()
	for _, b := range order {
		c.pending[b] = positions[b]
	}
	for t, n := range lines {
		c.stats[t].Lines += n
	}
	c.mu.Unlock()
	return order, nil
}

// Commit records the positions of an acknowledged batch.
func (c *Collector) Commit(b *logsrc.Batch) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, p := range c.pending[b] {
		p.Seen = c.committed[key].Seen
		if p.Seen.IsZero() {
			p.Seen = c.now()
		}
		c.committed[key] = p
	}
	delete(c.pending, b)
	// At most once a second; the scans and Flush write the rest.
	if c.now().Sub(c.savedFile) >= time.Second {
		c.saveLocked()
	}
}

// Flush writes the state file (at shutdown, once the shipper stopped).
func (c *Collector) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.saveLocked()
}

// saveLocked writes the state file (mu held).
func (c *Collector) saveLocked() {
	if c.cfg.StateFile == "" {
		return
	}
	c.savedFile = c.now()
	b, err := json.Marshal(state{SavedAt: c.savedAt, Containers: c.committed})
	if err == nil {
		err = writeAtomic(c.cfg.StateFile, b)
	}
	if err != nil {
		c.log.Warn("save positions", "file", c.cfg.StateFile, "err", err)
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

// CheckResult is what a target selects now.
type CheckResult struct {
	Target, Program string
	Containers      int
	Err             error
}

// Check lists the pods of every target once (no logs are read).
func (c *Collector) Check(ctx context.Context) []CheckResult {
	var out []CheckResult
	for i, t := range c.cfg.Targets {
		r := CheckResult{Target: t.Describe(), Program: c.stats[i].Program}
		labels, fields, err := c.selectors(ctx, t)
		var pods []Pod
		if err == nil {
			pods, err = c.cfg.Kube.Pods(ctx, t.Namespace, labels, fields)
		}
		r.Err = err
		for _, p := range pods {
			r.Containers += len(t.containersOf(p))
		}
		out = append(out, r)
	}
	return out
}

// Status returns the targets' state.
func (c *Collector) Status() []TargetStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]TargetStatus(nil), c.stats...)
}
