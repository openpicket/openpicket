package logsrc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// streamQueue bounds the lines of a stream waiting for a batch.
const streamQueue = 4096

// stream is a source that is not a file: the systemd journal (journalctl)
// or a local syslog listener.
type stream struct {
	src int
	// key names the stream's saved cursor (journal).
	key   string
	lines chan streamLine
	// up: the process runs or the socket is bound.
	up      atomic.Bool
	dropped atomic.Uint64
}

type streamLine struct {
	line []byte
	// cursor of a journal entry: its position, and its record id.
	cursor string
	time   time.Time
}

func (c *Collector) newStream(i int, s Source) *stream {
	st := &stream{src: i, lines: make(chan streamLine, streamQueue)}
	if s.Journal {
		st.key = "journal:" + strings.Join(s.Matches, " ")
	}
	return st
}

// startStreams runs the streams until Close.
func (c *Collector) startStreams() {
	for _, s := range c.streams {
		src := c.cfg.Sources[s.src]
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			if src.Journal {
				c.runJournal(s, src.Matches)
			} else {
				c.runListener(s, src.Listen)
			}
		}()
	}
}

func (c *Collector) setError(s *stream, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.stats[s.src].LastError = ""
	} else {
		c.stats[s.src].LastError = err.Error()
	}
}

// wait sleeps d unless the collector closes; it reports false then.
func (c *Collector) wait(d time.Duration) bool {
	select {
	case <-c.ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// journalDir is the host's journal seen from a container ("" on the host:
// journalctl finds it).
func (c *Collector) journalDir() string {
	if c.cfg.Root == "" || c.cfg.Root == "/" {
		return ""
	}
	for _, d := range []string{"/var/log/journal", "/run/log/journal"} {
		if fi, err := os.Stat(filepath.Join(c.cfg.Root, d)); err == nil && fi.IsDir() {
			return filepath.Join(c.cfg.Root, d)
		}
	}
	return filepath.Join(c.cfg.Root, "/var/log/journal")
}

// runJournal follows the journal with journalctl, after the acknowledged
// cursor (no backlog without one), and restarts it when it exits.
func (c *Collector) runJournal(s *stream, matches []string) {
	c.mu.Lock()
	cursor := c.committed[s.key].Cursor
	c.mu.Unlock()
	bin := c.cfg.Journalctl
	if bin == "" {
		bin = "journalctl"
	}
	for c.ctx.Err() == nil {
		args := []string{"-o", "json", "-f", "--no-pager"}
		if dir := c.journalDir(); dir != "" {
			args = append(args, "--directory", dir)
		}
		if cursor != "" {
			args = append(args, "--after-cursor", cursor)
		} else {
			args = append(args, "-n", "0")
		}
		args = append(args, matches...)
		err := c.runProcess(s, bin, args, func(line []byte) {
			out, cur, ok := journalLine(line)
			if !ok {
				return
			}
			select {
			case s.lines <- streamLine{line: out, cursor: cur, time: time.Now()}:
				// A restart continues after what was read (lines read but not
				// acknowledged are in the queue or in flight).
				cursor = cur
			case <-c.ctx.Done():
			}
		})
		if c.ctx.Err() != nil {
			return
		}
		c.setError(s, fmt.Errorf("journalctl: %w", err))
		c.log.Warn("journalctl exited; restarting in 5s", "err", err)
		if !c.wait(5 * time.Second) {
			return
		}
	}
}

// runProcess runs a command and hands each line of its output to fn.
func (c *Collector) runProcess(s *stream, bin string, args []string, fn func([]byte)) error {
	cmd := exec.CommandContext(c.ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{b: &stderr, max: 4096}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.up.Store(true)
	c.setError(s, nil)
	sc := bufio.NewScanner(stdout)
	// A journal entry in JSON escapes its message: more than MaxLine.
	sc.Buffer(make([]byte, 64<<10), 8*MaxLine)
	for sc.Scan() {
		fn(sc.Bytes())
	}
	scanErr := sc.Err()
	if scanErr != nil {
		_ = cmd.Process.Kill()
	}
	err = cmd.Wait()
	s.up.Store(false)
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return fmt.Errorf("%v: %s", err, lastLine(msg))
	}
	if scanErr != nil {
		return scanErr
	}
	if err == nil {
		err = errors.New("exited")
	}
	return err
}

type limitedWriter struct {
	b   *bytes.Buffer
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if room := w.max - w.b.Len(); room > 0 {
		w.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func lastLine(s string) string {
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// journalLine turns a journal entry (journalctl -o json) into a syslog
// line ("<PRI>TIMESTAMP HOST IDENT[PID]: MESSAGE") and its cursor.
func journalLine(raw []byte) ([]byte, string, bool) {
	var e map[string]json.RawMessage
	if json.Unmarshal(raw, &e) != nil {
		return nil, "", false
	}
	str := func(k string) string {
		var s string
		if v, ok := e[k]; ok && json.Unmarshal(v, &s) == nil {
			return s
		}
		return ""
	}
	cursor := str("__CURSOR")
	if cursor == "" {
		return nil, "", false
	}
	msg := str("MESSAGE")
	if msg == "" {
		// Binary messages are arrays of bytes.
		var b []byte
		if v, ok := e["MESSAGE"]; ok {
			var ints []int
			if json.Unmarshal(v, &ints) == nil {
				for _, i := range ints {
					b = append(b, byte(i))
				}
			}
		}
		msg = strings.ToValidUTF8(string(b), "�")
	}
	if msg == "" {
		return nil, cursor, false
	}
	prio, fac := 6, 1
	if p, err := strconv.Atoi(str("PRIORITY")); err == nil && p >= 0 && p <= 7 {
		prio = p
	}
	if f, err := strconv.Atoi(str("SYSLOG_FACILITY")); err == nil && f >= 0 && f <= 23 {
		fac = f
	}
	ts := time.Now()
	if us, err := strconv.ParseInt(str("__REALTIME_TIMESTAMP"), 10, 64); err == nil {
		ts = time.UnixMicro(us)
	}
	host := str("_HOSTNAME")
	if host == "" {
		host = "-"
	}
	ident := str("SYSLOG_IDENTIFIER")
	if ident == "" {
		ident = str("_COMM")
	}
	if ident == "" {
		ident = "unknown"
	}
	ident = strings.Map(func(r rune) rune {
		if r == ' ' || r == ':' || r == '[' {
			return '_'
		}
		return r
	}, ident)
	pid := str("SYSLOG_PID")
	if pid == "" {
		pid = str("_PID")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<%d>%s %s %s", fac*8+prio, ts.UTC().Format(time.RFC3339Nano), host, ident)
	if pid != "" {
		b.WriteString("[" + pid + "]")
	}
	b.WriteString(": ")
	b.WriteString(msg)
	line := []byte(b.String())
	if len(line) > MaxLine {
		line = line[:MaxLine]
	}
	return line, cursor, true
}

// runListener receives syslog datagrams on a local UDP address (OpenWrt's
// logd forwards there with log_ip/log_port). Nothing replays them: while
// the queue is full they are dropped and counted.
func (c *Collector) runListener(s *stream, addr string) {
	for c.ctx.Err() == nil {
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			c.setError(s, err)
			if !c.wait(5 * time.Second) {
				return
			}
			continue
		}
		s.up.Store(true)
		c.setError(s, nil)
		stop := context.AfterFunc(c.ctx, func() { conn.Close() })
		buf := make([]byte, 65536)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}
			for line := range bytes.SplitSeq(buf[:n], []byte{'\n'}) {
				line = bytes.TrimRight(line, "\r\x00")
				if len(line) == 0 {
					continue
				}
				select {
				case s.lines <- streamLine{line: bytes.Clone(line[:min(len(line), MaxLine)]), time: time.Now()}:
				default:
					s.dropped.Add(1)
				}
			}
		}
		stop()
		conn.Close()
		s.up.Store(false)
	}
}

// drain moves queued lines of s into b, within the limits.
func (c *Collector) drain(s *stream, b *Batch, maxRecords, maxBytes int, total, size *int) {
	for *total < maxRecords && *size < maxBytes {
		select {
		case l := <-s.lines:
			b.Records = append(b.Records, Record{Line: l.line, Time: l.time, Key: keyOf(s, l)})
			if l.cursor != "" {
				b.cursors[s.key] = l.cursor
			}
			*total++
			*size += len(l.line)
			c.stats[s.src].Lines++
		default:
			return
		}
	}
}

// keyOf is the stable identity of a journal entry; "" for a datagram.
func keyOf(s *stream, l streamLine) string {
	if l.cursor == "" {
		return ""
	}
	return s.key + "@" + l.cursor
}
