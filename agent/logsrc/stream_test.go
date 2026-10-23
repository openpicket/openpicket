package logsrc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openpicket/openpicket/pkg/syslogfmt"
)

func TestJournalLine(t *testing.T) {
	line, cursor, ok := journalLine([]byte(`{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1792749600000000","PRIORITY":"5","SYSLOG_FACILITY":"10",
		"_HOSTNAME":"web-01","SYSLOG_IDENTIFIER":"sshd","_PID":"812","MESSAGE":"Failed password for root from 198.51.100.66 port 4000 ssh2"}`))
	if !ok || cursor != "s=1;i=2" {
		t.Fatalf("ok %v cursor %q", ok, cursor)
	}
	if want := "<85>2026-10-23T10:00:00Z web-01 sshd[812]: Failed password for root from 198.51.100.66 port 4000 ssh2"; string(line) != want {
		t.Fatalf("line %q", line)
	}
	// The manager's syslog parsing reads it back.
	m, ok := syslogfmt.Parse(string(line), time.Now())
	if !ok || m.Program != "sshd" || m.PID != "812" || m.Host != "web-01" || !strings.HasPrefix(m.Message, "Failed password") {
		t.Fatalf("parsed %+v", m)
	}
	// Binary message, no identifier: _COMM.
	line, _, ok = journalLine([]byte(`{"__CURSOR":"c","_COMM":"my app","MESSAGE":[104,105]}`))
	if !ok || !strings.HasSuffix(string(line), " - my_app: hi") {
		t.Fatalf("binary: %q", line)
	}
	if _, _, ok := journalLine([]byte(`{"MESSAGE":"no cursor"}`)); ok {
		t.Fatal("entry without cursor")
	}
}

// fakeJournalctl records its arguments and prints entries after the
// cursor it is given.
func fakeJournalctl(t *testing.T) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	bin, argsFile = filepath.Join(dir, "journalctl"), filepath.Join(dir, "args")
	script := `#!/bin/sh
echo "$@" >> ` + argsFile + `
case "$*" in
*--after-cursor\ c2*) echo '{"__CURSOR":"c3","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"third"}' ;;
*) echo '{"__CURSOR":"c1","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"first"}'
   echo '{"__CURSOR":"c2","SYSLOG_IDENTIFIER":"cron","MESSAGE":"second"}' ;;
esac
exec sleep 60
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

func TestJournalResumesAfterAcknowledgedCursor(t *testing.T) {
	bin, argsFile := fakeJournalctl(t)
	state := filepath.Join(t.TempDir(), "pos.json")
	src := Source{Program: "syslog", Journal: true, Matches: []string{"_SYSTEMD_UNIT=sshd.service", "+", "SYSLOG_IDENTIFIER=cron"}}
	c, err := New(Config{Sources: []Source{src}, StateFile: state, Poll: 10 * time.Millisecond, Journalctl: bin})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	deadline := time.Now().Add(5 * time.Second)
	for len(keys) < 2 && time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		bs, _ := c.Next(ctx, 1000, 1<<20)
		cancel()
		for _, b := range bs {
			if b.Program != "syslog" {
				t.Fatalf("program %q", b.Program)
			}
			for _, r := range b.Records {
				if !strings.Contains(string(r.Line), "sshd: first") && !strings.Contains(string(r.Line), "cron: second") {
					t.Fatalf("line %q", r.Line)
				}
				keys = append(keys, r.Key)
			}
			c.Commit(b)
		}
	}
	if len(keys) != 2 || keys[0] == keys[1] || !strings.HasSuffix(keys[1], "@c2") {
		t.Fatalf("keys %q", keys)
	}
	st := c.Status()
	if st[0].Path != "journal _SYSTEMD_UNIT=sshd.service + SYSLOG_IDENTIFIER=cron" || st[0].Files != 1 || st[0].Lines != 2 {
		t.Fatalf("status %+v", st)
	}
	c.Close()

	// Restarted: after the acknowledged cursor.
	c2 := newCollectorWith(t, Config{Sources: []Source{src}, StateFile: state, Poll: 10 * time.Millisecond, Journalctl: bin})
	got := take(t, c2, 1, true)
	if len(got) != 1 || !strings.HasSuffix(got[0], "sshd: third") {
		t.Fatalf("after restart %q", got)
	}
	args, _ := os.ReadFile(argsFile)
	lines := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "-n 0") || !strings.Contains(lines[1], "--after-cursor c2") ||
		!strings.HasSuffix(lines[1], "_SYSTEMD_UNIT=sshd.service + SYSLOG_IDENTIFIER=cron") {
		t.Fatalf("journalctl args %q", lines)
	}
}

func newCollectorWith(t *testing.T, cfg Config) *Collector {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestListener(t *testing.T) {
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().String()
	l.Close()
	c := newCollectorWith(t, Config{Sources: []Source{{Program: "syslog", Listen: addr}}, Poll: 10 * time.Millisecond})
	take(t, c, 0, false) // starts the listener
	deadline := time.Now().Add(5 * time.Second)
	var got []string
	for len(got) == 0 && time.Now().Before(deadline) {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("<30>Oct 23 12:00:00 dropbear[1234]: Bad password attempt for 'root' from 198.51.100.7:4000\n"))
		conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		bs, _ := c.Next(ctx, 1000, 1<<20)
		cancel()
		for _, b := range bs {
			for _, r := range b.Records {
				if r.Key != "" || r.Path != "" {
					t.Fatalf("datagram record %+v", r)
				}
				got = append(got, b.Program+":"+string(r.Line))
			}
		}
	}
	if len(got) == 0 || got[0] != "syslog:<30>Oct 23 12:00:00 dropbear[1234]: Bad password attempt for 'root' from 198.51.100.7:4000" {
		t.Fatalf("got %q", got)
	}
	if st := c.Status(); st[0].Path != "udp://"+addr || st[0].Files != 1 {
		t.Fatalf("status %+v", st)
	}
}
