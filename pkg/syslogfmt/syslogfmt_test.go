package syslogfmt

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		line                    string
		prio                    int
		host, program, pid, msg string
		time                    string
	}{
		{"Oct 23 10:00:01 web-01 sshd[812]: Failed password for root from 198.51.100.66 port 4000 ssh2", -1,
			"web-01", "sshd", "812", "Failed password for root from 198.51.100.66 port 4000 ssh2", "2026-10-23T10:00:01Z"},
		{"<38>Oct  3 09:08:07 nas01 dropbear[33]: Bad password attempt for 'admin'", 38, "nas01", "dropbear", "33", "Bad password attempt for 'admin'", "2026-10-03T09:08:07Z"},
		// No host (some embedded senders).
		{"<13>Oct 23 10:00:01 kernel: link up", 13, "", "kernel", "", "link up", "2026-10-23T10:00:01Z"},
		// rsyslog high precision.
		{"2026-10-23T10:00:01.123456+09:00 db-01 postgres[99]: FATAL:  password authentication failed for user \"x\"", -1,
			"db-01", "postgres", "99", "FATAL:  password authentication failed for user \"x\"", "2026-10-23T01:00:01.123456Z"},
		// December line read in January: last year.
		{"Dec 31 23:59:59 h cron[1]: x", -1, "h", "cron", "1", "x", "2025-12-31T23:59:59Z"},
		// RFC 5424 with structured data and a BOM.
		{`<165>1 2026-10-23T10:00:01Z sw-01 sshd 77 ID47 [exampleSDID@32473 iut="3" eventSource="App\]x"] ` + "\ufeff" + `Invalid user bob`, 165,
			"sw-01", "sshd", "77", "Invalid user bob", "2026-10-23T10:00:01Z"},
		{`<34>1 2026-10-23T10:00:01Z - app - - - hello`, 34, "", "app", "", "hello", "2026-10-23T10:00:01Z"},
	} {
		n := now
		if c.program == "cron" {
			n = time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
		}
		m, ok := Parse(c.line, n)
		if !ok || m.Priority != c.prio || m.Host != c.host || m.Program != c.program || m.PID != c.pid || m.Message != c.msg ||
			m.Time.UTC().Format(time.RFC3339Nano) != c.time {
			t.Errorf("%q: %+v %v", c.line, m, ok)
		}
	}
	for _, bad := range []string{"", "plain text line", "<999>Oct 23 10:00:01 h p: x", "Oct 23 10:00:01 host no colon here", "<34>1 2026-10-23T10:00:01Z h - - - - x"} {
		if _, ok := Parse(bad, now); ok {
			t.Errorf("parsed %q", bad)
		}
	}
}
