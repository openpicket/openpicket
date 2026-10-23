// Package syslogfmt splits syslog lines into their header fields and
// message: RFC 3164 (BSD) with or without a priority, the same with an
// RFC 3339 timestamp (rsyslog's high precision format), and RFC 5424.
// Lines of syslog files (auth.log) and syslog messages received over the
// network both go through it, so CrowdSec gets the program and the bare
// message as its own syslog parser would give them.
package syslogfmt

import (
	"strconv"
	"strings"
	"time"
)

// Message is a parsed syslog line.
type Message struct {
	// Priority is facility*8+severity, -1 when the line has none.
	Priority int
	Time     time.Time
	Host     string
	// Program is the tag or APP-NAME ("sshd"), without the pid.
	Program string
	PID     string
	Message string
}

var months = map[string]time.Month{"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

// Parse splits a line. now completes BSD timestamps, which have no year
// (a date ahead of now by more than a day is taken from last year). ok is
// false when the line has no recognizable header.
func Parse(line string, now time.Time) (Message, bool) {
	m := Message{Priority: -1}
	rest := strings.TrimRight(line, "\r\n")
	if strings.HasPrefix(rest, "<") {
		end := strings.IndexByte(rest, '>')
		if end < 2 || end > 4 {
			return m, false
		}
		p, err := strconv.Atoi(rest[1:end])
		if err != nil || p > 191 {
			return m, false
		}
		m.Priority, rest = p, rest[end+1:]
		if strings.HasPrefix(rest, "1 ") {
			return parse5424(m, rest[2:])
		}
	}
	var ok bool
	if m.Time, rest, ok = bsdTime(rest, now); !ok {
		if m.Time, rest, ok = isoTime(rest); !ok {
			return m, false
		}
	}
	// HOSTNAME TAG[PID]: MSG; some senders leave the host out.
	host, after, found := strings.Cut(rest, " ")
	if !found {
		return m, false
	}
	if strings.HasSuffix(host, ":") || strings.Contains(host, "[") {
		after = rest
	} else {
		m.Host = host
	}
	tag, msg, found := strings.Cut(after, ":")
	if !found || tag == "" || strings.ContainsAny(tag, " \t") {
		return m, false
	}
	m.Program, m.PID = splitPID(tag)
	m.Message = strings.TrimPrefix(msg, " ")
	return m, m.Program != ""
}

func splitPID(tag string) (string, string) {
	if i := strings.IndexByte(tag, '['); i > 0 && strings.HasSuffix(tag, "]") {
		return tag[:i], tag[i+1 : len(tag)-1]
	}
	return tag, ""
}

// bsdTime reads "Oct 23 10:00:00 " (the day may be space padded).
func bsdTime(s string, now time.Time) (time.Time, string, bool) {
	if len(s) < 16 || s[3] != ' ' || s[15] != ' ' {
		return time.Time{}, s, false
	}
	mon, ok := months[s[:3]]
	if !ok {
		return time.Time{}, s, false
	}
	day, err := strconv.Atoi(strings.TrimSpace(s[4:6]))
	if err != nil {
		return time.Time{}, s, false
	}
	clock, err := time.Parse("15:04:05", s[7:15])
	if err != nil {
		return time.Time{}, s, false
	}
	loc := now.Location()
	t := time.Date(now.Year(), mon, day, clock.Hour(), clock.Minute(), clock.Second(), 0, loc)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, s[16:], true
}

func isoTime(s string) (time.Time, string, bool) {
	ts, rest, ok := strings.Cut(s, " ")
	if !ok {
		return time.Time{}, s, false
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, s, false
	}
	return t, rest, true
}

// parse5424 reads "TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG".
func parse5424(m Message, s string) (Message, bool) {
	f := strings.SplitN(s, " ", 6)
	if len(f) < 6 {
		return m, false
	}
	if f[0] != "-" {
		t, err := time.Parse(time.RFC3339Nano, f[0])
		if err != nil {
			return m, false
		}
		m.Time = t
	}
	if f[1] != "-" {
		m.Host = f[1]
	}
	if f[2] == "-" {
		return m, false
	}
	m.Program = f[2]
	if f[3] != "-" {
		m.PID = f[3]
	}
	msg := f[5]
	// Structured data: "-" or one or more [ ... ] elements.
	switch {
	case strings.HasPrefix(msg, "-"):
		msg = msg[1:]
	case strings.HasPrefix(msg, "["):
		depth, esc := 0, false
		i := 0
		for ; i < len(msg); i++ {
			c := msg[i]
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '[':
				depth++
			case c == ']':
				depth--
			}
			if depth == 0 && (i+1 == len(msg) || msg[i+1] != '[') {
				break
			}
		}
		if i >= len(msg) {
			return m, false
		}
		msg = msg[i+1:]
	default:
		return m, false
	}
	msg = strings.TrimPrefix(msg, " ")
	m.Message = strings.TrimPrefix(msg, "\ufeff")
	return m, true
}
