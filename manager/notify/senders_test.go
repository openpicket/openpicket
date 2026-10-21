package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var msg = &Message{ID: 7, Time: time.Unix(1_800_000_000, 0), Rule: "bans", Severity: "warning", Title: "Ban 198.51.100.4", Body: "ssh-bf", Subject: "198.51.100.4",
	Link: "https://op.example/ip/198.51.100.4"}

type captured struct {
	path    string
	headers http.Header
	body    string
}

func capture(t *testing.T) (*httptest.Server, chan captured) {
	ch := make(chan captured, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- captured{r.URL.Path, r.Header, string(b)}
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

func TestHTTPSenders(t *testing.T) {
	srv, ch := capture(t)
	s := &Sender{}
	ctx := context.Background()
	cases := []struct {
		d     Destination
		check func(c captured) bool
	}{
		{Destination{Type: "webhook", Config: map[string]string{"url": srv.URL + "/hook"}, Secrets: map[string]string{"authorization": "Bearer x", "headers": "X-A: 1\nX-B: 2"}},
			func(c captured) bool {
				var m Message
				_ = json.Unmarshal([]byte(c.body), &m)
				return m.Subject == "198.51.100.4" && c.headers.Get("Authorization") == "Bearer x" && c.headers.Get("X-B") == "2"
			}},
		{Destination{Type: "webhook", Config: map[string]string{"url": srv.URL, "template": `{"text":{{json .Title}},"sev":"{{.Severity}}"}`}},
			func(c captured) bool { return c.body == `{"text":"Ban 198.51.100.4","sev":"warning"}` }},
		{Destination{Type: "slack", Secrets: map[string]string{"webhook_url": srv.URL + "/slack"}},
			func(c captured) bool { return strings.Contains(c.body, `"text":"*Ban 198.51.100.4*`) }},
		{Destination{Type: "discord", Secrets: map[string]string{"webhook_url": srv.URL + "/discord"}},
			func(c captured) bool { return strings.Contains(c.body, `"content":"**Ban`) }},
		{Destination{Type: "ntfy", Config: map[string]string{"url": srv.URL, "topic": "op alerts"}, Secrets: map[string]string{"token": "tk"}},
			func(c captured) bool {
				return c.path == "/op alerts" && c.headers.Get("Priority") == "4" && c.headers.Get("Click") == msg.Link && c.headers.Get("Authorization") == "Bearer tk"
			}},
		{Destination{Type: "gotify", Config: map[string]string{"url": srv.URL}, Secrets: map[string]string{"token": "gk"}},
			func(c captured) bool {
				return c.path == "/message" && c.headers.Get("X-Gotify-Key") == "gk" && strings.Contains(c.body, `"priority":6`)
			}},
	}
	for _, tc := range cases {
		if err := s.Send(ctx, &tc.d, msg); err != nil {
			t.Fatalf("%s: %v", tc.d.Type, err)
		}
		if c := <-ch; !tc.check(c) {
			t.Errorf("%s: %+v", tc.d.Type, c)
		}
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 500) }))
	defer bad.Close()
	if err := s.Send(ctx, &Destination{Type: "webhook", Config: map[string]string{"url": bad.URL}}, msg); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("failing webhook: %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, d := range []Destination{
		{Name: "x", Type: "telegram"},
		{Name: "x", Type: "webhook"},
		{Name: "x", Type: "webhook", Config: map[string]string{"url": "http://h", "bogus": "1"}},
		{Name: "x", Type: "webhook", Config: map[string]string{"url": "http://h", "template": "{{"}},
		{Name: "x", Type: "email", Config: map[string]string{"host": "h", "from": "not an address", "to": "a@b.c"}},
		{Name: "x", Type: "slack", Secrets: map[string]string{"token": "x"}},
	} {
		if err := d.Validate(); err == nil {
			t.Errorf("%+v accepted", d)
		}
	}
	ok := Destination{Name: "x", Type: "email", Config: map[string]string{"host": "h", "from": "OpenPicket <op@example.com>", "to": "a@b.c, d@e.f"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEmail(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
		w("220 fake ESMTP")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					w("250 queued")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				w("250-fake")
				w("250 AUTH PLAIN")
			case strings.HasPrefix(cmd, "AUTH PLAIN"):
				w("235 ok")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				w("250 ok")
			case cmd == "DATA":
				inData = true
				w("354 go")
			case cmd == "QUIT":
				w("221 bye")
				got <- data.String()
				return
			default:
				w("502 ?")
			}
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	// PLAIN auth over a clear connection is only allowed to localhost by
	// net/smtp, which is what this test uses.
	d := &Destination{Type: "email", Config: map[string]string{"host": host, "port": port, "tls": "none", "from": "op@example.com", "to": "soc@example.com",
		"username": "op"}, Secrets: map[string]string{"password": "pw"}}
	if err := (&Sender{}).Send(context.Background(), d, msg); err != nil {
		t.Fatal(err)
	}
	mail := <-got
	if !strings.Contains(mail, "To: <soc@example.com>") || !strings.Contains(mail, "Subject: =?UTF-8?B?") {
		t.Fatalf("mail:\n%s", mail)
	}
	body := mail[strings.Index(mail, "\r\n\r\n")+4:]
	dec, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(body), "\r\n", ""))
	if !strings.Contains(string(dec), "ssh-bf") || !strings.Contains(string(dec), msg.Link) {
		t.Fatalf("body: %q", dec)
	}
	// STARTTLS is required unless disabled.
	d.Config["tls"] = ""
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln2.Close()
	go func() {
		c, err := ln2.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		_, _ = io.WriteString(c, "220 fake\r\n")
		_, _ = r.ReadString('\n')
		_, _ = io.WriteString(c, "250 fake\r\n")
		_, _ = r.ReadString('\n')
	}()
	_, d.Config["port"], _ = net.SplitHostPort(ln2.Addr().String())
	if err := (&Sender{}).Send(context.Background(), d, msg); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("no STARTTLS: %v", err)
	}
}

func TestMQTT(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	type pub struct {
		user, pass, topic string
		payload           []byte
	}
	got := make(chan pub, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var p pub
		typ, body, err := readPacket(c)
		if err != nil || typ != 0x10 {
			return
		}
		// Variable header: "MQTT", level, flags, keepalive; then client id,
		// username, password.
		read := func(b []byte) (string, []byte) {
			n := int(b[0])<<8 | int(b[1])
			return string(b[2 : 2+n]), b[2+n:]
		}
		_, rest := read(body)
		rest = rest[4:]
		_, rest = read(rest)
		p.user, rest = read(rest)
		p.pass, _ = read(rest)
		_ = writePacket(c, 0x20, []byte{0, 0})
		typ, body, err = readPacket(c)
		if err != nil || typ&0xf0 != 0x30 {
			return
		}
		p.topic, rest = read(body)
		p.payload = rest[2:]
		_ = writePacket(c, 0x40, rest[:2])
		got <- p
	}()
	d := &Destination{Type: "mqtt", Config: map[string]string{"url": "mqtt://" + ln.Addr().String(), "topic": "openpicket/alerts", "username": "u"},
		Secrets: map[string]string{"password": "p"}}
	if err := (&Sender{}).Send(context.Background(), d, msg); err != nil {
		t.Fatal(err)
	}
	p := <-got
	var m Message
	if p.user != "u" || p.pass != "p" || p.topic != "openpicket/alerts" || json.Unmarshal(p.payload, &m) != nil || m.Title != msg.Title {
		t.Fatalf("publish: %+v", p)
	}
}
