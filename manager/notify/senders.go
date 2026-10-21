package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// Message is what a destination sends.
type Message struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Rule     string    `json:"rule"`
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	Body     string    `json:"body"`
	Subject  string    `json:"subject"`
	// Link is absolute when the public URL is configured.
	Link string `json:"link"`
}

// Destination is a configured target.
type Destination struct {
	ID         string
	Name       string
	Type       string
	Enabled    bool
	Config     map[string]string
	Secrets    map[string]string
	Severities []string
}

// Types lists the destination types and their options; secret options are
// stored apart and never returned.
var Types = map[string]struct {
	Required, Optional, Secrets []string
}{
	"webhook": {Required: []string{"url"}, Optional: []string{"method", "template", "content_type"}, Secrets: []string{"authorization", "headers"}},
	"slack":   {Secrets: []string{"webhook_url"}},
	"discord": {Secrets: []string{"webhook_url"}},
	"ntfy":    {Required: []string{"url", "topic"}, Secrets: []string{"token"}},
	"gotify":  {Required: []string{"url"}, Secrets: []string{"token"}},
	"email":   {Required: []string{"host", "from", "to"}, Optional: []string{"port", "tls", "username"}, Secrets: []string{"password"}},
	"mqtt":    {Required: []string{"url", "topic"}, Optional: []string{"username", "client_id", "qos", "retain"}, Secrets: []string{"password"}},
}

// Validate checks a destination.
func (d *Destination) Validate() error {
	t, ok := Types[d.Type]
	if !ok {
		return fmt.Errorf("unknown destination type %q", d.Type)
	}
	if d.Name == "" || len(d.Name) > 100 {
		return errors.New("a name of 1-100 characters is required")
	}
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, t.Required...), t.Optional...) {
		allowed[k] = true
	}
	for k := range d.Config {
		if !allowed[k] {
			return fmt.Errorf("%s: unknown option %q", d.Type, k)
		}
	}
	for _, k := range t.Required {
		if d.Config[k] == "" {
			return fmt.Errorf("%s: %s is required", d.Type, k)
		}
	}
	secretOK := map[string]bool{}
	for _, k := range t.Secrets {
		secretOK[k] = true
	}
	for k := range d.Secrets {
		if !secretOK[k] {
			return fmt.Errorf("%s: unknown secret %q", d.Type, k)
		}
	}
	for _, k := range []string{"url"} {
		if v := d.Config[k]; v != "" {
			u, err := url.Parse(v)
			if err != nil || u.Host == "" {
				return fmt.Errorf("%s: invalid %s", d.Type, k)
			}
		}
	}
	if tpl := d.Config["template"]; tpl != "" {
		if _, err := template.New("t").Parse(tpl); err != nil {
			return fmt.Errorf("webhook: template: %v", err)
		}
	}
	if d.Type == "email" {
		if _, err := mail.ParseAddress(d.Config["from"]); err != nil {
			return errors.New("email: invalid from address")
		}
		if _, err := mail.ParseAddressList(d.Config["to"]); err != nil {
			return errors.New("email: invalid to addresses")
		}
	}
	return nil
}

// Sender delivers messages.
type Sender struct {
	HTTP *http.Client
	// Dial opens TCP connections (SMTP, MQTT).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (s *Sender) http() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (s *Sender) dial(ctx context.Context, addr string) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// Send delivers m to d.
func (s *Sender) Send(ctx context.Context, d *Destination, m *Message) error {
	switch d.Type {
	case "webhook":
		return s.webhook(ctx, d, m)
	case "slack":
		return s.postJSON(ctx, d.Secrets["webhook_url"], nil, map[string]any{"text": "*" + m.Title + "*\n" + m.Body + linkLine(m)})
	case "discord":
		return s.postJSON(ctx, d.Secrets["webhook_url"], nil, map[string]any{"content": "**" + m.Title + "**\n" + m.Body + linkLine(m)})
	case "ntfy":
		return s.ntfy(ctx, d, m)
	case "gotify":
		return s.gotify(ctx, d, m)
	case "email":
		return s.email(ctx, d, m)
	case "mqtt":
		return s.mqtt(ctx, d, m)
	}
	return fmt.Errorf("unknown destination type %q", d.Type)
}

func linkLine(m *Message) string {
	if m.Link == "" {
		return ""
	}
	return "\n" + m.Link
}

func (s *Sender) do(req *http.Request) error {
	resp, err := s.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (s *Sender) postJSON(ctx context.Context, u string, headers http.Header, body any) error {
	if u == "" {
		return errors.New("no URL")
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	return s.do(req)
}

func (s *Sender) webhook(ctx context.Context, d *Destination, m *Message) error {
	var body []byte
	ct := d.Config["content_type"]
	if tpl := d.Config["template"]; tpl != "" {
		t, err := template.New("t").Funcs(template.FuncMap{"json": func(v any) string { b, _ := json.Marshal(v); return string(b) }}).Parse(tpl)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, m); err != nil {
			return err
		}
		body = buf.Bytes()
	} else {
		body, _ = json.Marshal(m)
		ct = "application/json"
	}
	if ct == "" {
		ct = "application/json"
	}
	method := d.Config["method"]
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, d.Config["url"], bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ct)
	if a := d.Secrets["authorization"]; a != "" {
		req.Header.Set("Authorization", a)
	}
	// headers: "Name: value" lines.
	for _, line := range strings.Split(d.Secrets["headers"], "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) != "" {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return s.do(req)
}

var ntfyPriority = map[string]string{"info": "3", "warning": "4", "critical": "5"}

func (s *Sender) ntfy(ctx context.Context, d *Destination, m *Message) error {
	u := strings.TrimRight(d.Config["url"], "/") + "/" + url.PathEscape(d.Config["topic"])
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(m.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", m.Title)
	req.Header.Set("Priority", ntfyPriority[m.Severity])
	req.Header.Set("Tags", "shield,"+m.Severity)
	if m.Link != "" {
		req.Header.Set("Click", m.Link)
	}
	if t := d.Secrets["token"]; t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	return s.do(req)
}

var gotifyPriority = map[string]int{"info": 3, "warning": 6, "critical": 9}

func (s *Sender) gotify(ctx context.Context, d *Destination, m *Message) error {
	u := strings.TrimRight(d.Config["url"], "/") + "/message"
	h := http.Header{"X-Gotify-Key": {d.Secrets["token"]}}
	body := map[string]any{"title": m.Title, "message": m.Body + linkLine(m), "priority": gotifyPriority[m.Severity]}
	if m.Link != "" {
		body["extras"] = map[string]any{"client::notification": map[string]any{"click": map[string]string{"url": m.Link}}}
	}
	return s.postJSON(ctx, u, h, body)
}

func (s *Sender) email(ctx context.Context, d *Destination, m *Message) error {
	host := d.Config["host"]
	port := d.Config["port"]
	mode := d.Config["tls"] // starttls (default) | tls | none
	if port == "" {
		port = "587"
		if mode == "tls" {
			port = "465"
		}
	}
	from, _ := mail.ParseAddress(d.Config["from"])
	to, _ := mail.ParseAddressList(d.Config["to"])
	conn, err := s.dial(ctx, net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if mode == "tls" {
		conn = tls.Client(conn, tlsCfg)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if mode == "" || mode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp: server does not offer STARTTLS (set tls: none to send in clear)")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if u := d.Config["username"]; u != "" {
		if err := c.Auth(smtp.PlainAuth("", u, d.Secrets["password"], host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	var rcpt []string
	for _, a := range to {
		if err := c.Rcpt(a.Address); err != nil {
			return err
		}
		rcpt = append(rcpt, a.String())
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	subject := "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte("[OpenPicket] "+m.Title)) + "?="
	fmt.Fprintf(w, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n",
		from.String(), strings.Join(rcpt, ", "), subject, m.Time.Format(time.RFC1123Z))
	text := m.Body + linkLine(m) + "\n\nSeverity: " + m.Severity + "\nRule: " + m.Rule + "\n"
	enc := base64.StdEncoding.EncodeToString([]byte(text))
	for len(enc) > 76 {
		fmt.Fprintf(w, "%s\r\n", enc[:76])
		enc = enc[76:]
	}
	fmt.Fprintf(w, "%s\r\n", enc)
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// mqtt publishes one message (MQTT 3.1.1, QoS 0 or 1): mqtt://host:1883,
// mqtts://host:8883.
func (s *Sender) mqtt(ctx context.Context, d *Destination, m *Message) error {
	u, err := url.Parse(d.Config["url"])
	if err != nil {
		return err
	}
	addr := u.Host
	if u.Port() == "" {
		port := "1883"
		if u.Scheme == "mqtts" {
			port = "8883"
		}
		addr = net.JoinHostPort(u.Hostname(), port)
	}
	conn, err := s.dial(ctx, addr)
	if err != nil {
		return err
	}
	if u.Scheme == "mqtts" {
		conn = tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	str := func(s string) []byte {
		b := make([]byte, 2, 2+len(s))
		binary.BigEndian.PutUint16(b, uint16(len(s)))
		return append(b, s...)
	}
	clientID := d.Config["client_id"]
	if clientID == "" {
		clientID = "openpicket-" + strconv.FormatInt(time.Now().UnixNano()%1e9, 36)
	}
	flags := byte(0x02) // clean session
	payload := str(clientID)
	if user := d.Config["username"]; user != "" {
		flags |= 0x80
		payload = append(payload, str(user)...)
		if pw := d.Secrets["password"]; pw != "" {
			flags |= 0x40
			payload = append(payload, str(pw)...)
		}
	}
	vh := append(str("MQTT"), 4, flags, 0, 30)
	if err := writePacket(conn, 0x10, append(vh, payload...)); err != nil {
		return err
	}
	typ, body, err := readPacket(conn)
	if err != nil {
		return err
	}
	if typ>>4 != 2 || len(body) < 2 || body[1] != 0 {
		return fmt.Errorf("mqtt: connection refused (code %v)", body)
	}
	qos := byte(1)
	if d.Config["qos"] == "0" {
		qos = 0
	}
	header := byte(0x30) | qos<<1
	if d.Config["retain"] == "true" {
		header |= 1
	}
	msg, _ := json.Marshal(m)
	pub := str(d.Config["topic"])
	if qos == 1 {
		pub = append(pub, 0, 1)
	}
	if err := writePacket(conn, header, append(pub, msg...)); err != nil {
		return err
	}
	if qos == 1 {
		typ, body, err := readPacket(conn)
		if err != nil {
			return err
		}
		if typ>>4 != 4 || len(body) < 2 || body[0] != 0 || body[1] != 1 {
			return errors.New("mqtt: no PUBACK")
		}
	}
	return writePacket(conn, 0xE0, nil)
}

func writePacket(w io.Writer, header byte, body []byte) error {
	b := []byte{header}
	n := len(body)
	for {
		digit := byte(n % 128)
		n /= 128
		if n > 0 {
			digit |= 0x80
		}
		b = append(b, digit)
		if n == 0 {
			break
		}
	}
	_, err := w.Write(append(b, body...))
	return err
}

func readPacket(r io.Reader) (byte, []byte, error) {
	var h [1]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n, mult := 0, 1
	for i := 0; i < 4; i++ {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n += int(b[0]&0x7f) * mult
		if b[0]&0x80 == 0 {
			break
		}
		mult *= 128
	}
	if n > 1<<16 {
		return 0, nil, errors.New("mqtt: packet too large")
	}
	body := make([]byte, n)
	_, err := io.ReadFull(r, body)
	return h[0], body, err
}
