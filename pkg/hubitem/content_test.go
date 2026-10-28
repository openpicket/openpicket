package hubitem

import (
	"slices"
	"strings"
	"testing"
)

func TestParseDoc(t *testing.T) {
	sc := []byte(`type: trigger
name: a/major
filter: "evt.Meta.log_type == 'suricata_alert' && evt.Meta.x == '1'"
data:
  - source_url: https://hub-data.crowdsec.net/web/x.txt
    dest_file: x.txt
---
type: leaky
name: a/high
filter: evt.Meta.log_type in ["http_access-log", "http_error-log"]
`)
	d, err := ParseDoc(Scenarios, sc)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.Names, []string{"a/major", "a/high"}) || len(d.Data) != 1 || d.Data[0].DestFile != "x.txt" ||
		!slices.Equal(d.LogTypes, []string{"http_access-log", "http_error-log", "suricata_alert"}) {
		t.Fatalf("doc = %+v", d)
	}
	p, err := ParseDoc(Parsers, []byte(`name: a/p
filter: evt.Parsed.program == "x"
nodes:
  - grok: {}
    statics:
      - meta: log_type
        value: http_access-log
statics:
  - meta: log_type
    expression: 'evt.X == "a" ? "suricata_alert" : "suricata_anomaly"'
`))
	if err != nil || !slices.Equal(p.Produces, []string{"http_access-log", "suricata_alert", "suricata_anomaly"}) {
		t.Fatalf("parser = %+v %v", p, err)
	}
	c, err := ParseDoc(Collections, []byte("name: a/c\nparsers: [a/p]\nscenarios:\n  - a/s\ncollections: [b/c]\n"))
	if err != nil || !slices.Equal(c.Members[Parsers], []string{"a/p"}) || !slices.Equal(c.Members[Collections], []string{"b/c"}) {
		t.Fatalf("collection = %+v %v", c, err)
	}
	if _, err := ParseDoc(Scenarios, []byte("name: a/x\ndata: [{dest_file: ../../etc/passwd}]\n")); err == nil {
		t.Fatal("unsafe data file accepted")
	}
	if _, err := ParseDoc(Scenarios, []byte("- just a list\n")); err == nil {
		t.Fatal("no item accepted")
	}
}

func TestCompat(t *testing.T) {
	if s, m := Compat([]string{"suricata_alert"}, []string{"suricata_alert", "openpicket_nflog"}); s != CompatOK || len(m) != 0 {
		t.Fatal(s, m)
	}
	if s, m := Compat([]string{"http_access-log"}, []string{"suricata_alert"}); s != CompatMissing || !slices.Equal(m, []string{"http_access-log"}) {
		t.Fatal(s, m)
	}
	if s, _ := Compat(nil, nil); s != CompatUnknown {
		t.Fatal(s)
	}
	for url, ok := range map[string]bool{
		"https://hub-data.crowdsec.net/web/x.txt": true, "http://hub-data.crowdsec.net/x": false, "https://evil.example/x": false,
		"https://hub-data.crowdsec.net.evil/x": false,
	} {
		if DataSourceAllowed(url, []string{"hub-data.crowdsec.net"}) != ok {
			t.Errorf("%s", url)
		}
	}
}

func TestParserPrograms(t *testing.T) {
	for filter, want := range map[string]map[string]bool{
		`evt.Parsed.program startsWith 'nginx'`:                   {"nginx": true, "nginx-ingress": true, "apache2": false},
		`evt.Parsed.program in ['sshd-session', 'sshd']`:          {"sshd": true, "sshd-session": true, "ssh": false},
		`evt.Parsed.program == "postgres" && evt.Parsed.x == "y"`: {"postgres": true, "postgresql": false},
		`evt.Parsed.program matches '^(httpd|apache2)$'`:          {"httpd": true, "apache2": true, "nginx": false},
		`evt.Line.Labels.type == 'syslog'`:                        {"syslog": false},
	} {
		d, err := ParseDoc(Parsers, []byte("name: a/p\nfilter: \""+strings.ReplaceAll(filter, `"`, `\"`)+"\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		for program, ok := range want {
			if d.HandlesProgram(program) != ok {
				t.Errorf("%s: %s = %v", filter, program, !ok)
			}
		}
	}
}
