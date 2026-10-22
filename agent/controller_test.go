package agent

import (
	"context"
	"log/slog"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
)

func TestResolveControllerURL(t *testing.T) {
	base, _ := url.Parse("wss://picket.example.com:8443/agent/data/v1/connect?x=1")
	for in, want := range map[string]string{
		"/agent/v1/connect":                       "wss://picket.example.com:8443/agent/v1/connect",
		"/suri/agent/v1/connect?token=a":          "wss://picket.example.com:8443/suri/agent/v1/connect?token=a",
		"ws://suricata.lan:8080/agent/v1/connect": "ws://suricata.lan:8080/agent/v1/connect",
	} {
		if got, err := resolveControllerURL(base, in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "agent/v1/connect", "https://suricata.lan/agent/v1/connect"} {
		if _, err := resolveControllerURL(base, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestControllerSource(t *testing.T) {
	file := filepath.Join(t.TempDir(), "openpicket", "controller.json")
	log := slog.New(slog.DiscardHandler)
	base := "wss://picket.example.com/agent/data/v1/connect"
	s, err := newControllerSource(base, file, log)
	if err != nil {
		t.Fatal(err)
	}
	if s.URL() != "" {
		t.Fatal("endpoint known before the manager sent one")
	}

	// Endpoint waits until the manager sends one.
	got := make(chan string, 1)
	go func() {
		ep, _, err := s.Endpoint(context.Background())
		if err == nil {
			got <- ep.URL
		}
	}()
	k1, _ := sshkey.Generate()
	var changes []string
	s.onChange = func(u string) { changes = append(changes, u) }
	s.Set(&dataplanev1.ControllerEndpoint{Url: "/agent/v1/connect", HostKey: k1.Public("suri-controller").String()})
	select {
	case u := <-got:
		if u != "wss://picket.example.com/agent/v1/connect" {
			t.Fatalf("url = %s", u)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Endpoint did not return")
	}

	ep, changed, _ := s.Endpoint(context.Background())
	if ep.HostKey.Fingerprint() != k1.Public("x").Fingerprint() {
		t.Fatal("host key")
	}
	// The same endpoint again is no change; an invalid one is ignored.
	s.Set(&dataplanev1.ControllerEndpoint{Url: "/agent/v1/connect", HostKey: k1.Public("suri-controller").String()})
	s.Set(&dataplanev1.ControllerEndpoint{Url: "/agent/v1/connect", HostKey: "garbage"})
	s.Set(&dataplanev1.ControllerEndpoint{Url: "agent/v1/connect", HostKey: k1.Public("suri-controller").String()})
	select {
	case <-changed:
		t.Fatal("changed without a new endpoint")
	default:
	}
	// A new key closes the channel.
	k2, _ := sshkey.Generate()
	s.Set(&dataplanev1.ControllerEndpoint{Url: "/agent/v1/connect", HostKey: k2.Public("suri-controller").String()})
	select {
	case <-changed:
	default:
		t.Fatal("no change signalled")
	}
	if len(changes) != 2 {
		t.Fatalf("onChange calls = %v", changes)
	}

	// The last endpoint is back after a restart, resolved against the
	// current manager URL.
	s2, err := newControllerSource("ws://10.0.0.1:8080/agent/data/v1/connect", file, log)
	if err != nil {
		t.Fatal(err)
	}
	ep2, _, _ := s2.Endpoint(context.Background())
	if ep2.URL != "ws://10.0.0.1:8080/agent/v1/connect" || ep2.HostKey.Fingerprint() != k2.Public("x").Fingerprint() {
		t.Fatalf("restored endpoint = %s %s", ep2.URL, ep2.HostKey.Fingerprint())
	}
}
