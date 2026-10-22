package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	suriagent "github.com/jc-lab/suricontroller/agent"
	"github.com/jc-lab/suricontroller/pkg/sshkey"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
)

// controllerSource is the channel A endpoint the manager hands out, used
// when agent.yaml has no controller section. Trusting it is trusting the
// manager, whose key the agent pins. The last one is kept in a state file
// so Suricata management resumes at boot before the manager answers.
type controllerSource struct {
	base     *url.URL
	file     string
	log      *slog.Logger
	onChange func(url string)

	mu      sync.Mutex
	raw     *dataplanev1.ControllerEndpoint
	ep      *suriagent.Endpoint
	changed chan struct{}
	waiting bool
}

var _ suriagent.EndpointSource = (*controllerSource)(nil)

// newControllerSource loads the saved endpoint, if any. base is the
// manager URL (openpicket.url) that relative endpoint URLs resolve against.
func newControllerSource(base, file string, log *slog.Logger) (*controllerSource, error) {
	b, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	s := &controllerSource{base: b, file: file, log: log, changed: make(chan struct{})}
	data, err := os.ReadFile(file)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		log.Warn("read the saved controller endpoint", "file", file, "err", err)
	default:
		var saved struct {
			URL     string `json:"url"`
			HostKey string `json:"host_key"`
		}
		if err := json.Unmarshal(data, &saved); err != nil {
			log.Warn("read the saved controller endpoint", "file", file, "err", err)
			break
		}
		raw := &dataplanev1.ControllerEndpoint{Url: saved.URL, HostKey: saved.HostKey}
		if ep, err := s.resolve(raw); err != nil {
			log.Warn("saved controller endpoint is invalid", "file", file, "err", err)
		} else {
			s.raw, s.ep = raw, ep
		}
	}
	return s, nil
}

// resolve checks an endpoint from the manager and makes its URL absolute.
func (s *controllerSource) resolve(raw *dataplanev1.ControllerEndpoint) (*suriagent.Endpoint, error) {
	key, err := sshkey.ParsePublicKey(raw.GetHostKey())
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	u, err := resolveControllerURL(s.base, raw.GetUrl())
	if err != nil {
		return nil, err
	}
	return &suriagent.Endpoint{URL: u, HostKey: key}, nil
}

// resolveControllerURL returns v when it is a ws(s):// URL, and base with
// v's path (and query) when v is a path.
func resolveControllerURL(base *url.URL, v string) (string, error) {
	switch {
	case strings.HasPrefix(v, "ws://"), strings.HasPrefix(v, "wss://"):
		if _, err := url.Parse(v); err != nil {
			return "", err
		}
		return v, nil
	case strings.HasPrefix(v, "/"):
		p, err := url.Parse(v)
		if err != nil {
			return "", err
		}
		r := *base
		r.Path, r.RawPath, r.RawQuery, r.Fragment = p.Path, p.RawPath, p.RawQuery, ""
		return r.String(), nil
	default:
		return "", fmt.Errorf("url %q: neither ws(s):// nor a path", v)
	}
}

// Endpoint implements suriagent.EndpointSource.
func (s *controllerSource) Endpoint(ctx context.Context) (suriagent.Endpoint, <-chan struct{}, error) {
	for {
		s.mu.Lock()
		ep, ch := s.ep, s.changed
		first := ep == nil && !s.waiting
		if ep == nil {
			s.waiting = true
		}
		s.mu.Unlock()
		if ep != nil {
			return *ep, ch, nil
		}
		if first {
			s.log.Info("waiting for the controller endpoint from the manager (agent.yaml has no controller section)")
		}
		select {
		case <-ctx.Done():
			return suriagent.Endpoint{}, nil, ctx.Err()
		case <-ch:
		}
	}
}

// URL returns the current controller URL ("" while unknown).
func (s *controllerSource) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ep == nil {
		return ""
	}
	return s.ep.URL
}

// Set takes an endpoint from the manager. An invalid one is ignored; a
// new one is saved and reconnects channel A.
func (s *controllerSource) Set(raw *dataplanev1.ControllerEndpoint) {
	ep, err := s.resolve(raw)
	if err != nil {
		s.log.Warn("ignoring the controller endpoint from the manager", "err", err)
		return
	}
	s.mu.Lock()
	if s.raw != nil && s.raw.GetUrl() == raw.GetUrl() && s.raw.GetHostKey() == raw.GetHostKey() {
		s.mu.Unlock()
		return
	}
	s.raw, s.ep = raw, ep
	close(s.changed)
	s.changed = make(chan struct{})
	onChange := s.onChange
	s.mu.Unlock()
	s.log.Info("controller endpoint from the manager", "url", ep.URL, "host_key", raw.GetHostKey())
	if err := s.save(raw); err != nil {
		s.log.Warn("save the controller endpoint", "file", s.file, "err", err)
	}
	if onChange != nil {
		onChange(ep.URL)
	}
}

func (s *controllerSource) save(raw *dataplanev1.ControllerEndpoint) error {
	b, err := json.Marshal(map[string]string{"url": raw.GetUrl(), "host_key": raw.GetHostKey()})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.file), 0o750); err != nil {
		return err
	}
	tmp := s.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.file)
}
