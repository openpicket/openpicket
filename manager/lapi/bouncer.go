// Package lapi talks to the CrowdSec Local API: the decision stream (as a
// bouncer, for the relay) and alerts and decisions (as a watcher, for the
// UI).
package lapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Decision is a LAPI decision as returned by the stream.
type Decision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
	UUID     string `json:"uuid,omitempty"`
}

// Remaining parses the decision's remaining duration ("3h59m58s"; negative
// for expired decisions).
func (d *Decision) Remaining() (time.Duration, error) {
	return time.ParseDuration(d.Duration)
}

// Stream is one /v1/decisions/stream response.
type Stream struct {
	New     []*Decision `json:"new"`
	Deleted []*Decision `json:"deleted"`
	// ReceivedAt is when the response was received; until = ReceivedAt +
	// remaining duration.
	ReceivedAt time.Time `json:"-"`
}

// Config configures a LAPI client.
type Config struct {
	// URL of the LAPI (http://crowdsec-lapi:8080).
	URL string
	// BouncerKey authenticates the decision stream.
	BouncerKey string
	// Login/Password authenticate as a watcher (machine).
	Login    string
	Password string
	CAFile   string
	Timeout  time.Duration
	// HTTPClient overrides the client (tests).
	HTTPClient *http.Client
}

// Client is a LAPI client.
type Client struct {
	cfg    Config
	base   *url.URL
	client *http.Client
	now    func() time.Time
}

// New creates a client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.URL, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("lapi: invalid URL %q", cfg.URL)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Minute
	}
	c := &Client{cfg: cfg, base: u, client: cfg.HTTPClient, now: time.Now}
	if c.client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("lapi: no certificates in CA file")
			}
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
		}
		c.client = &http.Client{Transport: tr}
	}
	return c, nil
}

// URL returns the LAPI base URL.
func (c *Client) URL() string { return c.base.String() }

// Stream pulls the decision stream. With startup the LAPI returns every
// active decision (plus expired ones) and resets the bouncer cursor;
// without, only what changed since the last successful pull. A pull whose
// response was not read completely may still have advanced the cursor:
// callers must resync with startup after any error.
func (c *Client) Stream(ctx context.Context, startup bool) (*Stream, error) {
	if c.cfg.BouncerKey == "" {
		return nil, errors.New("lapi: no bouncer key configured")
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	u := *c.base
	u.Path += "/v1/decisions/stream"
	q := url.Values{"scopes": {"ip,range"}}
	if startup {
		q.Set("startup", "true")
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.cfg.BouncerKey)
	req.Header.Set("User-Agent", "openpicket-relay")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("lapi stream: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var s Stream
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, fmt.Errorf("lapi stream: decode: %w", err)
	}
	s.ReceivedAt = c.now()
	return &s, nil
}
