// Package misp connects OpenPicket to MISP (docs/ARCHITECTURE.md §5.5):
// repeated attackers are proposed as attributes of a monthly event, an
// operator approves them (in MISP or in the OpenPicket approval queue),
// and approved attributes become CrowdSec decisions that the edge
// enforces until they are revoked or their TTL ends.
//
// The approval state is stored in MISP only, as tags of the "openpicket"
// taxonomy: openpicket:state="proposed|approved|rejected|revoked" and
// openpicket:ttl="30d".
package misp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Tag names of the taxonomy.
const (
	TagNamespace  = "openpicket"
	StateProposed = "proposed"
	StateApproved = "approved"
	StateRejected = "rejected"
	StateRevoked  = "revoked"
)

// StateTag returns the machine tag of a state.
func StateTag(state string) string { return fmt.Sprintf(`openpicket:state="%s"`, state) }

// TTLTag returns the machine tag of a TTL.
func TTLTag(ttl string) string { return fmt.Sprintf(`openpicket:ttl="%s"`, ttl) }

// ClientConfig configures the client.
type ClientConfig struct {
	URL    string
	APIKey string
	CAFile string
	// InsecureSkipVerify disables certificate verification (self-signed
	// MISP installations).
	InsecureSkipVerify bool
	Timeout            time.Duration
	HTTPClient         *http.Client
}

// Client calls the MISP REST API.
type Client struct {
	cfg  ClientConfig
	http *http.Client
}

// New creates a client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.URL == "" || cfg.APIKey == "" {
		return nil, errors.New("misp: URL and API key are required")
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = time.Minute
	}
	c := &Client{cfg: cfg, http: cfg.HTTPClient}
	if c.http == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // opt-in
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("misp: no certificates in CA file")
			}
			tc.RootCAs = pool
		}
		tr.TLSClientConfig = tc
		c.http = &http.Client{Transport: tr}
	}
	return c, nil
}

// URL returns the MISP base URL.
func (c *Client) URL() string { return c.cfg.URL }

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.URL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("misp %s %s: status %d: %s", method, path, resp.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("misp %s %s: %w", method, path, err)
	}
	return nil
}

// Tag is an attribute or event tag.
type Tag struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Attribute is a MISP attribute.
type Attribute struct {
	ID        string `json:"id"`
	EventID   string `json:"event_id"`
	UUID      string `json:"uuid"`
	Type      string `json:"type"`
	Category  string `json:"category"`
	Value     string `json:"value"`
	ToIDS     bool   `json:"to_ids"`
	Deleted   bool   `json:"deleted"`
	Timestamp string `json:"timestamp"`
	Comment   string `json:"comment"`
	Event     *struct {
		ID   string `json:"id"`
		Info string `json:"info"`
	} `json:"Event,omitempty"`
	Tags []Tag `json:"Tag,omitempty"`
}

// Modified returns the attribute timestamp.
func (a *Attribute) Modified() time.Time {
	n, err := strconv.ParseInt(a.Timestamp, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// Machine returns the value of an openpicket:<predicate> tag.
func (a *Attribute) Machine(predicate string) string {
	prefix := TagNamespace + ":" + predicate + "="
	for _, t := range a.Tags {
		if v, ok := strings.CutPrefix(t.Name, prefix); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// SearchOpenPicket returns the IP attributes carrying any openpicket tag.
func (c *Client) SearchOpenPicket(ctx context.Context) ([]Attribute, error) {
	var res struct {
		Response struct {
			Attribute []Attribute `json:"Attribute"`
		} `json:"response"`
	}
	q := map[string]any{
		"returnFormat":     "json",
		"type":             []string{"ip-src", "ip-dst", "ip-src|port", "ip-dst|port"},
		"tags":             []string{TagNamespace + ":%"},
		"includeEventTags": false,
		"deleted":          []int{0, 1},
		"limit":            100000,
	}
	if err := c.do(ctx, http.MethodPost, "/attributes/restSearch", q, &res); err != nil {
		return nil, err
	}
	return res.Response.Attribute, nil
}

// AttachTag adds a tag to an attribute (the tag is created if missing).
func (c *Client) AttachTag(ctx context.Context, uuid, tag string) error {
	return c.do(ctx, http.MethodPost, "/tags/attachTagToObject", map[string]any{"uuid": uuid, "tag": tag, "local": false}, nil)
}

// RemoveTag removes a tag from an attribute.
func (c *Client) RemoveTag(ctx context.Context, uuid, tag string) error {
	return c.do(ctx, http.MethodPost, "/tags/removeTagFromObject", map[string]any{"uuid": uuid, "tag": tag}, nil)
}

// SetToIDS changes the IDS flag of an attribute.
func (c *Client) SetToIDS(ctx context.Context, id string, toIDS bool) error {
	return c.do(ctx, http.MethodPost, "/attributes/edit/"+id, map[string]any{"to_ids": toIDS}, nil)
}

// Event is the part of an event OpenPicket uses.
type Event struct {
	ID   string `json:"id"`
	UUID string `json:"uuid"`
	Info string `json:"info"`
}

// FindEvent returns the event with exactly this info, or nil.
func (c *Client) FindEvent(ctx context.Context, info string) (*Event, error) {
	var res struct {
		Response []struct {
			Event Event `json:"Event"`
		} `json:"response"`
	}
	if err := c.do(ctx, http.MethodPost, "/events/restSearch", map[string]any{"returnFormat": "json", "eventinfo": info, "metadata": true, "limit": 10}, &res); err != nil {
		return nil, err
	}
	for _, r := range res.Response {
		if r.Event.Info == info {
			e := r.Event
			return &e, nil
		}
	}
	return nil, nil
}

// AddEvent creates an unpublished event (distribution: this organisation).
func (c *Client) AddEvent(ctx context.Context, info string) (*Event, error) {
	var res struct {
		Event Event `json:"Event"`
	}
	in := map[string]any{"Event": map[string]any{"info": info, "distribution": 0, "threat_level_id": 3, "analysis": 0, "published": false}}
	if err := c.do(ctx, http.MethodPost, "/events/add", in, &res); err != nil {
		return nil, err
	}
	return &res.Event, nil
}

// AddAttribute adds an attribute to an event.
func (c *Client) AddAttribute(ctx context.Context, eventID string, a Attribute) (*Attribute, error) {
	var res struct {
		Attribute Attribute `json:"Attribute"`
	}
	in := map[string]any{"type": a.Type, "category": "Network activity", "value": a.Value, "to_ids": a.ToIDS, "comment": a.Comment, "distribution": 5}
	if err := c.do(ctx, http.MethodPost, "/attributes/add/"+eventID, in, &res); err != nil {
		return nil, err
	}
	return &res.Attribute, nil
}
