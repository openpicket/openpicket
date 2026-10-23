package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openpicket/openpicket/pkg/hubitem"
)

// Source is the CrowdSec hub the manager downloads from.
type Source struct {
	// BaseURL holds .index.json and the item files (default
	// https://cdn-hub.crowdsec.net/crowdsecurity/master; a mirror works).
	BaseURL string
	// DataHosts may serve data files over https (default
	// hub-data.crowdsec.net).
	DataHosts []string
	// RefreshEvery: the leader refreshes the index this often (default
	// 24h; negative disables).
	RefreshEvery time.Duration
	Client       *http.Client
}

// DefaultBaseURL of the CrowdSec hub.
const DefaultBaseURL = "https://cdn-hub.crowdsec.net/crowdsecurity/master"

// Limits of downloads.
const (
	maxIndexSize = 32 << 20
	maxDataSize  = 64 << 20
)

func (s *Source) defaults() {
	if s.BaseURL == "" {
		s.BaseURL = DefaultBaseURL
	}
	s.BaseURL = strings.TrimRight(s.BaseURL, "/")
	if len(s.DataHosts) == 0 {
		s.DataHosts = []string{"hub-data.crowdsec.net"}
	}
	if s.RefreshEvery == 0 {
		s.RefreshEvery = 24 * time.Hour
	}
	if s.Client == nil {
		s.Client = &http.Client{Timeout: 2 * time.Minute}
	}
}

// IndexEntry is an item of the hub index.
type IndexEntry struct {
	Path        string                             `json:"path"`
	Version     string                             `json:"version"`
	Versions    map[string]struct{ Digest string } `json:"versions"`
	Description string                             `json:"description"`
	Stage       string                             `json:"stage"`
	References  []string                           `json:"references"`
	// Collection members, by type.
	Parsers       []string `json:"parsers"`
	Scenarios     []string `json:"scenarios"`
	Postoverflows []string `json:"postoverflows"`
	Collections   []string `json:"collections"`
	Contexts      []string `json:"contexts"`
	AppsecConfigs []string `json:"appsec-configs"`
	AppsecRules   []string `json:"appsec-rules"`
}

// Members of a collection entry.
func (e *IndexEntry) Members() []Ref {
	var out []Ref
	add := func(t string, names []string) {
		for _, n := range names {
			out = append(out, Ref{t, n})
		}
	}
	add(hubitem.Parsers, e.Parsers)
	add(hubitem.Scenarios, e.Scenarios)
	add(hubitem.Postoverflows, e.Postoverflows)
	add(hubitem.Collections, e.Collections)
	add(hubitem.Contexts, e.Contexts)
	add(hubitem.AppsecConfigs, e.AppsecConfigs)
	add(hubitem.AppsecRules, e.AppsecRules)
	return out
}

// Index is the parsed hub index.
type Index map[string]map[string]*IndexEntry

// Hub downloads from the CrowdSec hub into the store.
type Hub struct {
	Store  *Store
	Source Source

	mu      sync.Mutex
	index   Index
	indexAt time.Time
}

// NewHub creates a hub client.
func NewHub(st *Store, src Source) *Hub {
	src.defaults()
	return &Hub{Store: st, Source: src}
}

func (h *Hub) get(ctx context.Context, url string, limit int64, header map[string]string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := h.Source.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, resp, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, resp, err
	}
	if int64(len(b)) > limit {
		return nil, resp, fmt.Errorf("GET %s: larger than %d bytes", url, limit)
	}
	return b, resp, nil
}

// RefreshIndex downloads the index (when it changed) and stores it.
func (h *Hub) RefreshIndex(ctx context.Context) (bool, error) {
	var etag string
	_ = h.Store.db.QueryRow(ctx, `SELECT hub_index_etag FROM openpicket.hub_meta WHERE id = 1 AND hub_index IS NOT NULL`).Scan(&etag)
	hdr := map[string]string{}
	if etag != "" {
		hdr["If-None-Match"] = etag
	}
	body, resp, err := h.get(ctx, h.Source.BaseURL+"/.index.json", maxIndexSize, hdr)
	if err != nil {
		return false, err
	}
	if body == nil {
		_, err := h.Store.db.Exec(ctx, `UPDATE openpicket.hub_meta SET hub_index_at = now() WHERE id = 1`)
		return false, err
	}
	var idx Index
	if err := json.Unmarshal(body, &idx); err != nil {
		return false, fmt.Errorf("hub index: %w", err)
	}
	if _, err := h.Store.db.Exec(ctx, `UPDATE openpicket.hub_meta SET hub_index = $1, hub_index_etag = $2, hub_index_at = now() WHERE id = 1`,
		body, resp.Header.Get("ETag")); err != nil {
		return false, err
	}
	h.mu.Lock()
	h.index, h.indexAt = idx, time.Time{}
	h.mu.Unlock()
	return true, nil
}

// Index returns the stored index (nil when never fetched) and when it was.
func (h *Hub) Index(ctx context.Context) (Index, time.Time, error) {
	var (
		at  *time.Time
		raw []byte
	)
	if err := h.Store.db.QueryRow(ctx, `SELECT hub_index_at FROM openpicket.hub_meta WHERE id = 1`).Scan(&at); err != nil {
		return nil, time.Time{}, err
	}
	if at == nil {
		return nil, time.Time{}, nil
	}
	h.mu.Lock()
	if h.index != nil && h.indexAt.Equal(*at) {
		idx := h.index
		h.mu.Unlock()
		return idx, *at, nil
	}
	h.mu.Unlock()
	if err := h.Store.db.QueryRow(ctx, `SELECT COALESCE(hub_index, ''::bytea) FROM openpicket.hub_meta WHERE id = 1`).Scan(&raw); err != nil {
		return nil, time.Time{}, err
	}
	var idx Index
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &idx); err != nil {
			return nil, time.Time{}, err
		}
	}
	h.mu.Lock()
	h.index, h.indexAt = idx, *at
	h.mu.Unlock()
	return idx, *at, nil
}

// RunRefresh refreshes the index periodically (leader).
func (h *Hub) RunRefresh(ctx context.Context) {
	if h.Source.RefreshEvery < 0 {
		return
	}
	log := h.Store.log
	for {
		_, at, err := h.Index(ctx)
		if err == nil && time.Since(at) >= h.Source.RefreshEvery {
			if _, err := h.RefreshIndex(ctx); err != nil && ctx.Err() == nil {
				log.Warn("refresh the CrowdSec hub index", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// Download is an item fetched from the hub, checked against the index.
type Download struct {
	Ref
	Entry   *IndexEntry
	Content []byte
	Doc     *hubitem.Doc
}

// fetch downloads an item and checks its digest.
func (h *Hub) fetch(ctx context.Context, idx Index, ref Ref) (*Download, error) {
	e := idx[ref.Type][ref.Name]
	if e == nil {
		return nil, fmt.Errorf("%w: %s %s is not in the hub index", ErrNotFound, ref.Type, ref.Name)
	}
	if !hubitem.ValidName(ref.Name) || strings.Contains(e.Path, "..") || !strings.HasSuffix(e.Path, ".yaml") {
		return nil, fmt.Errorf("%w: unexpected hub path %q", ErrInvalid, e.Path)
	}
	want := e.Versions[e.Version].Digest
	if want == "" {
		return nil, fmt.Errorf("%w: no digest for %s %s", ErrInvalid, ref.Name, e.Version)
	}
	b, _, err := h.get(ctx, h.Source.BaseURL+"/"+e.Path, hubitem.MaxItemSize, nil)
	if err != nil {
		return nil, err
	}
	if got := digest(b); got != want {
		// The hub changed between the index and the file: refresh first.
		return nil, fmt.Errorf("%s: sha256 %s, the index says %s (refresh the index)", ref.Name, got, want)
	}
	doc, err := hubitem.ParseDoc(ref.Type, b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref.Name, err)
	}
	return &Download{Ref: ref, Entry: e, Content: b, Doc: doc}, nil
}

// resolve fetches an item and, for collections, its members (nested).
func (h *Hub) resolve(ctx context.Context, idx Index, root Ref) ([]*Download, error) {
	var out []*Download
	seen := map[Ref]bool{}
	var walk func(r Ref, depth int) error
	walk = func(r Ref, depth int) error {
		if seen[r] {
			return nil
		}
		if depth > 8 {
			return fmt.Errorf("%w: collections nested too deep", ErrInvalid)
		}
		seen[r] = true
		d, err := h.fetch(ctx, idx, r)
		if err != nil {
			return err
		}
		out = append(out, d)
		for _, m := range d.Entry.Members() {
			if err := walk(m, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return out, walk(root, 0)
}

// Preview is what installing an item would bring.
type Preview struct {
	Root  *Download
	Items []*Download
	// Data files to download.
	Data []string
}

// Preview fetches an item and its members without storing them.
func (h *Hub) Preview(ctx context.Context, ref Ref) (*Preview, error) {
	idx, _, err := h.Index(ctx)
	if err != nil {
		return nil, err
	}
	if idx == nil {
		return nil, fmt.Errorf("%w: the hub index was never downloaded", ErrInvalid)
	}
	items, err := h.resolve(ctx, idx, ref)
	if err != nil {
		return nil, err
	}
	p := &Preview{Root: items[0], Items: items}
	for _, d := range items {
		for _, r := range d.Doc.Data {
			if !slices.Contains(p.Data, r.DestFile) {
				p.Data = append(p.Data, r.DestFile)
			}
		}
	}
	sort.Strings(p.Data)
	return p, nil
}

// Install downloads an item (with a collection's members and the data
// files they read) and stores it. Built-in and custom items of the same
// name are kept: the hub version does not replace them. New items take
// their default state (scenarios in simulation).
func (h *Hub) Install(ctx context.Context, ref Ref, by string) ([]Ref, error) {
	p, err := h.Preview(ctx, ref)
	if err != nil {
		return nil, err
	}
	data := map[string][]byte{}
	for _, d := range p.Items {
		for _, r := range d.Doc.Data {
			if _, ok := data[r.DestFile]; ok {
				continue
			}
			if !hubitem.DataSourceAllowed(r.SourceURL, h.Source.DataHosts) {
				return nil, fmt.Errorf("%w: %s reads %s from %s, which is not an allowed data host (%s)", ErrInvalid, d.Name, r.DestFile,
					r.SourceURL, strings.Join(h.Source.DataHosts, ", "))
			}
			b, _, err := h.get(ctx, r.SourceURL, maxDataSize, nil)
			if err != nil {
				return nil, err
			}
			data[r.DestFile] = b
		}
	}
	var installed []Ref
	err = pgx.BeginFunc(ctx, h.Store.db, func(tx pgx.Tx) error {
		for i, d := range p.Items {
			var source string
			err := tx.QueryRow(ctx, `SELECT source FROM openpicket.hub_items WHERE type = $1 AND name = $2 FOR UPDATE`, d.Type, d.Name).Scan(&source)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
			case err != nil:
				return err
			case source != hubitem.SourceHub:
				if i == 0 {
					return fmt.Errorf("%w: %s is a %s item; remove it first", ErrInvalid, d.Name, source)
				}
				continue // a member already provided another way
			}
			stage := d.Entry.Stage
			if hubitem.Staged(d.Type) && stage == "" {
				// parsers/<stage>/<author>/<name>.yaml
				if parts := strings.Split(d.Entry.Path, "/"); len(parts) == 4 {
					stage = parts[1]
				}
			}
			content := d.Content
			if d.Type == hubitem.Collections {
				content = nil
			} else if _, err := hubitem.ItemPath(d.Type, stage, d.Name); err != nil {
				return fmt.Errorf("%w: %v", ErrInvalid, err)
			}
			members, _ := json.Marshal(d.Entry.Members())
			files := []string{}
			for _, r := range d.Doc.Data {
				files = append(files, r.DestFile)
			}
			dataJSON, _ := json.Marshal(files)
			if _, err := tx.Exec(ctx, `INSERT INTO openpicket.hub_items (type, name, source, version, stage, content, digest, description, members, data, explicit, updated_by)
				VALUES ($1,$2,'hub',$3,$4,COALESCE($5, ''::bytea),$6,$7,$8,$9,$10,$11)
				ON CONFLICT (type, name) DO UPDATE SET version=excluded.version, stage=excluded.stage, content=excluded.content, digest=excluded.digest,
					description=excluded.description, members=excluded.members, data=excluded.data,
					explicit=hub_items.explicit OR excluded.explicit, updated_at=now(), updated_by=excluded.updated_by`,
				d.Type, d.Name, d.Entry.Version, stage, content, digest(d.Content), d.Entry.Description, members, dataJSON, i == 0, by); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO openpicket.hub_item_state (type, name, state, updated_by) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
				d.Type, d.Name, DefaultState(d.Type, hubitem.SourceHub), by); err != nil {
				return err
			}
			installed = append(installed, d.Ref)
		}
		for name, b := range data {
			if _, err := tx.Exec(ctx, `INSERT INTO openpicket.hub_data (dest_file, content, digest) VALUES ($1,$2,$3)
				ON CONFLICT (dest_file) DO UPDATE SET content=excluded.content, digest=excluded.digest, updated_at=now()`, name, b, digest(b)); err != nil {
				return err
			}
		}
		if err := pruneOrphans(ctx, tx); err != nil {
			return err
		}
		return bump(ctx, tx)
	})
	if err != nil {
		return nil, err
	}
	h.Store.log.Info("installed from the CrowdSec hub", "type", ref.Type, "name", ref.Name, "items", len(installed), "by", by)
	return installed, nil
}

// Remove deletes a hub or custom item. An item still in an installed
// collection only stops being explicit; a collection's members go with it
// unless installed on their own or in another collection.
func (s *Store) Remove(ctx context.Context, ref Ref, by string) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var source string
		err := tx.QueryRow(ctx, `SELECT source FROM openpicket.hub_items WHERE type = $1 AND name = $2 FOR UPDATE`, ref.Type, ref.Name).Scan(&source)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if source == hubitem.SourceBuiltin {
			return fmt.Errorf("%w: %s is built in; turn it off instead", ErrInvalid, ref.Name)
		}
		var inCollection bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openpicket.hub_items WHERE type = 'collections' AND members @> $1)`,
			fmt.Sprintf(`[{"type":%q,"name":%q}]`, ref.Type, ref.Name)).Scan(&inCollection); err != nil {
			return err
		}
		if inCollection {
			if _, err := tx.Exec(ctx, `UPDATE openpicket.hub_items SET explicit = false, updated_at = now(), updated_by = $3 WHERE type = $1 AND name = $2`,
				ref.Type, ref.Name, by); err != nil {
				return err
			}
		} else if err := deleteItem(ctx, tx, ref); err != nil {
			return err
		}
		if err := pruneOrphans(ctx, tx); err != nil {
			return err
		}
		s.log.Info("CrowdSec item removed", "type", ref.Type, "name", ref.Name, "by", by, "kept_as_member", inCollection)
		return bump(ctx, tx)
	})
}

// pruneOrphans deletes hub items installed only as collection members
// that no collection has any more, and data files no item reads.
func pruneOrphans(ctx context.Context, tx pgx.Tx) error {
	for range 8 { // nested collections free their members in rounds
		tag, err := tx.Exec(ctx, `WITH orphans AS (
				SELECT i.type, i.name FROM openpicket.hub_items i
				WHERE i.source = 'hub' AND NOT i.explicit AND NOT EXISTS (
					SELECT 1 FROM openpicket.hub_items c, jsonb_array_elements(c.members) m
					WHERE c.type = 'collections' AND m->>'type' = i.type AND m->>'name' = i.name)),
			gone AS (DELETE FROM openpicket.hub_items i USING orphans o WHERE i.type = o.type AND i.name = o.name RETURNING i.type, i.name)
			DELETE FROM openpicket.hub_item_state s USING gone g WHERE s.type = g.type AND s.name = g.name`)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			break
		}
	}
	_, err := tx.Exec(ctx, `DELETE FROM openpicket.hub_data d WHERE NOT EXISTS (
		SELECT 1 FROM openpicket.hub_items i, jsonb_array_elements_text(i.data) f WHERE f = d.dest_file)`)
	return err
}
