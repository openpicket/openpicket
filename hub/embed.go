// Package hub holds OpenPicket's built-in CrowdSec content: its own parsers
// and scenarios, and the hub items they need (vendor/, pinned by
// scripts/vendor-hub.sh). The manager stores them in PostgreSQL at start
// (manager/hub); the CrowdSec image carries no content.
package hub

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/openpicket/openpicket/pkg/hubitem"
)

// BuiltinRevision numbers the built-in content. Bump it with any change
// to parsers/, scenarios/ or vendor/ (TestBuiltinSum checks): a manager
// never replaces content of a higher revision, so an older replica during
// a rolling upgrade cannot roll it back.
const BuiltinRevision = 3

//go:embed parsers scenarios vendor
var content embed.FS

// Item is a built-in item.
type Item struct {
	Type    string
	Name    string
	Stage   string
	Version string
	Content []byte
	// Description from the item.
	Description string
}

// Builtin returns the built-in items, sorted by type and name.
func Builtin() ([]Item, error) {
	var out []Item
	// OpenPicket's own: parsers/<stage>/*.yaml, scenarios/*.yaml.
	err := fs.WalkDir(content, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(p, "vendor/") || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		b, err := content.ReadFile(p)
		if err != nil {
			return err
		}
		it := Item{Content: b, Version: fmt.Sprint(BuiltinRevision)}
		parts := strings.Split(p, "/")
		switch {
		case parts[0] == hubitem.Parsers && len(parts) == 3:
			it.Type, it.Stage = hubitem.Parsers, parts[1]
		case parts[0] == hubitem.Scenarios && len(parts) == 2:
			it.Type = hubitem.Scenarios
		default:
			return fmt.Errorf("hub: unexpected file %s", p)
		}
		if it.Name, it.Description, err = header(b); err != nil {
			return fmt.Errorf("hub: %s: %w", p, err)
		}
		out = append(out, it)
		return nil
	})
	if err != nil {
		return nil, err
	}
	raw, err := content.ReadFile("vendor/manifest.json")
	if err != nil {
		return nil, err
	}
	var manifest []struct {
		Type, Name, Path, Version, Stage string
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("hub: vendor manifest: %w", err)
	}
	for _, m := range manifest {
		b, err := content.ReadFile(path.Join("vendor", m.Path))
		if err != nil {
			return nil, err
		}
		_, desc, _ := header(b)
		out = append(out, Item{Type: m.Type, Name: m.Name, Stage: m.Stage, Version: m.Version, Content: b, Description: desc})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Name < out[j].Name
	})
	for i := 1; i < len(out); i++ {
		if out[i].Type == out[i-1].Type && out[i].Name == out[i-1].Name {
			return nil, fmt.Errorf("hub: %s %s defined twice", out[i].Type, out[i].Name)
		}
	}
	for _, it := range out {
		if _, err := hubitem.ItemPath(it.Type, it.Stage, it.Name); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// header reads the name and description of a single-document item.
func header(b []byte) (string, string, error) {
	var h struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&h); err != nil {
		return "", "", err
	}
	var extra yaml.Node
	if dec.Decode(&extra) == nil {
		return "", "", fmt.Errorf("one item per file")
	}
	if !hubitem.ValidName(h.Name) {
		return "", "", fmt.Errorf("invalid name %q", h.Name)
	}
	return h.Name, h.Description, nil
}
