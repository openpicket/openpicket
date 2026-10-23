package hubitem

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Doc is what OpenPicket reads from an item file (every YAML document).
type Doc struct {
	// Names of the documents (scenario buckets, parser nodes...).
	Names []string
	// Data files the item reads.
	Data []DataRef
	// Members of a collection, by type.
	Members map[string][]string
	// LogTypes a scenario's filters require (evt.Meta.log_type literals).
	LogTypes []string
	// Produces: log types a parser sets (statics meta log_type).
	Produces []string
}

// DataRef is a data entry of an item.
type DataRef struct {
	SourceURL string `yaml:"source_url"`
	DestFile  string `yaml:"dest_file"`
}

// MaxItemSize bounds an item file.
const MaxItemSize = 1 << 20

var (
	logTypeEq = regexp.MustCompile(`log_type\s*==\s*["']([^"']+)["']`)
	logTypeIn = regexp.MustCompile(`log_type\s+in\s*\[([^\]]*)\]`)
	quoted    = regexp.MustCompile(`["']([^"']+)["']`)
	// compared drops the operands of comparisons from an expression: the
	// remaining literals are values it can produce.
	compared = regexp.MustCompile(`(==|!=|\bin\b|contains|startsWith|endsWith)\s*(\[[^\]]*\]|["'][^"']*["'])`)
)

// ParseDoc reads an item file of a type.
func ParseDoc(typ string, content []byte) (*Doc, error) {
	if len(content) == 0 || len(content) > MaxItemSize {
		return nil, fmt.Errorf("hubitem: item size %d", len(content))
	}
	d := &Doc{Members: map[string][]string{}}
	dec := yaml.NewDecoder(bytes.NewReader(content))
	n := 0
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("hubitem: invalid YAML: %w", err)
		}
		if len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
			continue
		}
		n++
		var raw struct {
			Name   string    `yaml:"name"`
			Filter string    `yaml:"filter"`
			Data   []DataRef `yaml:"data"`
		}
		if err := node.Decode(&raw); err != nil {
			return nil, fmt.Errorf("hubitem: invalid item: %w", err)
		}
		if raw.Name != "" {
			d.Names = append(d.Names, raw.Name)
		}
		for _, r := range raw.Data {
			if r.DestFile == "" {
				continue
			}
			if !ValidDataFile(r.DestFile) {
				return nil, fmt.Errorf("hubitem: invalid data file %q", r.DestFile)
			}
			d.Data = append(d.Data, r)
		}
		if typ == Scenarios {
			d.LogTypes = append(d.LogTypes, filterLogTypes(raw.Filter)...)
		}
		if typ == Parsers {
			collectProduces(node.Content[0], &d.Produces)
		}
		if typ == Collections {
			var members map[string]any
			_ = node.Decode(&members)
			for _, t := range Types {
				list, _ := members[t].([]any)
				for _, m := range list {
					if s, ok := m.(string); ok && ValidName(s) {
						d.Members[t] = append(d.Members[t], s)
					}
				}
			}
		}
	}
	if n == 0 {
		return nil, errors.New("hubitem: no item in the file")
	}
	d.LogTypes = sortedUnique(d.LogTypes)
	d.Produces = sortedUnique(d.Produces)
	return d, nil
}

func filterLogTypes(filter string) []string {
	var out []string
	for _, m := range logTypeEq.FindAllStringSubmatch(filter, -1) {
		out = append(out, m[1])
	}
	for _, m := range logTypeIn.FindAllStringSubmatch(filter, -1) {
		for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
			out = append(out, q[1])
		}
	}
	return out
}

// collectProduces walks a parser for statics setting log_type.
func collectProduces(n *yaml.Node, out *[]string) {
	switch n.Kind {
	case yaml.MappingNode:
		var meta, value, expr string
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i].Value, n.Content[i+1]
			switch k {
			case "meta":
				meta = v.Value
			case "value":
				value = v.Value
			case "expression":
				expr = v.Value
			}
			collectProduces(v, out)
		}
		if meta == "log_type" {
			if value != "" {
				*out = append(*out, value)
			}
			for _, q := range quoted.FindAllStringSubmatch(compared.ReplaceAllString(expr, ""), -1) {
				*out = append(*out, q[1])
			}
		}
	case yaml.SequenceNode, yaml.DocumentNode:
		for _, c := range n.Content {
			collectProduces(c, out)
		}
	}
}

func sortedUnique(s []string) []string {
	sort.Strings(s)
	return slices.Compact(s)
}

// Compatibility of a scenario with the log types the enabled parsers set.
const (
	CompatOK      = "ok"      // reads a log type a parser sets
	CompatMissing = "missing" // every log type it reads is missing
	CompatUnknown = "unknown" // its filters name no log type
)

// Compat judges a scenario against the produced log types; missing lists
// what it reads that nothing produces.
func Compat(required, produced []string) (string, []string) {
	if len(required) == 0 {
		return CompatUnknown, nil
	}
	var missing []string
	ok := false
	for _, r := range required {
		if slices.Contains(produced, r) {
			ok = true
		} else {
			missing = append(missing, r)
		}
	}
	if ok {
		return CompatOK, missing
	}
	return CompatMissing, missing
}

// DataSourceAllowed reports whether a data file may be downloaded from
// url: https on one of hosts.
func DataSourceAllowed(url string, hosts []string) bool {
	rest, ok := strings.CutPrefix(url, "https://")
	if !ok {
		return false
	}
	host, _, _ := strings.Cut(rest, "/")
	return slices.Contains(hosts, strings.ToLower(host))
}
