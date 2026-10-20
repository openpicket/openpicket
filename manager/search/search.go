// Package search parses the UI search language and compiles it to SQL
// conditions over a table whose searchable fields are declared by the
// caller.
//
// Syntax (terms are ANDed):
//
//	ssh                  free text: any text field contains "ssh"
//	"port scan"          phrase
//	scenario:ssh         field contains (case-insensitive)
//	country=CN           field equals
//	events>10            numeric or time comparison (> >= < <=)
//	created>24h          time relative to now (also 7d, 30m) or a date
//	-country:CN          negation (also NOT)
//	country:""           field is empty
//	a OR b, (a OR b) c   alternatives and grouping
package search

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Kind is the type of a field.
type Kind int

const (
	Text Kind = iota
	Number
	Time
	Bool
)

// Field is a searchable column.
type Field struct {
	// SQL is the column expression.
	SQL  string
	Kind Kind
	// Exists, when set, is a condition template with one %s for the
	// comparison, for fields of a related table (the decisions of an
	// alert): "EXISTS (SELECT 1 FROM d WHERE d.alert = a.id AND %s)". SQL
	// is then the column inside the subquery.
	Exists string
	// NoFreeText leaves the field out of free-text search.
	NoFreeText bool
}

// Schema maps field names (and aliases) to columns.
type Schema struct {
	Fields map[string]Field
	// Prefixes map a field prefix ("meta.") to a JSONB column holding
	// arrays of strings per key: meta.dst_ip:10.0.0.1.
	Prefixes map[string]string
}

// Node is a parsed query.
type Node interface{ node() }

type (
	And  struct{ Terms []Node }
	Or   struct{ Terms []Node }
	Not  struct{ Term Node }
	Term struct {
		// Field is empty for free text.
		Field string
		Op    string // ":" "=" ">" ">=" "<" "<="
		Value string
	}
)

func (And) node()  {}
func (Or) node()   {}
func (Not) node()  {}
func (Term) node() {}

// Error is a syntax error.
type Error struct {
	Pos int
	Msg string
}

func (e *Error) Error() string { return fmt.Sprintf("search: %s at %d", e.Msg, e.Pos) }

type token struct {
	kind string // word, quoted, field, not, (, )
	text string
	pos  int
	// field terms
	field, op, value string
}

const maxQuery = 4096

// Parse parses a query; an empty query returns nil.
func Parse(q string) (Node, error) {
	if len(q) > maxQuery {
		return nil, &Error{0, "query too long"}
	}
	toks, err := lex(q)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	if len(toks) == 0 {
		return nil, nil
	}
	n, err := p.or(0)
	if err != nil {
		return nil, err
	}
	if p.i < len(p.toks) {
		return nil, &Error{p.toks[p.i].pos, "unexpected " + p.toks[p.i].text}
	}
	return n, nil
}

func lex(q string) ([]token, error) {
	var out []token
	r := []rune(q)
	i := 0
	readValue := func() (string, bool, error) {
		if i < len(r) && r[i] == '"' {
			start := i
			i++
			var b strings.Builder
			for i < len(r) && r[i] != '"' {
				if r[i] == '\\' && i+1 < len(r) {
					i++
				}
				b.WriteRune(r[i])
				i++
			}
			if i >= len(r) {
				return "", false, &Error{start, "unterminated quote"}
			}
			i++
			return b.String(), true, nil
		}
		start := i
		for i < len(r) && !unicode.IsSpace(r[i]) && r[i] != '(' && r[i] != ')' {
			i++
		}
		return string(r[start:i]), false, nil
	}
	for i < len(r) {
		c := r[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '(' || c == ')':
			out = append(out, token{kind: string(c), text: string(c), pos: i})
			i++
		case c == '-' && i+1 < len(r) && !unicode.IsSpace(r[i+1]):
			out = append(out, token{kind: "not", text: "-", pos: i})
			i++
		case c == '"':
			pos := i
			v, _, err := readValue()
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: "quoted", text: v, pos: pos})
		default:
			pos := i
			start := i
			for i < len(r) && (unicode.IsLetter(r[i]) || unicode.IsDigit(r[i]) || r[i] == '_' || r[i] == '.') {
				i++
			}
			name := string(r[start:i])
			op := ""
			if name != "" && i < len(r) {
				for _, o := range []string{">=", "<=", ":", "=", ">", "<"} {
					if strings.HasPrefix(string(r[i:min(i+2, len(r))]), o) {
						op = o
						break
					}
				}
			}
			if op != "" {
				i += len(op)
				v, _, err := readValue()
				if err != nil {
					return nil, err
				}
				out = append(out, token{kind: "field", text: string(r[start:i]), pos: pos, field: strings.ToLower(name), op: op, value: v})
				continue
			}
			i = start
			v, _, _ := readValue()
			if v == "" {
				return nil, &Error{pos, "unexpected " + string(c)}
			}
			out = append(out, token{kind: "word", text: v, pos: pos})
		}
	}
	return out, nil
}

type parser struct {
	toks []token
	i    int
}

func (p *parser) peek() *token {
	if p.i < len(p.toks) {
		return &p.toks[p.i]
	}
	return nil
}

func isKeyword(t *token, kw string) bool { return t != nil && t.kind == "word" && t.text == kw }

func (p *parser) or(depth int) (Node, error) {
	if depth > 32 {
		return nil, &Error{0, "too deeply nested"}
	}
	first, err := p.and(depth)
	if err != nil {
		return nil, err
	}
	terms := []Node{first}
	for isKeyword(p.peek(), "OR") {
		p.i++
		n, err := p.and(depth)
		if err != nil {
			return nil, err
		}
		terms = append(terms, n)
	}
	if len(terms) == 1 {
		return first, nil
	}
	return Or{terms}, nil
}

func (p *parser) and(depth int) (Node, error) {
	var terms []Node
	for {
		t := p.peek()
		if t == nil || t.kind == ")" || isKeyword(t, "OR") {
			break
		}
		if isKeyword(t, "AND") {
			p.i++
			continue
		}
		n, err := p.unary(depth)
		if err != nil {
			return nil, err
		}
		terms = append(terms, n)
	}
	switch len(terms) {
	case 0:
		pos := 0
		if t := p.peek(); t != nil {
			pos = t.pos
		}
		return nil, &Error{pos, "missing term"}
	case 1:
		return terms[0], nil
	}
	return And{terms}, nil
}

func (p *parser) unary(depth int) (Node, error) {
	t := p.peek()
	if t.kind == "not" || isKeyword(t, "NOT") {
		p.i++
		if p.peek() == nil {
			return nil, &Error{t.pos, "nothing to negate"}
		}
		n, err := p.unary(depth)
		if err != nil {
			return nil, err
		}
		return Not{n}, nil
	}
	return p.primary(depth)
}

func (p *parser) primary(depth int) (Node, error) {
	t := p.peek()
	p.i++
	switch t.kind {
	case "(":
		n, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if c := p.peek(); c == nil || c.kind != ")" {
			return nil, &Error{t.pos, "unclosed parenthesis"}
		}
		p.i++
		return n, nil
	case ")":
		return nil, &Error{t.pos, "unexpected )"}
	case "field":
		return Term{Field: t.field, Op: t.op, Value: t.value}, nil
	}
	return Term{Op: ":", Value: t.text}, nil
}

// Builder accumulates SQL arguments; conditions reference $n placeholders
// starting after the caller's own arguments.
type Builder struct {
	Args []any
	Now  func() time.Time
}

func (b *Builder) arg(v any) string {
	b.Args = append(b.Args, v)
	return "$" + strconv.Itoa(len(b.Args))
}

// ErrUnknownField is wrapped by SQL for an unknown field.
var ErrUnknownField = errors.New("unknown field")

// SQL compiles n to a condition ("TRUE" for nil).
func (s *Schema) SQL(n Node, b *Builder) (string, error) {
	if b.Now == nil {
		b.Now = time.Now
	}
	if n == nil {
		return "TRUE", nil
	}
	switch n := n.(type) {
	case And:
		return s.join(n.Terms, " AND ", b)
	case Or:
		return s.join(n.Terms, " OR ", b)
	case Not:
		c, err := s.SQL(n.Term, b)
		if err != nil {
			return "", err
		}
		return "NOT COALESCE(" + c + ", FALSE)", nil
	case Term:
		return s.term(n, b)
	}
	return "", fmt.Errorf("search: unexpected node %T", n)
}

func (s *Schema) join(terms []Node, sep string, b *Builder) (string, error) {
	parts := make([]string, 0, len(terms))
	for _, t := range terms {
		c, err := s.SQL(t, b)
		if err != nil {
			return "", err
		}
		parts = append(parts, "("+c+")")
	}
	return strings.Join(parts, sep), nil
}

func likeEscape(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(v)
}

func (s *Schema) term(t Term, b *Builder) (string, error) {
	if t.Field == "" {
		// Free text over every text field.
		pat := b.arg("%" + likeEscape(t.Value) + "%")
		var parts []string
		for _, name := range sortedFields(s.Fields) {
			f := s.Fields[name]
			if f.Kind != Text || f.NoFreeText || f.Exists != "" {
				continue
			}
			parts = append(parts, f.SQL+" ILIKE "+pat)
		}
		for _, prefix := range sortedFields(s.Prefixes) {
			parts = append(parts, s.Prefixes[prefix]+"::text ILIKE "+pat)
		}
		if len(parts) == 0 {
			return "FALSE", nil
		}
		return strings.Join(dedupe(parts), " OR "), nil
	}
	for prefix, col := range s.Prefixes {
		if key, ok := strings.CutPrefix(t.Field, prefix); ok && key != "" {
			k := b.arg(key)
			switch t.Op {
			case ":":
				if t.Value == "" {
					return "NOT (" + col + " ? " + k + ")", nil
				}
				return "EXISTS (SELECT 1 FROM jsonb_array_elements_text(" + col + "->" + k + ") v WHERE v ILIKE " + b.arg("%"+likeEscape(t.Value)+"%") + ")", nil
			case "=":
				return col + "->" + k + " ? " + b.arg(t.Value), nil
			}
			return "", fmt.Errorf("search: %s supports : and = only", t.Field)
		}
	}
	f, ok := s.Fields[t.Field]
	if !ok {
		return "", fmt.Errorf("search: %w %q", ErrUnknownField, t.Field)
	}
	cond, err := s.compare(f, t, b)
	if err != nil {
		return "", err
	}
	if f.Exists != "" {
		return fmt.Sprintf(f.Exists, cond), nil
	}
	return cond, nil
}

func (s *Schema) compare(f Field, t Term, b *Builder) (string, error) {
	switch f.Kind {
	case Text:
		switch t.Op {
		case ":":
			if t.Value == "" {
				return "COALESCE(" + f.SQL + ", '') = ''", nil
			}
			return f.SQL + " ILIKE " + b.arg("%"+likeEscape(t.Value)+"%"), nil
		case "=":
			return "lower(" + f.SQL + ") = lower(" + b.arg(t.Value) + ")", nil
		}
		return f.SQL + " " + t.Op + " " + b.arg(t.Value), nil
	case Number:
		n, err := strconv.ParseFloat(t.Value, 64)
		if err != nil {
			return "", fmt.Errorf("search: %s: %q is not a number", t.Field, t.Value)
		}
		op := t.Op
		if op == ":" {
			op = "="
		}
		return f.SQL + " " + op + " " + b.arg(n), nil
	case Bool:
		v, err := strconv.ParseBool(strings.ToLower(t.Value))
		if err != nil {
			return "", fmt.Errorf("search: %s: %q is not true/false", t.Field, t.Value)
		}
		return f.SQL + " = " + b.arg(v), nil
	case Time:
		at, day, err := ParseTime(t.Value, b.Now())
		if err != nil {
			return "", fmt.Errorf("search: %s: %v", t.Field, err)
		}
		switch t.Op {
		case ":", "=":
			if !day {
				return f.SQL + " = " + b.arg(at), nil
			}
			return "(" + f.SQL + " >= " + b.arg(at) + " AND " + f.SQL + " < " + b.arg(at.AddDate(0, 0, 1)) + ")", nil
		}
		return f.SQL + " " + t.Op + " " + b.arg(at), nil
	}
	return "", errors.New("search: unsupported field kind")
}

// ParseTime parses a time value: RFC3339, a date (day reports true), or a
// duration ago (24h, 7d, 30m, 2w).
func ParseTime(v string, now time.Time) (time.Time, bool, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, false, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", v, time.UTC); err == nil {
		return t, true, nil
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04", v, time.UTC); err == nil {
		return t, false, nil
	}
	v = strings.TrimPrefix(v, "-")
	if len(v) >= 2 {
		unit := v[len(v)-1]
		if n, err := strconv.Atoi(v[:len(v)-1]); err == nil && n >= 0 {
			switch unit {
			case 'd':
				return now.Add(-time.Duration(n) * 24 * time.Hour), false, nil
			case 'w':
				return now.Add(-time.Duration(n) * 7 * 24 * time.Hour), false, nil
			}
		}
	}
	if d, err := time.ParseDuration(v); err == nil {
		return now.Add(-d), false, nil
	}
	return time.Time{}, false, fmt.Errorf("%q is not a time (2026-01-02, RFC3339, or 24h/7d ago)", v)
}

// WithoutField removes top-level AND terms on field (facets ignore their
// own filter so other values stay visible).
func WithoutField(n Node, field string) Node {
	match := func(t Node) bool {
		if nt, ok := t.(Not); ok {
			t = nt.Term
		}
		tt, ok := t.(Term)
		return ok && tt.Field == field
	}
	switch v := n.(type) {
	case And:
		var keep []Node
		for _, t := range v.Terms {
			if !match(t) {
				keep = append(keep, t)
			}
		}
		switch len(keep) {
		case 0:
			return nil
		case 1:
			return keep[0]
		}
		return And{keep}
	case nil:
		return nil
	}
	if match(n) {
		return nil
	}
	return n
}

// Fields lists the field names a node references.
func Fields(n Node) []string {
	var out []string
	var walk func(Node)
	walk = func(n Node) {
		switch v := n.(type) {
		case And:
			for _, t := range v.Terms {
				walk(t)
			}
		case Or:
			for _, t := range v.Terms {
				walk(t)
			}
		case Not:
			walk(v.Term)
		case Term:
			if v.Field != "" {
				out = append(out, v.Field)
			}
		}
	}
	walk(n)
	return out
}

func sortedFields[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
