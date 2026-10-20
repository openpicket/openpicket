package search

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var schema = &Schema{
	Fields: map[string]Field{
		"scenario":  {SQL: "a.scenario"},
		"country":   {SQL: "a.country"},
		"events":    {SQL: "a.events_count", Kind: Number},
		"created":   {SQL: "a.created_at", Kind: Time},
		"simulated": {SQL: "a.simulated", Kind: Bool},
		"origin":    {SQL: "d.origin", Exists: "EXISTS (SELECT 1 FROM d WHERE d.alert_id = a.id AND %s)"},
	},
	Prefixes: map[string]string{"meta.": "a.meta"},
}

func compile(t *testing.T, q string) (string, []any) {
	t.Helper()
	n, err := Parse(q)
	if err != nil {
		t.Fatalf("parse %q: %v", q, err)
	}
	b := &Builder{Now: func() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) }}
	sql, err := schema.SQL(n, b)
	if err != nil {
		t.Fatalf("sql %q: %v", q, err)
	}
	return sql, b.Args
}

func TestParse(t *testing.T) {
	n, err := Parse(`ssh -country:CN (events>10 OR "port scan") meta.dst_ip=10.0.0.1 created>=24h`)
	if err != nil {
		t.Fatal(err)
	}
	want := And{[]Node{
		Term{Op: ":", Value: "ssh"},
		Not{Term{Field: "country", Op: ":", Value: "CN"}},
		Or{[]Node{Term{Field: "events", Op: ">", Value: "10"}, Term{Op: ":", Value: "port scan"}}},
		Term{Field: "meta.dst_ip", Op: "=", Value: "10.0.0.1"},
		Term{Field: "created", Op: ">=", Value: "24h"},
	}}
	if !reflect.DeepEqual(n, want) {
		t.Fatalf("got %#v", n)
	}
	for _, bad := range []string{`(a`, `a)`, `"open`, `OR a`, `a NOT`, strings.Repeat("(", 40) + "a" + strings.Repeat(")", 40)} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if n, err := Parse("   "); n != nil || err != nil {
		t.Fatal("empty query")
	}
	if n, _ := Parse("NOT a AND b"); !reflect.DeepEqual(n, And{[]Node{Not{Term{Op: ":", Value: "a"}}, Term{Op: ":", Value: "b"}}}) {
		t.Fatalf("keywords: %#v", n)
	}
}

func TestSQL(t *testing.T) {
	sql, args := compile(t, `scenario:ssh country=cn events>=5 simulated:false`)
	if sql != `(a.scenario ILIKE $1) AND (lower(a.country) = lower($2)) AND (a.events_count >= $3) AND (a.simulated = $4)` {
		t.Fatal(sql)
	}
	if !reflect.DeepEqual(args, []any{"%ssh%", "cn", 5.0, false}) {
		t.Fatal(args)
	}
	sql, args = compile(t, `created>7d -origin=cscli`)
	if sql != `(a.created_at > $1) AND (NOT COALESCE(EXISTS (SELECT 1 FROM d WHERE d.alert_id = a.id AND lower(d.origin) = lower($2)), FALSE))` {
		t.Fatal(sql)
	}
	if args[0].(time.Time) != time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) {
		t.Fatal(args)
	}
	sql, args = compile(t, `created:2026-10-01`)
	if sql != `(a.created_at >= $1 AND a.created_at < $2)` || args[1].(time.Time).Day() != 2 {
		t.Fatal(sql, args)
	}
	sql, args = compile(t, `50%_off`)
	if sql != `a.country ILIKE $1 OR a.scenario ILIKE $1 OR a.meta::text ILIKE $1` || args[0] != `%50\%\_off%` {
		t.Fatal(sql, args)
	}
	sql, _ = compile(t, `meta.dst_ip:10.0 country:""`)
	if sql != `(EXISTS (SELECT 1 FROM jsonb_array_elements_text(a.meta->$1) v WHERE v ILIKE $2)) AND (COALESCE(a.country, '') = '')` {
		t.Fatal(sql)
	}
	n, _ := Parse("bogus:1")
	if _, err := schema.SQL(n, &Builder{}); !errors.Is(err, ErrUnknownField) {
		t.Fatal(err)
	}
	n, _ = Parse("events>many")
	if _, err := schema.SQL(n, &Builder{}); err == nil {
		t.Fatal("bad number accepted")
	}
}

func TestWithoutField(t *testing.T) {
	n, _ := Parse(`country:CN -country:RU scenario:ssh`)
	if got := WithoutField(n, "country"); !reflect.DeepEqual(got, Term{Field: "scenario", Op: ":", Value: "ssh"}) {
		t.Fatalf("%#v", got)
	}
	n, _ = Parse(`country:CN`)
	if WithoutField(n, "country") != nil {
		t.Fatal("single term")
	}
	// Inside OR the clause stays.
	n, _ = Parse(`country:CN OR scenario:x`)
	if !reflect.DeepEqual(WithoutField(n, "country"), n) {
		t.Fatal("or")
	}
}
