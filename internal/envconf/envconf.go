// Package envconf reads configuration from environment variables. Secrets
// also accept NAME_FILE pointing at a file (Kubernetes Secret mounts).
package envconf

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env reads variables with a common prefix and collects parse errors.
type Env struct {
	prefix string
	errs   []error
	lookup func(string) (string, bool)
	read   func(string) ([]byte, error)
}

// New returns a reader for variables starting with prefix.
func New(prefix string) *Env {
	return &Env{prefix: prefix, lookup: os.LookupEnv, read: os.ReadFile}
}

func (e *Env) get(name string) (string, bool) { return e.lookup(e.prefix + name) }

// String sets *dst when the variable is set.
func (e *Env) String(name string, dst *string) {
	if v, ok := e.get(name); ok {
		*dst = v
	}
}

// Secret sets *dst from the variable or from the file named by NAME_FILE.
func (e *Env) Secret(name string, dst *string) {
	if v, ok := e.get(name); ok {
		*dst = v
		return
	}
	if p, ok := e.get(name + "_FILE"); ok && p != "" {
		b, err := e.read(p)
		if err != nil {
			e.errs = append(e.errs, fmt.Errorf("%s%s_FILE: %w", e.prefix, name, err))
			return
		}
		*dst = strings.TrimRight(string(b), "\r\n")
	}
}

// Bool sets *dst from 1/0/true/false/yes/no.
func (e *Env) Bool(name string, dst *bool) {
	v, ok := e.get(name)
	if !ok || v == "" {
		return
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		*dst = true
	case "0", "false", "no", "off":
		*dst = false
	default:
		e.errs = append(e.errs, fmt.Errorf("%s%s: invalid boolean %q", e.prefix, name, v))
	}
}

// Int sets *dst.
func (e *Env) Int(name string, dst *int) {
	v, ok := e.get(name)
	if !ok || v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s%s: invalid integer %q", e.prefix, name, v))
		return
	}
	*dst = n
}

// Duration sets *dst ("30s", "5m").
func (e *Env) Duration(name string, dst *time.Duration) {
	v, ok := e.get(name)
	if !ok || v == "" {
		return
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s%s: invalid duration %q", e.prefix, name, v))
		return
	}
	*dst = d
}

// List sets *dst from a comma separated list.
func (e *Env) List(name string, dst *[]string) {
	v, ok := e.get(name)
	if !ok {
		return
	}
	*dst = nil
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*dst = append(*dst, s)
		}
	}
}

// Err returns the collected errors.
func (e *Env) Err() error { return errors.Join(e.errs...) }
