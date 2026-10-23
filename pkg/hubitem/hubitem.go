// Package hubitem describes CrowdSec hub content as OpenPicket manages it
// (docs/ARCHITECTURE.md §8): items kept in PostgreSQL, rendered into a
// bundle of files that the log processors' sync process writes under the
// CrowdSec configuration and data directories.
package hubitem

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Item types, as the hub index names them.
const (
	Parsers       = "parsers"
	Postoverflows = "postoverflows"
	Scenarios     = "scenarios"
	Collections   = "collections"
	Contexts      = "contexts"
	AppsecConfigs = "appsec-configs"
	AppsecRules   = "appsec-rules"
)

// Types are the item types managed, in display order.
var Types = []string{Collections, Parsers, Scenarios, Postoverflows, Contexts, AppsecConfigs, AppsecRules}

// Staged types live in a stage directory (s00-raw, s01-parse...).
func Staged(typ string) bool { return typ == Parsers || typ == Postoverflows }

// States of an item.
const (
	Enabled    = "enabled"
	Simulation = "simulation" // scenarios: alerts without decisions
	Disabled   = "disabled"
)

// ValidState reports whether state applies to an item type.
func ValidState(typ, state string) bool {
	switch state {
	case Enabled, Disabled:
		return true
	case Simulation:
		return typ == Scenarios || typ == Collections
	}
	return false
}

// Sources of an item.
const (
	SourceBuiltin = "builtin" // shipped with OpenPicket
	SourceHub     = "hub"     // downloaded from the CrowdSec hub
	SourceCustom  = "custom"  // uploaded by a user
)

var (
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,128}$`)
	stageRe = regexp.MustCompile(`^s[0-9]{2}-[a-z0-9-]{1,32}$`)
	fileRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

// ValidType reports whether typ is managed.
func ValidType(typ string) bool { return slices.Contains(Types, typ) }

// ValidName reports whether name has the hub's "author/name" form.
func ValidName(name string) bool { return nameRe.MatchString(name) && !strings.Contains(name, "..") }

// ValidStage reports whether stage names a stage directory.
func ValidStage(stage string) bool { return stageRe.MatchString(stage) }

// ItemPath is where an item is written, relative to the CrowdSec
// configuration directory; collections are not written (CrowdSec does not
// read them: their members are items of their own).
func ItemPath(typ, stage, name string) (string, error) {
	if !ValidType(typ) || !ValidName(name) {
		return "", fmt.Errorf("hubitem: invalid item %s %q", typ, name)
	}
	if typ == Collections {
		return "", errors.New("hubitem: collections are not written")
	}
	// author/name -> author-name.yaml: one directory per type, as cscli
	// lays out local items.
	file := strings.Replace(name, "/", "-", 1) + ".yaml"
	if Staged(typ) {
		if !ValidStage(stage) {
			return "", fmt.Errorf("hubitem: invalid stage %q for %s", stage, name)
		}
		return path.Join(typ, stage, file), nil
	}
	return path.Join(typ, file), nil
}

// ValidDataFile reports whether name is a safe data file name (the
// dest_file of a data entry, relative to the data directory).
func ValidDataFile(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if !fileRe.MatchString(part) || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// ManagedDirs are the configuration subdirectories the sync process owns:
// everything in them comes from bundles.
var ManagedDirs = []string{Parsers, Postoverflows, Scenarios, Contexts, AppsecConfigs, AppsecRules}

// File is one file of a bundle.
type File struct {
	// Path is relative to the configuration directory (items) or the data
	// directory (data).
	Path    string `json:"path"`
	Content []byte `json:"content"`
}

// Bundle is the content a log processor runs.
type Bundle struct {
	Revision int64  `json:"revision"`
	Items    []File `json:"items"`
	Data     []File `json:"data"`
	// Simulation lists the scenarios in simulation mode.
	Simulation []string `json:"simulation"`
}

// Check validates every path of a bundle.
func (b *Bundle) Check() error {
	seen := map[string]bool{}
	for _, f := range b.Items {
		dir, _, ok := strings.Cut(f.Path, "/")
		if !ok || !slices.Contains(ManagedDirs, dir) || !strings.HasSuffix(f.Path, ".yaml") || path.Clean(f.Path) != f.Path ||
			strings.Contains(f.Path, "..") || seen["i:"+f.Path] {
			return fmt.Errorf("hubitem: invalid item path %q", f.Path)
		}
		seen["i:"+f.Path] = true
	}
	for _, f := range b.Data {
		if !ValidDataFile(f.Path) || seen["d:"+f.Path] {
			return fmt.Errorf("hubitem: invalid data path %q", f.Path)
		}
		seen["d:"+f.Path] = true
	}
	for _, s := range b.Simulation {
		if !ValidName(s) {
			return fmt.Errorf("hubitem: invalid scenario name %q", s)
		}
	}
	return nil
}

// Status is what a log processor reports.
type Status struct {
	// Revision applied (0: none yet; CrowdSec is not running).
	Revision int64 `json:"revision"`
	// Running: CrowdSec runs with the revision.
	Running bool `json:"running"`
	// Error of the last bundle refused (its revision in ErrorRevision).
	Error         string `json:"error,omitempty"`
	ErrorRevision int64  `json:"error_revision,omitempty"`
}

// Sync protocol paths on the log processor (port 8082).
const (
	PathStatus = "/hub/status"
	PathBundle = "/hub/bundle"
)
