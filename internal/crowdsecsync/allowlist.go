package crowdsecsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openpicket/openpicket/pkg/allowsync"
)

// ErrNoLAPI is returned while the local API cannot be reached (starting).
var ErrNoLAPI = errors.New("the local API is not reachable yet")

// maxArgs bounds the values of one cscli command.
const maxArgs = 200

// Allowlister keeps the openpicket allowlist of the local LAPI equal to the
// states the manager pushes (allowsync). It reads the allowlist with cscli
// (through the LAPI), writes it with cscli (to the database), and reads it
// again to check: cscli reports refused values with exit status 0.
type Allowlister struct {
	// CSCLI is the cscli binary (default cscli).
	CSCLI string
	// Run runs cscli and returns its standard output; nil runs CSCLI.
	Run func(ctx context.Context, args ...string) ([]byte, error)
	Now func() time.Time

	mu sync.Mutex
}

func (a *Allowlister) run(ctx context.Context, args ...string) ([]byte, error) {
	if a.Run != nil {
		return a.Run(ctx, args...)
	}
	bin := a.CSCLI
	if bin == "" {
		bin = "cscli"
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("cscli %s: %w: %s", strings.Join(args[:min(len(args), 2)], " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (a *Allowlister) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// inspect returns the items of the allowlist, or false when it does not
// exist.
func (a *Allowlister) inspect(ctx context.Context) ([]allowsync.Item, bool, error) {
	out, err := a.run(ctx, "allowlists", "inspect", allowsync.Name, "-o", "json")
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found"):
			return nil, false, nil
		case strings.Contains(msg, "connection refused"), strings.Contains(msg, "dial tcp"):
			return nil, false, fmt.Errorf("%w: %v", ErrNoLAPI, err)
		}
		return nil, false, err
	}
	var resp struct {
		ConsoleManaged bool `json:"console_managed"`
		Items          []struct {
			Value       string    `json:"value"`
			Description string    `json:"description"`
			Expiration  time.Time `json:"expiration"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, false, fmt.Errorf("cscli allowlists inspect: %w", err)
	}
	if resp.ConsoleManaged {
		return nil, false, fmt.Errorf("allowlist %s is managed by the CrowdSec console; cscli cannot change it", allowsync.Name)
	}
	items := make([]allowsync.Item, 0, len(resp.Items))
	for _, it := range resp.Items {
		item := allowsync.Item{Value: it.Value, Description: it.Description}
		// No expiry is the zero time.
		if it.Expiration.Year() > 1 {
			exp := it.Expiration
			item.ExpiresAt = &exp
		}
		items = append(items, item)
	}
	return items, true, nil
}

// Apply makes the allowlist hold exactly st.
func (a *Allowlister) Apply(ctx context.Context, st allowsync.State) (allowsync.Result, error) {
	var res allowsync.Result
	for _, it := range st.Items {
		if err := allowsync.Check(it.Value); err != nil {
			return res, err
		}
		if len(it.Description) > 1024 {
			return res, fmt.Errorf("description of %s is longer than 1024 bytes", it.Value)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	have, exists, err := a.inspect(ctx)
	if err != nil {
		return res, err
	}
	if !exists {
		if _, err := a.run(ctx, "allowlists", "create", allowsync.Name, "--description="+allowsync.Description); err != nil {
			return res, err
		}
		res.Created = true
	}
	now := a.now()
	remove, add := allowsync.Diff(st.Items, have, now)
	for start := 0; start < len(remove); start += maxArgs {
		vals := remove[start:min(start+maxArgs, len(remove))]
		if _, err := a.run(ctx, append([]string{"allowlists", "remove", allowsync.Name}, vals...)...); err != nil {
			return res, err
		}
		res.Removed += len(vals)
	}
	// cscli takes one expiry and comment per command: group the items.
	type key struct {
		desc string
		secs int64
	}
	groups := map[key][]string{}
	for _, it := range add {
		k := key{desc: it.Description}
		if it.ExpiresAt != nil {
			k.secs = max(1, int64(math.Ceil(it.ExpiresAt.Sub(now).Seconds())))
		}
		groups[k] = append(groups[k], it.Value)
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].secs != keys[j].secs {
			return keys[i].secs < keys[j].secs
		}
		return keys[i].desc < keys[j].desc
	})
	for _, k := range keys {
		vals := groups[k]
		for start := 0; start < len(vals); start += maxArgs {
			args := append([]string{"allowlists", "add", allowsync.Name}, vals[start:min(start+maxArgs, len(vals))]...)
			if k.secs > 0 {
				args = append(args, fmt.Sprintf("--expiration=%ds", k.secs))
			}
			if k.desc != "" {
				args = append(args, "--comment="+k.desc)
			}
			if _, err := a.run(ctx, args...); err != nil {
				return res, err
			}
		}
		res.Added += len(vals)
	}
	if len(remove)+len(add) == 0 && !res.Created {
		res.Items = len(have)
		return res, nil
	}
	have, _, err = a.inspect(ctx)
	if err != nil {
		return res, err
	}
	res.Items = len(have)
	if r, ad := allowsync.Diff(st.Items, have, a.now()); len(r)+len(ad) > 0 {
		return res, fmt.Errorf("the allowlist is still out of sync after cscli (%d to remove, %d to add)", len(r), len(ad))
	}
	return res, nil
}
