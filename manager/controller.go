package manager

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	suriapiv1 "github.com/jc-lab/suricontroller/gen/suricontroller/api/v1"
	"github.com/jc-lab/suricontroller/gen/suricontroller/api/v1/apiv1connect"
	"github.com/jc-lab/suricontroller/pkg/sshkey"
	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/principal"
)

// controllerEndpoint follows the channel A endpoint handed to agents
// (HelloAck.controller): the openpicket-suricontroller host key and agent
// path, read with a viewer principal token.
type controllerEndpoint struct {
	system   apiv1connect.SystemServiceClient
	key      *sshkey.PrivateKey
	url      string
	interval time.Duration
	log      *slog.Logger
	now      func() time.Time
	current  atomic.Pointer[dataplanev1.ControllerEndpoint]
}

// principalSubject names the manager in its own principal tokens.
const principalSubject = "openpicket-manager"

func newControllerEndpoint(base *url.URL, key *sshkey.PrivateKey, override string, interval time.Duration, log *slog.Logger) *controllerEndpoint {
	if interval <= 0 {
		interval = time.Minute
	}
	api := strings.TrimSuffix(base.String(), "/") + "/api"
	return &controllerEndpoint{
		system: apiv1connect.NewSystemServiceClient(&http.Client{Timeout: 10 * time.Second}, api),
		key:    key, url: override, interval: interval, log: log.With("component", "controller-endpoint"), now: time.Now,
	}
}

// Get returns the endpoint, or nil while unknown.
func (c *controllerEndpoint) Get() *dataplanev1.ControllerEndpoint { return c.current.Load() }

// refresh reads the endpoint; it reports a change.
func (c *controllerEndpoint) refresh(ctx context.Context) (bool, error) {
	tok, err := principal.Mint(c.key.Key, principal.AudienceSuricontroller, principalSubject, principalSubject,
		[]string{principal.RoleViewer}, principal.DefaultTTL, c.now())
	if err != nil {
		return false, err
	}
	req := connect.NewRequest(&suriapiv1.GetInfoRequest{})
	req.Header().Set(principal.Header, tok)
	res, err := c.system.GetInfo(ctx, req)
	if err != nil {
		return false, err
	}
	ep := &dataplanev1.ControllerEndpoint{Url: c.url, HostKey: res.Msg.GetHostKey()}
	if ep.Url == "" {
		ep.Url = res.Msg.GetAgentPath()
		if ep.Url == "" {
			ep.Url = wire.AgentPath
		}
	}
	if proto.Equal(ep, c.current.Load()) {
		return false, nil
	}
	c.current.Store(ep)
	return true, nil
}

// run keeps the endpoint current: every 5s until known, then every
// interval. onChange runs after each change.
func (c *controllerEndpoint) run(ctx context.Context, onChange func(*dataplanev1.ControllerEndpoint)) {
	failing := false
	for {
		changed, err := c.refresh(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			if !failing {
				c.log.Warn("read the controller endpoint from openpicket-suricontroller", "err", err)
			}
			failing = true
		case err == nil:
			if failing || changed {
				c.log.Info("controller endpoint", "url", c.Get().GetUrl(), "host_key", c.Get().GetHostKey())
			}
			failing = false
			if changed {
				onChange(c.Get())
			}
		}
		wait := c.interval
		if c.Get() == nil {
			wait = min(wait, 5*time.Second)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
