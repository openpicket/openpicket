package manager

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/api"
	"github.com/openpicket/openpicket/pkg/version"
)

// API creates the management API server on top of this manager; cfg
// provides authentication and the UI options.
func (m *Manager) API(cfg api.Config) (*api.Server, error) {
	cfg.DB = m.opts.DB
	cfg.Geo = m.geo
	cfg.Policies = m.policies
	cfg.Settings = m.settings
	cfg.HostKey = m.HostPublicKey()
	cfg.Replica = m.opts.ReplicaID
	cfg.Version = version.Version
	cfg.Status = m.componentStatus
	if cfg.Logger == nil {
		cfg.Logger = m.log
	}
	return api.New(cfg)
}

// componentStatus reports the health of what this replica depends on.
func (m *Manager) componentStatus(ctx context.Context) []*apiv1.ComponentStatus {
	now := timestamppb.Now()
	c := func(name, state, detail string) *apiv1.ComponentStatus {
		return &apiv1.ComponentStatus{Name: name, State: state, Detail: detail, CheckedAt: now}
	}
	var out []*apiv1.ComponentStatus
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := m.opts.DB.Ping(pctx); err != nil {
		out = append(out, c("postgresql", "down", err.Error()))
	} else {
		out = append(out, c("postgresql", "ok", ""))
	}
	for _, sink := range []string{"loki", "crowdsec"} {
		if br := m.pipe.Breaker(sink); br != nil && br.Open() {
			out = append(out, c(sink, "down", "deliveries are failing; batches are retried"))
		} else {
			out = append(out, c(sink, "ok", ""))
		}
	}
	if total, up := m.cs.Health(); total == 0 {
		out = append(out, c("crowdsec-agents", "down", "no endpoint discovered"))
	} else if up < total {
		out = append(out, c("crowdsec-agents", "degraded", fmt.Sprintf("%d of %d endpoints healthy", up, total)))
	} else {
		out = append(out, c("crowdsec-agents", "ok", fmt.Sprintf("%d endpoints", total)))
	}
	if m.relay == nil {
		out = append(out, c("lapi", "disabled", "no LAPI configured: decisions are not distributed"))
	} else {
		out = append(out, c("lapi", "ok", m.opts.LAPI.URL))
	}
	geo := m.geo.Current()
	switch {
	case geo.HasCountry() && geo.HasASN():
		out = append(out, c("geoip", "ok", "country and ASN databases loaded"))
	case geo.HasCountry() || geo.HasASN():
		out = append(out, c("geoip", "degraded", "only one of the country and ASN databases is uploaded"))
	default:
		out = append(out, c("geoip", "degraded", "no MaxMind database uploaded: country and AS policies are skipped"))
	}
	out = append(out, c("agents", "ok", fmt.Sprintf("%d sessions on this replica", len(m.gw.Sessions()))))
	return out
}
