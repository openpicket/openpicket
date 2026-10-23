package manager

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/alerts"
	"github.com/openpicket/openpicket/manager/api"
	"github.com/openpicket/openpicket/manager/csmetrics"
	"github.com/openpicket/openpicket/manager/db"
	"github.com/openpicket/openpicket/manager/sinks/loki"
	"github.com/openpicket/openpicket/pkg/version"
)

// API creates the management API server on top of this manager; cfg
// provides authentication and the UI options.
func (m *Manager) API(cfg api.Config) (*api.Server, error) {
	cfg.DB = m.opts.DB
	cfg.Geo = m.geo
	cfg.Policies = m.policies
	cfg.Hub = m.hub
	cfg.HubRemote = m.hubRemote
	cfg.LogPrograms = m.programs
	cfg.Settings = m.settings
	cfg.HostKey = m.HostPublicKey
	cfg.Replica = m.opts.ReplicaID
	cfg.Version = version.Version
	cfg.Status = m.componentStatus
	cfg.Metrics = csmetrics.New(m.opts.CrowdSecMetrics)
	cfg.Notify = m.notify
	if m.misp != nil {
		cfg.MISP = m.misp
		cfg.MISPSettings = api.MISPSettings{ProposeMinAlerts: m.opts.MISP.ProposeMinAlerts, DefaultTTL: m.opts.MISP.DefaultTTL}
		if cfg.MISPSettings.DefaultTTL == "" {
			cfg.MISPSettings.DefaultTTL = "30d"
		}
		cfg.PokeMISP = func() {
			m.misp.Poke()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _ = m.opts.DB.Exec(ctx, `SELECT pg_notify($1, '')`, db.ChannelMISP)
		}
	}
	if m.opts.Loki.URL != "" {
		q, err := loki.NewQuerier(m.opts.Loki, m.opts.LokiQueryURL)
		if err != nil {
			return nil, err
		}
		cfg.Logs = q
		m.lokiQuery = q
	}
	if m.alerts != nil {
		cfg.Alerts = &alerts.Querier{DB: m.opts.DB, StatusMaxAge: 3 * m.opts.StatusInterval}
		cfg.AlertStore = &alerts.Store{DB: m.opts.DB}
		cfg.LAPIs = m.lapis
		cfg.Poke = m.pokeAlerts
		cfg.Resync = func() { m.pokeAlerts(resyncPayload) }
	}
	if cfg.Logger == nil {
		cfg.Logger = m.log
	}
	return api.New(cfg)
}

// resyncPayload on the alerts channel asks for a full pass.
const resyncPayload = "!full"

// pokeAlerts asks the alerts leader (this or another replica) to sync now.
func (m *Manager) pokeAlerts(instance string) {
	if instance == resyncPayload {
		m.alerts.Resync()
	} else {
		m.alerts.Poke(instance)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = m.opts.DB.Exec(ctx, `SELECT pg_notify($1, $2)`, db.ChannelAlerts, instance)
}

// localSinksDown reports the log sinks whose deliveries fail on this
// replica (a gateway).
func (m *Manager) localSinksDown() map[string]string {
	out := map[string]string{}
	if m.pipe == nil {
		return out
	}
	for _, sink := range []string{"loki", "crowdsec"} {
		if br := m.pipe.Breaker(sink); br != nil && br.Open() {
			out[sink] = "Deliveries to " + sink + " are failing on " + m.opts.ReplicaID + "; batches are retried and agents buffer."
		}
	}
	return out
}

// sinksDown reports failing log sinks: on this replica, or on the gateway
// replicas (as they recorded it) when this one runs the API only.
func (m *Manager) sinksDown() map[string]string {
	if m.opts.Role.Gateway() {
		return m.localSinksDown()
	}
	out := map[string]string{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gws, err := m.Gateways(ctx)
	if err != nil {
		return out
	}
	for _, g := range gws {
		for _, sink := range g.SinksDown {
			out[sink] = "Deliveries to " + sink + " are failing on " + g.Replica + "; batches are retried and agents buffer."
		}
	}
	return out
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
	if m.lokiQuery != nil {
		if err := m.lokiQuery.Ready(pctx); err != nil {
			out = append(out, c("loki-query", "down", err.Error()))
		} else {
			out = append(out, c("loki-query", "ok", ""))
		}
	}
	if m.search != nil {
		switch h, err := m.search.Health(pctx); {
		case err != nil:
			out = append(out, c("opensearch", "down", err.Error()))
		case h == "green" || h == "yellow":
			out = append(out, c("opensearch", "ok", "cluster "+h))
		default:
			out = append(out, c("opensearch", "degraded", "cluster "+h))
		}
	}
	down := m.sinksDown()
	for _, sink := range []string{"loki", "crowdsec"} {
		if d, ok := down[sink]; ok {
			out = append(out, c(sink, "down", d))
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
	rows, err := m.opts.DB.Query(ctx, `SELECT instance, last_poll_at, last_error FROM openpicket.alert_sync ORDER BY instance`)
	if err == nil {
		for rows.Next() {
			var (
				name, lastErr string
				poll          *time.Time
			)
			if rows.Scan(&name, &poll, &lastErr) != nil {
				continue
			}
			switch {
			case lastErr != "":
				out = append(out, c("lapi-alerts/"+name, "degraded", lastErr))
			case poll == nil || time.Since(*poll) > 5*time.Minute:
				out = append(out, c("lapi-alerts/"+name, "degraded", "alerts not synced recently"))
			default:
				out = append(out, c("lapi-alerts/"+name, "ok", "synced "+poll.UTC().Format(time.RFC3339)))
			}
		}
		rows.Close()
	}
	if m.misp != nil {
		var (
			last    *time.Time
			lastErr string
		)
		if err := m.opts.DB.QueryRow(ctx, `SELECT last_sync_at, last_error FROM openpicket.misp_sync WHERE id = 1`).Scan(&last, &lastErr); err == nil {
			switch {
			case lastErr != "":
				out = append(out, c("misp", "degraded", lastErr))
			case last == nil:
				out = append(out, c("misp", "degraded", "not synced yet"))
			default:
				out = append(out, c("misp", "ok", "synced "+last.UTC().Format(time.RFC3339)))
			}
		}
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
	if m.opts.Role.Gateway() {
		out = append(out, c("agents", "ok", fmt.Sprintf("%d sessions on this replica", len(m.gw.Sessions()))))
	}
	if m.opts.Role == RoleAPI {
		out = append(out, m.gatewayStatus(ctx))
	}
	return out
}

// gatewayStatus reports the gateway replicas (role api): whether any runs,
// and whether their database accounts are restricted.
func (m *Manager) gatewayStatus(ctx context.Context) *apiv1.ComponentStatus {
	c := func(state, detail string) *apiv1.ComponentStatus {
		return &apiv1.ComponentStatus{Name: "gateway", State: state, Detail: detail, CheckedAt: timestamppb.Now()}
	}
	gws, err := m.Gateways(ctx)
	if err != nil {
		return c("down", err.Error())
	}
	if len(gws) == 0 {
		return c("down", "no gateway replica seen in the last 3 minutes: agents cannot connect")
	}
	sessions := 0
	var open []string
	for _, g := range gws {
		sessions += g.Sessions
		if !g.DBRestricted {
			open = append(open, g.Replica+" ("+g.DBUser+")")
		}
	}
	if len(open) > 0 {
		return c("degraded", fmt.Sprintf("database privileges not separated: %s can change what the API manages (set a gateway database role)", strings.Join(open, ", ")))
	}
	return c("ok", fmt.Sprintf("%d replicas, %d agent sessions, database account restricted", len(gws), sessions))
}
