package manager

import (
	"context"
	"encoding/json"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/manager/dbroles"
	"github.com/openpicket/openpicket/pkg/version"
)

// keyControllerEndpoint is the setting holding the suricontroller
// endpoint the API replicas read, for the gateways to hand agents.
const keyControllerEndpoint = "controller.endpoint"

// storeControllerEndpoint records the endpoint for the gateways (role api).
func (m *Manager) storeControllerEndpoint(ep *dataplanev1.ControllerEndpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := protojson.Marshal(ep)
	if err != nil {
		return
	}
	if err := m.settings.Put(ctx, keyControllerEndpoint, json.RawMessage(raw)); err != nil {
		m.log.Warn("store controller endpoint", "err", err)
	}
}

// loadControllerEndpoint reads the endpoint the API replicas stored (role
// gateway), and hands a new one to the connected agents.
func (m *Manager) loadControllerEndpoint(ctx context.Context, push bool) {
	var raw json.RawMessage
	ok, err := m.settings.Get(ctx, keyControllerEndpoint, &raw)
	if err != nil || !ok {
		return
	}
	ep := &dataplanev1.ControllerEndpoint{}
	if protojson.Unmarshal(raw, ep) != nil {
		return
	}
	old := m.ctlEP.Swap(ep)
	if push && (old == nil || old.GetUrl() != ep.GetUrl() || old.GetHostKey() != ep.GetHostKey()) {
		m.pushController(ep)
	}
}

// controllerEndpoint is what agents get in their HelloAck.
func (m *Manager) controllerEndpoint() *dataplanev1.ControllerEndpoint {
	if m.controller != nil {
		return m.controller.Get()
	}
	return m.ctlEP.Load()
}

// publishGateway records this gateway replica: its host key (shown by the
// API replicas) and whether its database account is restricted.
func (m *Manager) publishGateway(ctx context.Context) {
	restricted, user, err := dbroles.Restricted(ctx, m.opts.DB)
	if err != nil {
		m.log.Warn("check the database account", "err", err)
	}
	if !restricted && m.opts.Role == RoleGateway {
		m.log.Warn("the gateway's database account is not restricted: it can change what the API manages (set a gateway database role)", "user", user)
	}
	down := []string{}
	for sink := range m.localSinksDown() {
		down = append(down, sink)
	}
	listeners := []string{}
	if m.syslog != nil {
		listeners = m.syslog.Listeners()
	}
	if _, err := m.opts.DB.Exec(ctx, `INSERT INTO openpicket.gateway_info (replica, host_key, db_user, db_restricted, version, sinks_down, sessions, syslog, seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (replica) DO UPDATE SET host_key = excluded.host_key, db_user = excluded.db_user, db_restricted = excluded.db_restricted,
			version = excluded.version, sinks_down = excluded.sinks_down, sessions = excluded.sessions, syslog = excluded.syslog, seen_at = now()`,
		m.opts.ReplicaID, m.HostPublicKey(), user, restricted, version.Version, down, len(m.gw.Sessions()), listeners); err != nil {
		m.log.Warn("record gateway", "err", err)
	}
}

// runGatewayInfo refreshes the record every minute; replicas gone for a
// day are removed.
func (m *Manager) runGatewayInfo(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		m.publishGateway(ctx)
		_, _ = m.opts.DB.Exec(ctx, `DELETE FROM openpicket.gateway_info WHERE seen_at < now() - interval '1 day'`)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// GatewayInfo is a gateway replica as recorded.
type GatewayInfo struct {
	Replica, HostKey, DBUser, Version string
	DBRestricted                      bool
	SinksDown                         []string
	// Syslog lists the syslog listeners ("udp [::]:5514").
	Syslog   []string
	Sessions int
	SeenAt   time.Time
}

// Gateways lists the gateway replicas seen in the last 10 minutes.
func (m *Manager) Gateways(ctx context.Context) ([]GatewayInfo, error) {
	rows, err := m.opts.DB.Query(ctx, `SELECT replica, host_key, db_user, db_restricted, version, sinks_down, sessions, syslog, seen_at FROM openpicket.gateway_info
		WHERE seen_at > now() - interval '3 minutes' ORDER BY replica`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GatewayInfo
	for rows.Next() {
		var g GatewayInfo
		if err := rows.Scan(&g.Replica, &g.HostKey, &g.DBUser, &g.DBRestricted, &g.Version, &g.SinksDown, &g.Sessions, &g.Syslog, &g.SeenAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
