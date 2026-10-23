package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jc-lab/suricontroller/pkg/nodeid"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/syslog"
	"github.com/openpicket/openpicket/pkg/record"
)

type syslogService struct{ s *Server }

const (
	maxSyslogSources  = 64
	maxSyslogPrograms = 64
)

func (y *syslogService) ListSyslogDevices(ctx context.Context, _ *connect.Request[apiv1.ListSyslogDevicesRequest]) (*connect.Response[apiv1.ListSyslogDevicesResponse], error) {
	rows, err := y.s.cfg.DB.Query(ctx, `SELECT d.id, d.description, d.sources, d.labels, d.programs, d.enabled, d.updated_at, d.updated_by,
			COALESCE(s.messages, 0), s.last_seen, COALESCE(p.programs, '{}')
		FROM openpicket.syslog_devices d
		LEFT JOIN (SELECT device_id, sum(messages)::bigint AS messages, max(last_seen) AS last_seen FROM openpicket.syslog_sources GROUP BY device_id) s ON s.device_id = d.id
		LEFT JOIN (SELECT node_id, array_agg(program ORDER BY program) AS programs FROM openpicket.log_programs GROUP BY node_id) p ON p.node_id = d.id
		ORDER BY d.id`)
	if err != nil {
		return nil, toConnectError(err)
	}
	defer rows.Close()
	res := &apiv1.ListSyslogDevicesResponse{}
	for rows.Next() {
		d, err := scanSyslogDevice(rows)
		if err != nil {
			return nil, toConnectError(err)
		}
		res.Devices = append(res.Devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(res), nil
}

func scanSyslogDevice(row pgx.Row) (*apiv1.SyslogDevice, error) {
	d := &apiv1.SyslogDevice{}
	var sources []netip.Prefix
	var labels, programs []byte
	var updated time.Time
	var last *time.Time
	if err := row.Scan(&d.Id, &d.Description, &sources, &labels, &programs, &d.Enabled, &updated, &d.UpdatedBy, &d.Messages, &last, &d.SeenPrograms); err != nil {
		return nil, err
	}
	for _, p := range sources {
		if p.IsSingleIP() {
			d.Sources = append(d.Sources, p.Addr().String())
		} else {
			d.Sources = append(d.Sources, p.String())
		}
	}
	_ = json.Unmarshal(labels, &d.Labels)
	_ = json.Unmarshal(programs, &d.Programs)
	d.UpdatedAt = timestamppb.New(updated)
	if last != nil {
		d.LastSeen = timestamppb.New(*last)
	}
	return d, nil
}

// validSyslogDevice checks a device and returns its sources as networks.
func validSyslogDevice(d *apiv1.SyslogDevice) ([]netip.Prefix, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: device", errInvalid)
	}
	if err := nodeid.Validate(d.GetId()); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalid, err)
	}
	if len(d.GetDescription()) > 512 {
		return nil, fmt.Errorf("%w: description longer than 512 bytes", errInvalid)
	}
	if n := len(d.GetSources()); n == 0 || n > maxSyslogSources {
		return nil, fmt.Errorf("%w: 1 to %d source addresses or networks", errInvalid, maxSyslogSources)
	}
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, s := range d.GetSources() {
		p, err := parseSource(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("%w: source %q: %v", errInvalid, s, err)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if err := validateLabels(d.GetLabels()); err != nil {
		return nil, err
	}
	if len(d.GetPrograms()) > maxSyslogPrograms {
		return nil, fmt.Errorf("%w: at most %d program names", errInvalid, maxSyslogPrograms)
	}
	for tag, prog := range d.GetPrograms() {
		if tag == "" || len(tag) > 128 || strings.IndexFunc(tag, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return nil, fmt.Errorf("%w: syslog tag %q", errInvalid, tag)
		}
		if prog == "" || record.NormalizeProgram(prog) != prog {
			return nil, fmt.Errorf("%w: program %q of %q: lowercase letters, digits, '.', '_' and '-' (at most %d)", errInvalid, prog, tag, record.MaxProgram)
		}
	}
	return out, nil
}

// parseSource reads an address or a network.
func parseSource(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		a, bits := p.Addr(), p.Bits()
		if a.Is4In6() {
			a, bits = a.Unmap(), max(bits-96, 0)
		}
		if bits == 0 {
			return netip.Prefix{}, errors.New("a default route matches every sender")
		}
		return netip.PrefixFrom(a, bits).Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func (y *syslogService) PutSyslogDevice(ctx context.Context, req *connect.Request[apiv1.PutSyslogDeviceRequest]) (*connect.Response[apiv1.PutSyslogDeviceResponse], error) {
	d := req.Msg.GetDevice()
	sources, err := validSyslogDevice(d)
	if err != nil {
		return nil, toConnectError(err)
	}
	labels, _ := json.Marshal(nonNil(d.GetLabels()))
	programs, _ := json.Marshal(nonNil(d.GetPrograms()))
	err = pgx.BeginFunc(ctx, y.s.cfg.DB, func(tx pgx.Tx) error {
		var node bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM openpicket.nodes WHERE id = $1)`, d.GetId()).Scan(&node); err != nil {
			return err
		}
		if node {
			return fmt.Errorf("%w: a node with id %q exists", errExists, d.GetId())
		}
		var other string
		err := tx.QueryRow(ctx, `SELECT id FROM openpicket.syslog_devices WHERE id <> $1 AND sources && $2::cidr[] LIMIT 1`, d.GetId(), sources).Scan(&other)
		if err == nil {
			return fmt.Errorf("%w: device %q has one of these sources", errInvalid, other)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if req.Msg.GetCreate() {
			_, err := tx.Exec(ctx, `INSERT INTO openpicket.syslog_devices (id, description, sources, labels, programs, enabled, updated_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				d.GetId(), d.GetDescription(), sources, labels, programs, d.GetEnabled(), by(ctx))
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: device %q", errExists, d.GetId())
			}
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE openpicket.syslog_devices SET description = $2, sources = $3, labels = $4, programs = $5, enabled = $6,
				updated_at = now(), updated_by = $7 WHERE id = $1`,
			d.GetId(), d.GetDescription(), sources, labels, programs, d.GetEnabled(), by(ctx))
		if err == nil && tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: device %q", errNotFound, d.GetId())
		}
		return err
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	row := y.s.cfg.DB.QueryRow(ctx, `SELECT id, description, sources, labels, programs, enabled, updated_at, updated_by, 0::bigint, NULL::timestamptz, '{}'::text[]
		FROM openpicket.syslog_devices WHERE id = $1`, d.GetId())
	out, err := scanSyslogDevice(row)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.PutSyslogDeviceResponse{Device: out}), nil
}

func (y *syslogService) DeleteSyslogDevice(ctx context.Context, req *connect.Request[apiv1.DeleteSyslogDeviceRequest]) (*connect.Response[apiv1.DeleteSyslogDeviceResponse], error) {
	tag, err := y.s.cfg.DB.Exec(ctx, `DELETE FROM openpicket.syslog_devices WHERE id = $1`, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	if tag.RowsAffected() == 0 {
		return nil, toConnectError(fmt.Errorf("%w: device %q", errNotFound, req.Msg.GetId()))
	}
	return connect.NewResponse(&apiv1.DeleteSyslogDeviceResponse{}), nil
}

func (y *syslogService) ListSyslogSenders(ctx context.Context, req *connect.Request[apiv1.ListSyslogSendersRequest]) (*connect.Response[apiv1.ListSyslogSendersResponse], error) {
	// A sender recorded before its device was registered matches it now.
	rows, err := y.s.cfg.DB.Query(ctx, `SELECT s.addr, COALESCE(d.id, ''), s.messages, s.dropped, s.sample, s.first_seen, s.last_seen
		FROM openpicket.syslog_sources s
		LEFT JOIN LATERAL (SELECT id FROM openpicket.syslog_devices d, unnest(d.sources) src WHERE s.addr <<= src ORDER BY masklen(src) DESC LIMIT 1) d ON true
		WHERE NOT $1 OR d.id IS NULL
		ORDER BY s.last_seen DESC LIMIT 500`, req.Msg.GetUnregistered())
	if err != nil {
		return nil, toConnectError(err)
	}
	defer rows.Close()
	res := &apiv1.ListSyslogSendersResponse{}
	for rows.Next() {
		var addr netip.Addr
		var first, last time.Time
		s := &apiv1.SyslogSender{}
		if err := rows.Scan(&addr, &s.DeviceId, &s.Messages, &s.Dropped, &s.Sample, &first, &last); err != nil {
			return nil, toConnectError(err)
		}
		s.Addr, s.FirstSeen, s.LastSeen = addr.String(), timestamppb.New(first), timestamppb.New(last)
		res.Senders = append(res.Senders, s)
	}
	if err := rows.Err(); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(res), nil
}

func (y *syslogService) GetSyslogSettings(ctx context.Context, _ *connect.Request[apiv1.GetSyslogSettingsRequest]) (*connect.Response[apiv1.GetSyslogSettingsResponse], error) {
	res := &apiv1.GetSyslogSettingsResponse{Unregistered: y.s.cfg.SyslogUnregistered, UnregisteredDefault: true}
	if !syslog.ValidMode(res.Unregistered) {
		res.Unregistered = syslog.ModeDrop
	}
	var stored string
	if ok, err := y.s.cfg.Settings.Get(ctx, syslog.KeyUnregistered, &stored); err != nil {
		return nil, toConnectError(err)
	} else if ok && syslog.ValidMode(stored) {
		res.Unregistered, res.UnregisteredDefault = stored, false
	}
	rows, err := y.s.cfg.DB.Query(ctx, `SELECT replica, syslog FROM openpicket.gateway_info
		WHERE seen_at > now() - interval '3 minutes' AND cardinality(syslog) > 0 ORDER BY replica`)
	if err != nil {
		return nil, toConnectError(err)
	}
	defer rows.Close()
	for rows.Next() {
		g := &apiv1.SyslogGateway{}
		if err := rows.Scan(&g.Replica, &g.Listeners); err != nil {
			return nil, toConnectError(err)
		}
		res.Gateways = append(res.Gateways, g)
	}
	if err := rows.Err(); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(res), nil
}

func (y *syslogService) SetSyslogSettings(ctx context.Context, req *connect.Request[apiv1.SetSyslogSettingsRequest]) (*connect.Response[apiv1.SetSyslogSettingsResponse], error) {
	mode := req.Msg.GetUnregistered()
	if !syslog.ValidMode(mode) {
		return nil, toConnectError(fmt.Errorf("%w: unregistered must be %q or %q", errInvalid, syslog.ModeDrop, syslog.ModeAccept))
	}
	if err := y.s.cfg.Settings.Put(ctx, syslog.KeyUnregistered, mode); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&apiv1.SetSyslogSettingsResponse{}), nil
}
