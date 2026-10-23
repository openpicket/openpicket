package api

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/auth"
)

func TestSyslogDevices(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	e.server.cfg.Auth.Roles = auth.Roles{Admin: auth.RoleConfig{Users: []string{"root"}}, Operator: auth.RoleConfig{Groups: []string{"secops"}}, Viewer: auth.RoleConfig{Groups: []string{"staff"}}}
	admin := e.clients(viewerHeaders("root", ""))
	op := e.clients(viewerHeaders("alice", "secops"))
	viewer := e.clients(viewerHeaders("bob", "staff"))
	db := e.server.cfg.DB

	put := func(c *clients, create bool, d *apiv1.SyslogDevice) (*apiv1.SyslogDevice, error) {
		res, err := c.syslog.PutSyslogDevice(ctx, connect.NewRequest(&apiv1.PutSyslogDeviceRequest{Device: d, Create: create}))
		if err != nil {
			return nil, err
		}
		return res.Msg.Device, nil
	}
	fw := &apiv1.SyslogDevice{Id: "fw-01", Sources: []string{"10.0.0.1", "::ffff:10.0.9.0/120"}, Enabled: true,
		Labels: map[string]string{"site": "seoul"}, Programs: map[string]string{"%ASA-4-106023": "cisco-asa", "*": "fw"}}
	if _, err := put(viewer, true, fw); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer put: %v", err)
	}
	got, err := put(op, true, fw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sources) != 2 || got.Sources[0] != "10.0.0.1" || got.Sources[1] != "10.0.9.0/24" || got.UpdatedBy == "" {
		t.Fatalf("device %v", got)
	}
	if _, err := put(op, true, fw); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO openpicket.nodes (id, public_key, x25519, fingerprint) VALUES ('edge-01', 'k', 'x', 'f')`); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]*apiv1.SyslogDevice{
		"bad id":         {Id: "FW", Sources: []string{"10.1.0.1"}},
		"no source":      {Id: "sw-01"},
		"bad source":     {Id: "sw-01", Sources: []string{"10.1.0.300"}},
		"default route":  {Id: "sw-01", Sources: []string{"0.0.0.0/0"}},
		"overlap":        {Id: "sw-01", Sources: []string{"10.0.9.0/24"}},
		"bad program":    {Id: "sw-01", Sources: []string{"10.1.0.1"}, Programs: map[string]string{"x": "Cisco ASA"}},
		"bad tag":        {Id: "sw-01", Sources: []string{"10.1.0.1"}, Programs: map[string]string{"a b": "x"}},
		"node namespace": {Id: "edge-01", Sources: []string{"10.1.0.1"}},
	} {
		_, err := put(op, true, d)
		if want := connect.CodeInvalidArgument; name == "node namespace" {
			want = connect.CodeAlreadyExists
			if code(err) != want {
				t.Errorf("%s: %v", name, err)
			}
		} else if code(err) != want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := put(op, false, &apiv1.SyslogDevice{Id: "nope", Sources: []string{"10.1.0.1"}}); code(err) != connect.CodeNotFound {
		t.Fatalf("update missing: %v", err)
	}
	fw.Description, fw.Sources = "ASA", []string{"10.0.0.1"}
	if got, err = put(op, false, fw); err != nil || got.Description != "ASA" || len(got.Sources) != 1 {
		t.Fatalf("update: %v %v", got, err)
	}

	// Senders as the gateways record them: one matches fw-01 now.
	if _, err := db.Exec(ctx, `INSERT INTO openpicket.syslog_sources (addr, device_id, messages, dropped, sample) VALUES
		('10.0.0.1', 'fw-01', 10, 0, 'a'), ('10.2.0.7', NULL, 0, 4, 'b'), ('10.0.0.1'::inet + 1, NULL, 0, 2, 'c')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO openpicket.log_programs (node_id, program, lines) VALUES ('fw-01', 'cisco-asa', 10)`); err != nil {
		t.Fatal(err)
	}
	snd, err := viewer.syslog.ListSyslogSenders(ctx, connect.NewRequest(&apiv1.ListSyslogSendersRequest{Unregistered: true}))
	if err != nil || len(snd.Msg.Senders) != 2 {
		t.Fatalf("unregistered senders: %v %v", snd, err)
	}
	all, err := viewer.syslog.ListSyslogSenders(ctx, connect.NewRequest(&apiv1.ListSyslogSendersRequest{}))
	if err != nil || len(all.Msg.Senders) != 3 {
		t.Fatalf("senders: %v %v", all, err)
	}
	list, err := viewer.syslog.ListSyslogDevices(ctx, connect.NewRequest(&apiv1.ListSyslogDevicesRequest{}))
	if err != nil || len(list.Msg.Devices) != 1 {
		t.Fatalf("devices: %v %v", list, err)
	}
	if d := list.Msg.Devices[0]; d.Messages != 10 || d.LastSeen == nil || len(d.SeenPrograms) != 1 || d.Programs["*"] != "fw" || d.Labels["site"] != "seoul" {
		t.Fatalf("device %v", d)
	}

	// Unregistered senders: the installation default until stored.
	e.server.cfg.SyslogUnregistered = "accept"
	st, err := viewer.syslog.GetSyslogSettings(ctx, connect.NewRequest(&apiv1.GetSyslogSettingsRequest{}))
	if err != nil || st.Msg.Unregistered != "accept" || !st.Msg.UnregisteredDefault {
		t.Fatalf("settings: %v %v", st, err)
	}
	if _, err := op.syslog.SetSyslogSettings(ctx, connect.NewRequest(&apiv1.SetSyslogSettingsRequest{Unregistered: "drop"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("operator set: %v", err)
	}
	if _, err := admin.syslog.SetSyslogSettings(ctx, connect.NewRequest(&apiv1.SetSyslogSettingsRequest{Unregistered: "keep"})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad mode: %v", err)
	}
	if _, err := admin.syslog.SetSyslogSettings(ctx, connect.NewRequest(&apiv1.SetSyslogSettingsRequest{Unregistered: "drop"})); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO openpicket.gateway_info (replica, host_key, db_user, db_restricted, syslog) VALUES ('gw-1', 'k', 'u', true, '{"udp [::]:5514"}')`); err != nil {
		t.Fatal(err)
	}
	st, err = viewer.syslog.GetSyslogSettings(ctx, connect.NewRequest(&apiv1.GetSyslogSettingsRequest{}))
	if err != nil || st.Msg.Unregistered != "drop" || st.Msg.UnregisteredDefault || len(st.Msg.Gateways) != 1 || st.Msg.Gateways[0].Listeners[0] != "udp [::]:5514" {
		t.Fatalf("settings: %v %v", st, err)
	}

	// The namespace is shared both ways.
	key, _ := sshkey.Generate()
	if _, err := op.nodes.RegisterNode(ctx, connect.NewRequest(&apiv1.RegisterNodeRequest{PublicKey: key.Public("fw-01").String()})); code(err) != connect.CodeAlreadyExists {
		t.Fatalf("node with a device id: %v", err)
	}
	if _, err := op.syslog.DeleteSyslogDevice(ctx, connect.NewRequest(&apiv1.DeleteSyslogDeviceRequest{Id: "fw-01"})); err != nil {
		t.Fatal(err)
	}
	if _, err := op.syslog.DeleteSyslogDevice(ctx, connect.NewRequest(&apiv1.DeleteSyslogDeviceRequest{Id: "fw-01"})); code(err) != connect.CodeNotFound {
		t.Fatalf("delete again: %v", err)
	}
}
