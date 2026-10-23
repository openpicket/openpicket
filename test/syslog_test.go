package test

import (
	"context"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jc-lab/suricontroller/pkg/sshkey"

	"github.com/openpicket/openpicket/manager"
	"github.com/openpicket/openpicket/manager/sinks/crowdsec"
	"github.com/openpicket/openpicket/manager/sinks/loki"
)

// TestSyslogDevices sends syslog to a gateway on a restricted database
// account: registered devices' lines reach CrowdSec and Loki under the
// device id, unregistered senders are dropped and counted until the
// setting accepts them, and devices registered later apply at once.
func TestSyslogDevices(t *testing.T) {
	ctx := context.Background()
	pool, gwPool, _ := restrictedPools(t)
	lk := &lokiLabels{}
	lokiSrv := httptest.NewServer(lk)
	defer lokiSrv.Close()
	lp := &envelopeLP{}
	lpSrv := httptest.NewServer(lp)
	defer lpSrv.Close()

	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.syslog_devices (id, sources, labels, programs) VALUES
		('fw-01', '{127.0.0.2/32}', '{"site":"busan"}', '{"%ASA-4-106023":"cisco-asa"}')`); err != nil {
		t.Fatal(err)
	}
	hostKey, _ := sshkey.Generate()
	m, err := manager.New(manager.Options{
		DB: gwPool, Role: manager.RoleGateway, HostKey: hostKey, ReplicaID: "gw-1",
		Loki: loki.Config{URL: lokiSrv.URL}, CrowdSec: crowdsec.Config{Endpoints: []string{lpSrv.URL}},
		Syslog: manager.SyslogOptions{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0"},
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = m.Run(rctx); close(done) }()
	stop := func() { cancel(); <-done }
	defer stop()

	addrs := map[string]string{}
	for _, l := range m.Syslog().Listeners() {
		network, addr, _ := strings.Cut(l, " ")
		addrs[network] = addr
	}
	send := func(network, from, msg string) {
		t.Helper()
		d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(from)}}
		if network == "tcp" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
		}
		c, err := d.Dial(network, addrs[network])
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte(msg))
		c.Close()
	}
	has := func(node, line string) bool {
		lp.mu.Lock()
		defer lp.mu.Unlock()
		for i, e := range lp.got {
			if lp.meta[i]["node_id"] == node && e.Log.Program+": "+e.Log.Message == line {
				return true
			}
		}
		return false
	}
	// UDP is not acknowledged: send again until the line arrives.
	until := func(what string, cond func() bool, resend func()) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timeout: %s (CrowdSec got %q)", what, lp.lines())
			}
			if resend != nil {
				resend()
			}
			time.Sleep(200 * time.Millisecond)
		}
	}

	asa := "<164>Oct 23 10:00:01 fw %ASA-4-106023: Deny tcp src outside:198.51.100.7/4444 dst inside:10.0.0.5/22"
	ssh := "<38>Oct 23 10:00:02 fw sshd[42]: Failed password for root from 198.51.100.66 port 4000 ssh2"
	send("tcp", "127.0.0.2", asa+"\n"+ssh+"\n")
	until("fw-01 lines", func() bool {
		return has("fw-01", "cisco-asa: Deny tcp src outside:198.51.100.7/4444 dst inside:10.0.0.5/22") &&
			has("fw-01", "sshd: Failed password for root from 198.51.100.66 port 4000 ssh2")
	}, nil)
	lp.mu.Lock()
	if lp.meta[0]["site"] != "busan" {
		t.Errorf("meta %v", lp.meta[0])
	}
	lp.mu.Unlock()

	// Unregistered: dropped until the setting accepts it.
	send("udp", "127.0.0.5", "<13>Oct 23 10:00:03 nas app: unregistered")
	time.Sleep(1500 * time.Millisecond)
	if has("127.0.0.5", "app: unregistered") {
		t.Fatal("unregistered sender accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.settings (key, value) VALUES ('syslog.unregistered', '"accept"')`); err != nil {
		t.Fatal(err)
	}
	until("accepted sender", func() bool { return has("127.0.0.5", "app: unregistered") },
		func() { send("udp", "127.0.0.5", "<13>Oct 23 10:00:03 nas app: unregistered") })

	// A device registered while running applies at once.
	if _, err := pool.Exec(ctx, `INSERT INTO openpicket.syslog_devices (id, sources, programs) VALUES ('sw-01', '{127.0.0.6/32}', '{"*":"switch"}')`); err != nil {
		t.Fatal(err)
	}
	until("new device", func() bool { return has("sw-01", "switch: port 3 link down") },
		func() { send("udp", "127.0.0.6", "port 3 link down") })
	// Loki labels the source (syslog), as for syslog files.
	until("Loki stream", func() bool {
		lk.mu.Lock()
		defer lk.mu.Unlock()
		for _, s := range lk.streams {
			if s["node"] == "fw-01" && s["program"] == "syslog" && s["instance"] == "syslog" {
				return true
			}
		}
		return false
	}, nil)

	var listeners []string
	if err := pool.QueryRow(ctx, `SELECT syslog FROM openpicket.gateway_info WHERE replica = 'gw-1'`).Scan(&listeners); err != nil || len(listeners) != 2 {
		t.Fatalf("gateway listeners %v %v", listeners, err)
	}
	// The counts are written by the gateway (flushed on stop).
	stop()
	var messages, dropped int64
	var device *string
	if err := pool.QueryRow(ctx, `SELECT device_id, messages, dropped FROM openpicket.syslog_sources WHERE addr = '127.0.0.2'`).Scan(&device, &messages, &dropped); err != nil ||
		device == nil || *device != "fw-01" || messages != 2 || dropped != 0 {
		t.Fatalf("fw-01 sender: %v %d %d %v", device, messages, dropped, err)
	}
	if err := pool.QueryRow(ctx, `SELECT device_id, messages, dropped FROM openpicket.syslog_sources WHERE addr = '127.0.0.5'`).Scan(&device, &messages, &dropped); err != nil ||
		device != nil || messages < 1 || dropped < 1 {
		t.Fatalf("unregistered sender: %v %d %d %v", device, messages, dropped, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM openpicket.log_programs WHERE node_id = 'fw-01' AND program IN ('cisco-asa', 'sshd')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("log_programs: %d %v", n, err)
	}
}
