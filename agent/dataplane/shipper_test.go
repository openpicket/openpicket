package dataplane

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/jc-lab/suricontroller/agent/collector"
	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/pkg/direction"
	"github.com/openpicket/openpicket/pkg/record"
)

func pipeStreams(t *testing.T) (agentSide, managerSide *wire.MsgStream) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return wire.NewMsgStream(a, 0), wire.NewMsgStream(b, 0)
}

func recvBatch(t *testing.T, ms *wire.MsgStream) *dataplanev1.LogBatch {
	t.Helper()
	ch := make(chan *dataplanev1.LogBatch, 1)
	go func() {
		b := &dataplanev1.LogBatch{}
		if err := ms.Recv(b); err != nil {
			close(ch)
			return
		}
		ch <- b
	}()
	select {
	case b, ok := <-ch:
		if !ok {
			t.Fatal("stream closed")
		}
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for batch")
		return nil
	}
}

func memRecords(s *Shipper, lines ...string) []*dataplanev1.Record {
	var out []*dataplanev1.Record
	for _, l := range lines {
		out = append(out, &dataplanev1.Record{Line: []byte(l), Rid: s.NextMemoryRID()})
	}
	return out
}

func TestShipperResendsUnackedOnNewSession(t *testing.T) {
	s := NewShipper(ShipperConfig{NodeID: "n1", BootID: "boot1"})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if !s.Push(ctx, record.TypeNflog, memRecords(s, `{"n":1}`), 0) {
			t.Fatal("push")
		}
	}

	agentSide, mgr := pipeStreams(t)
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.Serve(sctx, agentSide) }()
	for want := uint64(1); want <= 3; want++ {
		if b := recvBatch(t, mgr); b.Seq != want || b.BootId != "boot1" || b.Type != record.TypeNflog {
			t.Fatalf("batch %+v, want seq %d", b, want)
		}
	}
	if err := mgr.Send(&dataplanev1.LogAck{BootId: "boot1", Seq: 2}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return s.Stats().InflightBatches == 1 })
	cancel()
	<-done

	// The next session resends only the unacknowledged batch, then new ones.
	agentSide, mgr = pipeStreams(t)
	go func() { _ = s.Serve(ctx, agentSide) }()
	if b := recvBatch(t, mgr); b.Seq != 3 {
		t.Fatalf("resent seq %d, want 3", b.Seq)
	}
	s.Push(ctx, record.TypeNflog, memRecords(s, `{"n":4}`), 0)
	b4 := recvBatch(t, mgr)
	if b4.Seq != 4 {
		t.Fatalf("new seq %d, want 4", b4.Seq)
	}
	if recs := decode(t, b4); len(recs) != 1 || string(recs[0].Line) != `{"n":4}` || recs[0].Rid == "" {
		t.Fatalf("records = %v", recs)
	}
	// An ack for another boot is ignored.
	_ = mgr.Send(&dataplanev1.LogAck{BootId: "other", Seq: 10})
	_ = mgr.Send(&dataplanev1.LogAck{BootId: "boot1", Seq: 4})
	waitFor(t, func() bool { return s.Stats().InflightBatches == 0 })
	if st := s.Stats(); st.SentRecords != 4 {
		t.Fatalf("sent = %d", st.SentRecords)
	}
}

func TestShipperWindowBlocksProducers(t *testing.T) {
	s := NewShipper(ShipperConfig{NodeID: "n1", BootID: "b", MaxInflightBytes: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if !s.Push(ctx, record.TypeNflog, memRecords(s, `{}`), 0) {
		t.Fatal("first push must fit")
	}
	if s.Push(ctx, record.TypeNflog, memRecords(s, `{}`), 0) {
		t.Fatal("second push should block until the window has room")
	}
	if st := s.Stats(); st.DroppedRecords != 1 || st.InflightBatches != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestConvertTagsAlertsAndKeepsLinesStable(t *testing.T) {
	nets, _ := direction.NewNets([]string{"192.168.1.0/24"})
	s := NewShipper(ShipperConfig{NodeID: "n1", BootID: "b", Nets: func() *direction.Nets { return nets }})
	alert := `{"timestamp":"2026-10-20T10:59:01.000000+0900","event_type":"alert","src_ip":"198.51.100.9","dest_ip":"192.168.1.50","direction":"to_client","flow":{"src_ip":"192.168.1.50","dest_ip":"198.51.100.9"}}`
	flow := `{"timestamp":"2026-10-20T10:59:02.000000+0900","event_type":"flow","src_ip":"192.168.1.50"}`
	b := &collector.Batch{Type: agentv1.LogType_LOG_TYPE_EVE, Records: []collector.Record{
		{Line: []byte(alert), Path: "/log/eve.json", Inode: 3, Offset: 0},
		{Line: []byte(flow), Path: "/log/eve.json", Inode: 3, Offset: 300},
	}}
	recs := s.convert(b)
	again := s.convert(b)
	if string(recs[0].Line) != string(again[0].Line) || recs[0].Rid != again[0].Rid {
		t.Fatal("conversion is not deterministic")
	}
	var e record.Eve
	if err := json.Unmarshal(recs[0].Line, &e); err != nil {
		t.Fatal(err)
	}
	if e.OpenPicket == nil || e.OpenPicket.Direction != direction.Outbound || e.OpenPicket.RemoteIP != "198.51.100.9" ||
		e.OpenPicket.RID != record.FileRID("n1", "/log/eve.json", 3, 0) {
		t.Fatalf("tag = %+v", e.OpenPicket)
	}
	if string(recs[1].Line) != flow {
		t.Fatal("flow line must not be tagged")
	}
	if recs[0].TimeUnixNano != time.Date(2026, 10, 20, 1, 59, 1, 0, time.UTC).UnixNano() {
		t.Fatalf("time = %d", recs[0].TimeUnixNano)
	}
}

// decode is used by tests in this package.
func decode(t *testing.T, b *dataplanev1.LogBatch) []*dataplanev1.Record {
	t.Helper()
	dec, _ := zstd.NewReader(nil)
	defer dec.Close()
	raw, err := dec.DecodeAll(b.ZstdRecords, nil)
	if err != nil {
		t.Fatal(err)
	}
	var l dataplanev1.RecordList
	if err := proto.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l.Records
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
