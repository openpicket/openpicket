package dataplane

import (
	"context"
	"errors"
	"log/slog"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
)

// ErrVersionMismatch is returned by DecisionSink.ApplyDelta when the delta
// does not start at the applied version. The agent then reports its version
// and the manager answers with a snapshot.
var ErrVersionMismatch = errors.New("dataplane: decision version mismatch")

// DecisionSink applies the decisions the manager distributes (the
// enforcer). It makes the final local checks (allowlist, local networks,
// limits).
type DecisionSink interface {
	// Version is the last applied version (0: none).
	Version() uint64
	ApplySnapshot(ctx context.Context, s *dataplanev1.DecisionSnapshot) (setSize uint32, err error)
	ApplyDelta(ctx context.Context, d *dataplanev1.DecisionDelta) (setSize uint32, err error)
}

// PolicySink validates and applies port policy bundles.
type PolicySink interface {
	// Version is the last applied bundle version (0: none).
	Version() uint64
	Apply(ctx context.Context, b *dataplanev1.PolicyBundle) error
}

func serveDecisions(ctx context.Context, sess *Session, sink DecisionSink, log *slog.Logger) error {
	ms, err := sess.Open(dataplanev1.StreamType_STREAM_TYPE_DECISIONS)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { ms.Close() })
	defer stop()
	defer ms.Close()
	sub := &dataplanev1.DecisionsUp{Body: &dataplanev1.DecisionsUp_Subscribe{Subscribe: &dataplanev1.DecisionSubscribe{HaveVersion: sink.Version()}}}
	if err := ms.Send(sub); err != nil {
		return err
	}
	for {
		down := &dataplanev1.DecisionsDown{}
		if err := ms.Recv(down); err != nil {
			return err
		}
		var (
			size uint32
			err  error
		)
		switch b := down.Body.(type) {
		case *dataplanev1.DecisionsDown_Snapshot:
			size, err = sink.ApplySnapshot(ctx, b.Snapshot)
		case *dataplanev1.DecisionsDown_Delta:
			size, err = sink.ApplyDelta(ctx, b.Delta)
		default:
			continue
		}
		ack := &dataplanev1.DecisionAck{Version: sink.Version(), SetSize: size}
		if err != nil {
			ack.Error = err.Error()
			if !errors.Is(err, ErrVersionMismatch) {
				log.Warn("apply decisions", "err", err)
			}
		}
		if err := ms.Send(&dataplanev1.DecisionsUp{Body: &dataplanev1.DecisionsUp_Ack{Ack: ack}}); err != nil {
			return err
		}
	}
}

func servePolicy(ctx context.Context, sess *Session, sink PolicySink, log *slog.Logger) error {
	ms, err := sess.Open(dataplanev1.StreamType_STREAM_TYPE_POLICY)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { ms.Close() })
	defer stop()
	defer ms.Close()
	if err := ms.Send(&dataplanev1.PolicyUp{Body: &dataplanev1.PolicyUp_Subscribe{Subscribe: &dataplanev1.PolicySubscribe{HaveVersion: sink.Version()}}}); err != nil {
		return err
	}
	for {
		b := &dataplanev1.PolicyBundle{}
		if err := ms.Recv(b); err != nil {
			return err
		}
		ack := &dataplanev1.PolicyAck{Version: b.Version}
		if err := sink.Apply(ctx, b); err != nil {
			ack.Error = err.Error()
			log.Warn("apply port policy", "version", b.Version, "err", err)
		}
		if err := ms.Send(&dataplanev1.PolicyUp{Body: &dataplanev1.PolicyUp_Ack{Ack: ack}}); err != nil {
			return err
		}
	}
}
