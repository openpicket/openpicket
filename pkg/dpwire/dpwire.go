// Package dpwire holds the framing shared by both ends of the data plane
// (channel B): the Noise prologue, the WebSocket subprotocol and typed
// yamux streams. It reuses suricontroller's secure channel and message
// framing.
package dpwire

import (
	"fmt"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/jc-lab/suricontroller/pkg/wire"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
)

const (
	// Prologue binds the Noise handshake to this protocol and version.
	Prologue = "openpicket/dataplane/1"
	// Subprotocol is the WebSocket subprotocol of the data plane endpoint.
	Subprotocol = "openpicket.dataplane.v1"
	// Path is the default HTTP path of the data plane endpoint.
	Path = "/agent/data/v1/connect"
	// MaxClockSkew bounds the handshake timestamp difference.
	MaxClockSkew = 5 * time.Minute
	// MaxMessageSize bounds one framed message (a log batch or a decision
	// snapshot).
	MaxMessageSize = 32 << 20
)

// OpenStream opens a stream of the given type.
func OpenStream(sess *yamux.Session, t dataplanev1.StreamType) (*wire.MsgStream, error) {
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	ms := wire.NewMsgStream(st, MaxMessageSize)
	if err := ms.Send(&dataplanev1.StreamHeader{Type: t}); err != nil {
		st.Close()
		return nil, fmt.Errorf("dpwire: send stream header: %w", err)
	}
	return ms, nil
}

// AcceptStream accepts the next stream and reads its header.
func AcceptStream(sess *yamux.Session) (*wire.MsgStream, dataplanev1.StreamType, error) {
	st, err := sess.AcceptStream()
	if err != nil {
		return nil, 0, err
	}
	ms := wire.NewMsgStream(st, MaxMessageSize)
	_ = st.SetReadDeadline(time.Now().Add(30 * time.Second))
	hdr := &dataplanev1.StreamHeader{}
	if err := ms.Recv(hdr); err != nil {
		st.Close()
		return nil, 0, fmt.Errorf("dpwire: read stream header: %w", err)
	}
	_ = st.SetReadDeadline(time.Time{})
	return ms, hdr.Type, nil
}

// YamuxConfig returns the yamux configuration of both peers.
func YamuxConfig() *yamux.Config { return wire.YamuxConfig() }
