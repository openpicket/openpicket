package manager

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	dataplanev1 "github.com/openpicket/openpicket/gen/openpicket/dataplane/v1"
	"github.com/openpicket/openpicket/manager/db"
	"github.com/openpicket/openpicket/manager/gateway"
)

// presence records which replica holds each node's session. When a node
// connects to another replica, the previous holder is told (NOTIFY) to close
// its session, so a node has one live session across the cluster.
type presence struct {
	db      *pgxpool.Pool
	replica string
	gw      *gateway.Gateway
	log     *slog.Logger

	mu      sync.Mutex
	pending map[string]pendingStatus // session id -> latest status
}

// sessionStale matches the API's sessionTimeout: a session whose heartbeat
// is older is shown offline, and its row may be taken over.
const sessionStale = 90 * time.Second

// upsertSession makes a session the holder of its node.
const upsertSession = `INSERT INTO openpicket.node_sessions AS cur (node_id, session_id, replica, remote_addr, boot_id, connected_at, heartbeat_at, hello, status, status_at)
	VALUES ($1,$2,$3,$4,$5,$6,now(),$7,NULL,NULL)
	ON CONFLICT (node_id) DO UPDATE SET session_id=excluded.session_id, replica=excluded.replica, remote_addr=excluded.remote_addr,
		boot_id=excluded.boot_id, connected_at=excluded.connected_at, heartbeat_at=excluded.heartbeat_at,
		hello=excluded.hello, status=NULL, status_at=NULL`

// connected records a new session. A database failure is logged and
// ignored: an outage must not refuse agents (§5.1); the heartbeat records
// the session later (rerecord).
func (p *presence) connected(ctx context.Context, s *gateway.Session) {
	hello, _ := proto.Marshal(s.Hello())
	err := pgx.BeginFunc(ctx, p.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, upsertSession,
			s.NodeID, s.ID, p.replica, s.RemoteAddr, s.BootID(), s.ConnectedAt, hello); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE openpicket.nodes SET dp_last_seen_at = now() WHERE id = $1`, s.NodeID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, db.ChannelSessions, s.NodeID+" "+s.ID)
		return err
	})
	if err != nil {
		p.log.Warn("record session", "node", s.NodeID, "err", err)
	}
}

func (p *presence) disconnected(s *gateway.Session) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := p.db.Exec(ctx, `DELETE FROM openpicket.node_sessions WHERE node_id = $1 AND session_id = $2`, s.NodeID, s.ID); err != nil {
		p.log.Warn("remove session", "node", s.NodeID, "err", err)
	}
	if _, err := p.db.Exec(ctx, `UPDATE openpicket.nodes SET dp_last_seen_at = now() WHERE id = $1`, s.NodeID); err != nil {
		p.log.Debug("update last seen", "node", s.NodeID, "err", err)
	}
}

// status queues the latest status report of a session; flushStatus writes
// it (OnStatus must not block the control loop).
func (p *presence) status(s *gateway.Session, st *dataplanev1.Status) {
	raw, err := proto.Marshal(st)
	if err != nil {
		return
	}
	p.mu.Lock()
	if p.pending == nil {
		p.pending = map[string]pendingStatus{}
	}
	p.pending[s.ID] = pendingStatus{node: s.NodeID, raw: raw}
	p.mu.Unlock()
}

type pendingStatus struct {
	node string
	raw  []byte
}

func (p *presence) flushStatus(ctx context.Context) {
	p.mu.Lock()
	pending := p.pending
	p.pending = nil
	p.mu.Unlock()
	for session, st := range pending {
		if _, err := p.db.Exec(ctx, `UPDATE openpicket.node_sessions SET status = $3, status_at = now() WHERE node_id = $1 AND session_id = $2`,
			st.node, session, st.raw); err != nil {
			p.log.Debug("record status", "node", st.node, "err", err)
		}
	}
}

// notified handles "<node> <session>": close an older local session.
func (p *presence) notified(payload string) {
	node, session, ok := strings.Cut(payload, " ")
	if ok {
		p.gw.Disconnect(node, session)
	}
}

// run refreshes heartbeats of the local sessions and writes status
// reports.
func (p *presence) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	st := time.NewTicker(2 * time.Second)
	defer st.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-st.C:
			p.flushStatus(ctx)
			continue
		case <-t.C:
		}
		sessions := p.gw.Sessions()
		if len(sessions) == 0 {
			continue
		}
		var ids, nodes []string
		for _, s := range sessions {
			ids, nodes = append(ids, s.ID), append(nodes, s.NodeID)
		}
		rows, _ := p.db.Query(ctx, `UPDATE openpicket.node_sessions SET heartbeat_at = now() WHERE session_id = ANY($1) RETURNING session_id`, ids)
		beat, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			p.log.Warn("session heartbeat", "err", err)
			continue
		}
		if _, err := p.db.Exec(ctx, `UPDATE openpicket.nodes SET dp_last_seen_at = now() WHERE id = ANY($1)`, nodes); err != nil {
			p.log.Warn("node last seen", "err", err)
		}
		p.rerecord(ctx, sessions, beat)
	}
}

// rerecord records the local sessions the heartbeat missed: their row was
// not written at connect (database outage), or it still names an earlier
// session whose replica died. Another session's row is taken over only once
// its heartbeat is stale, so a live session on another replica is kept.
func (p *presence) rerecord(ctx context.Context, sessions []*gateway.Session, beat []string) {
	stale := fmt.Sprintf("%d seconds", int(sessionStale.Seconds()))
	for _, s := range sessions {
		if slices.Contains(beat, s.ID) || p.gw.Session(s.NodeID) != s {
			continue
		}
		hello, _ := proto.Marshal(s.Hello())
		tag, err := p.db.Exec(ctx, upsertSession+` WHERE cur.session_id = excluded.session_id OR cur.heartbeat_at < now() - $8::interval`,
			s.NodeID, s.ID, p.replica, s.RemoteAddr, s.BootID(), s.ConnectedAt, hello, stale)
		if err != nil {
			p.log.Warn("re-record session", "node", s.NodeID, "err", err)
			continue
		}
		if tag.RowsAffected() > 0 {
			p.log.Info("re-recorded session", "node", s.NodeID, "session", s.ID)
		}
	}
}
