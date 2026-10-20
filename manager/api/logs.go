package api

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/sinks/loki"
)

type logService struct{ s *Server }

var plainValue = regexp.MustCompile(`^[A-Za-z0-9_.:\-]{1,128}$`)

func anyOf(label string, values []string) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		if !plainValue.MatchString(v) {
			return "", connect.NewError(connect.CodeInvalidArgument, errors.New("invalid "+label+" "+v))
		}
		quoted = append(quoted, regexp.QuoteMeta(v))
	}
	return label + "=~" + loki.Quote("^("+strings.Join(quoted, "|")+")$"), nil
}

// LogQL builds the query of a filter.
func LogQL(f *apiv1.LogFilter) (string, error) {
	if q := strings.TrimSpace(f.GetLogql()); q != "" {
		if len(q) > 4096 {
			return "", connect.NewError(connect.CodeInvalidArgument, errors.New("query too long"))
		}
		return q, nil
	}
	sel := []string{`job="openpicket"`}
	for _, l := range []struct {
		label  string
		values []string
	}{{"node", f.GetNodes()}, {"type", f.GetTypes()}, {"event_type", f.GetEventTypes()}} {
		c, err := anyOf(l.label, l.values)
		if err != nil {
			return "", err
		}
		if c != "" {
			sel = append(sel, c)
		}
	}
	if f.GetInstance() != "" {
		sel = append(sel, "instance="+loki.Quote(f.GetInstance()))
	}
	q := "{" + strings.Join(sel, ", ") + "}"
	if t := f.GetText(); t != "" {
		q += " |~ " + loki.Quote("(?i)"+regexp.QuoteMeta(t))
	}
	if ip := f.GetIp(); ip != "" {
		if !plainValue.MatchString(ip) {
			return "", connect.NewError(connect.CodeInvalidArgument, errors.New("invalid ip"))
		}
		v := loki.Quote(ip)
		q += " | src_ip=" + v + " or dest_ip=" + v + " or remote_ip=" + v
	}
	for _, m := range []struct{ label, value string }{
		{"direction", f.GetDirection()}, {"signature_id", f.GetSignatureId()}, {"community_id", f.GetCommunityId()}, {"site", f.GetSite()},
	} {
		if m.value != "" {
			q += " | " + m.label + "=" + loki.Quote(m.value)
		}
	}
	return q, nil
}

func (l *logService) querier() (*loki.Querier, error) {
	if l.s.cfg.Logs == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the log explorer needs Loki (OPENPICKET_LOKI_URL)"))
	}
	return l.s.cfg.Logs, nil
}

func lokiError(err error) error {
	var qe *loki.QueryError
	if errors.As(err, &qe) && qe.Status == 400 {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewError(connect.CodeUnavailable, err)
}

func toEntries(es []loki.Entry) []*apiv1.LogEntry {
	out := make([]*apiv1.LogEntry, 0, len(es))
	for _, e := range es {
		out = append(out, &apiv1.LogEntry{Time: timestamppb.New(e.Time), Line: e.Line, Labels: e.Labels})
	}
	return out
}

func (l *logService) QueryLogs(ctx context.Context, req *connect.Request[apiv1.QueryLogsRequest]) (*connect.Response[apiv1.QueryLogsResponse], error) {
	q, err := l.querier()
	if err != nil {
		return nil, err
	}
	logql, err := LogQL(req.Msg.GetFilter())
	if err != nil {
		return nil, err
	}
	end := l.s.cfg.Now()
	if req.Msg.To != nil {
		end = req.Msg.GetTo().AsTime()
	}
	start := end.Add(-time.Hour)
	if req.Msg.From != nil {
		start = req.Msg.GetFrom().AsTime()
	}
	limit := clampLimit32(req.Msg.GetLimit(), 200, 5000)
	es, err := q.QueryRange(ctx, logql, start, end, limit, !req.Msg.GetAscending())
	if err != nil {
		return nil, lokiError(err)
	}
	return connect.NewResponse(&apiv1.QueryLogsResponse{Entries: toEntries(es), Logql: logql}), nil
}

func clampLimit32(n int32, def, max int) int {
	if n <= 0 {
		return def
	}
	return min(int(n), max)
}

// TailInterval is how often a tail polls Loki.
var TailInterval = 2 * time.Second

const maxTail = 30 * time.Minute

func (l *logService) TailLogs(ctx context.Context, req *connect.Request[apiv1.TailLogsRequest], stream *connect.ServerStream[apiv1.TailLogsResponse]) error {
	q, err := l.querier()
	if err != nil {
		return err
	}
	logql, err := LogQL(req.Msg.GetFilter())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, maxTail)
	defer cancel()
	// Start a little in the past: lines arrive in Loki with some delay.
	from := l.s.cfg.Now().Add(-30 * time.Second)
	sent := map[string]bool{}
	t := time.NewTicker(TailInterval)
	defer t.Stop()
	for {
		es, err := q.QueryRange(ctx, logql, from, l.s.cfg.Now(), 1000, false)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return lokiError(err)
		}
		var fresh []loki.Entry
		next := map[string]bool{}
		for _, e := range es {
			k := e.Time.String() + "\x00" + e.Line
			if e.Time.Equal(es[len(es)-1].Time) {
				next[k] = true
			}
			if !sent[k] {
				fresh = append(fresh, e)
			}
		}
		if len(es) > 0 {
			// Lines at the boundary may be repeated by the next query.
			from = es[len(es)-1].Time
			sent = next
		}
		if len(fresh) > 0 {
			if err := stream.Send(&apiv1.TailLogsResponse{Entries: toEntries(fresh)}); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

var logLabels = map[string]bool{"node": true, "type": true, "instance": true, "event_type": true}

func (l *logService) LogLabelValues(ctx context.Context, req *connect.Request[apiv1.LogLabelValuesRequest]) (*connect.Response[apiv1.LogLabelValuesResponse], error) {
	q, err := l.querier()
	if err != nil {
		return nil, err
	}
	if !logLabels[req.Msg.GetLabel()] {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("unknown label"))
	}
	start := l.s.cfg.Now().Add(-24 * time.Hour)
	if req.Msg.From != nil {
		start = req.Msg.GetFrom().AsTime()
	}
	vals, err := q.LabelValues(ctx, req.Msg.GetLabel(), start, l.s.cfg.Now())
	if err != nil {
		return nil, lokiError(err)
	}
	return connect.NewResponse(&apiv1.LogLabelValuesResponse{Values: vals}), nil
}
