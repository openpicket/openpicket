package api

import (
	"context"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const maxAuditDetail = 4 << 10

// auditInterceptor records successful audited calls.
func (s *Server) auditInterceptor(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		procedure := req.Spec().Procedure
		if err == nil && procedures[procedure].audit {
			msg, _ := req.Any().(proto.Message)
			target := auditTarget(msg)
			if target == "" {
				// RegisterNode: the id comes from the key.
				out, _ := res.Any().(proto.Message)
				target = auditTarget(out)
			}
			s.audit(ctx, actionName(procedure), target, auditDetail(msg))
		}
		return res, err
	}
}

// audit appends an entry; failures are logged (the change already
// happened).
func (s *Server) audit(ctx context.Context, action, target, detail string) {
	if addr := remoteAddr(ctx); addr != "" {
		if detail != "" {
			detail += " "
		}
		detail += "from " + addr
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.cfg.DB.Exec(ctx, `INSERT INTO openpicket.audit (source, principal, action, target, detail) VALUES ('openpicket',$1,$2,$3,$4)`,
		by(ctx), action, target, detail); err != nil {
		s.log.Warn("audit", "action", action, "err", err)
	}
}

// actionName turns "/openpicket.api.v1.NodeService/UpdateNode" into
// "NodeService.UpdateNode".
func actionName(procedure string) string {
	p := strings.TrimPrefix(procedure, "/openpicket.api.v1.")
	return strings.ReplaceAll(p, "/", ".")
}

var targetFields = []protoreflect.Name{"id", "name", "value", "ip", "node_id", "policy_id", "kind", "ids"}

// auditTarget finds the object a request acts on: a well-known top-level
// field, or one inside the first message field (PutPolicy{policy{id}}).
func auditTarget(m proto.Message) string {
	if m == nil {
		return ""
	}
	r := m.ProtoReflect()
	if t := fieldTarget(r); t != "" {
		return t
	}
	fields := r.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if f.Kind() == protoreflect.MessageKind && !f.IsList() && !f.IsMap() && r.Has(f) {
			return fieldTarget(r.Get(f).Message())
		}
	}
	return ""
}

func fieldTarget(r protoreflect.Message) string {
	fields := r.Descriptor().Fields()
	for _, name := range targetFields {
		f := fields.ByName(name)
		if f == nil || !r.Has(f) {
			continue
		}
		v := r.Get(f)
		if f.IsList() {
			var parts []string
			for i := 0; i < v.List().Len() && i < 20; i++ {
				parts = append(parts, v.List().Get(i).String())
			}
			return strings.Join(parts, ",")
		}
		if f.Kind() == protoreflect.StringKind || f.Kind() == protoreflect.Int64Kind {
			return v.String()
		}
	}
	return ""
}

// auditDetail is the request as JSON, without secrets, truncated.
func auditDetail(m proto.Message) string {
	if m == nil {
		return ""
	}
	c := proto.Clone(m)
	scrub(c.ProtoReflect())
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(c)
	if err != nil {
		return ""
	}
	if len(raw) > maxAuditDetail {
		return string(raw[:maxAuditDetail]) + "…"
	}
	return string(raw)
}

// secretFields are never written to the audit log.
var secretFields = map[protoreflect.Name]bool{"password": true, "secrets": true, "license_key": true}

// scrub clears secret fields at any depth.
func scrub(m protoreflect.Message) {
	m.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case secretFields[f.Name()]:
			m.Clear(f)
		case f.Kind() == protoreflect.MessageKind && f.IsList():
			for i := 0; i < v.List().Len(); i++ {
				scrub(v.List().Get(i).Message())
			}
		case f.Kind() == protoreflect.MessageKind && !f.IsMap():
			scrub(v.Message())
		}
		return true
	})
}

// limiter allows n attempts per key and window (login).
type limiter struct {
	n      int
	window time.Duration

	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) > 10000 {
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > l.window {
				delete(l.hits, k)
			}
		}
	}
	ts := l.hits[key]
	keep := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}
	if len(keep) >= l.n {
		l.hits[key] = keep
		return false
	}
	l.hits[key] = append(keep, now)
	return true
}
