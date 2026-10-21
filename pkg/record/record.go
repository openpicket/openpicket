// Package record defines the log record schema shared by the agent and the
// manager: log type names, the fixed "openpicket" tag the agent appends to
// eve alert/anomaly and nflog lines, record ids and eve field access.
//
// The tag is written once by the agent before the record is buffered, so a
// retransmitted line is byte-identical (Loki deduplicates identical
// timestamp, labels and line at query time).
package record

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	agentv1 "github.com/jc-lab/suricontroller/gen/suricontroller/agent/v1"
)

// Log type names on the wire (LogBatch.type).
const (
	TypeEve      = "eve"
	TypeSuricata = "suricata"
	TypeFast     = "fast"
	TypeStats    = "stats"
	TypeAgent    = "agent"
	TypeNflog    = "nflog"
)

// TypeName maps a suricontroller log type to its wire name.
func TypeName(t agentv1.LogType) string {
	switch t {
	case agentv1.LogType_LOG_TYPE_EVE:
		return TypeEve
	case agentv1.LogType_LOG_TYPE_SURICATA:
		return TypeSuricata
	case agentv1.LogType_LOG_TYPE_FAST:
		return TypeFast
	case agentv1.LogType_LOG_TYPE_STATS:
		return TypeStats
	case agentv1.LogType_LOG_TYPE_AGENT:
		return TypeAgent
	}
	return "unknown"
}

// IsJSON reports whether records of the type are JSON objects.
func IsJSON(t string) bool { return t == TypeEve || t == TypeNflog }

// TagField is the name of the object the agent appends.
const TagField = "openpicket"

// Tag is the fixed agent-side annotation of a record.
type Tag struct {
	RID        string `json:"rid"`
	Direction  string `json:"direction,omitempty"`
	Confidence string `json:"direction_confidence,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	LocalIP    string `json:"local_ip,omitempty"`
}

// AppendTag returns line with `,"openpicket":{...}` inserted before its
// closing brace. Lines that are not a JSON object are returned unchanged.
func AppendTag(line []byte, t Tag) []byte {
	return AppendField(line, TagField, t)
}

// AppendField inserts `"name": <json of v>` into the JSON object line.
func AppendField(line []byte, name string, v any) []byte {
	trimmed := bytes.TrimRight(line, " \t\r")
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return line
	}
	b, err := json.Marshal(v)
	if err != nil {
		return line
	}
	body := trimmed[:len(trimmed)-1]
	out := make([]byte, 0, len(trimmed)+len(name)+len(b)+6)
	out = append(out, body...)
	if len(bytes.TrimSpace(body)) > 1 {
		out = append(out, ',')
	}
	out = strconv.AppendQuote(out, name)
	out = append(out, ':')
	out = append(out, b...)
	return append(out, '}')
}

// FileRID identifies a line read from a file; it is stable across agent
// restarts because the collector re-reads unacknowledged lines from the
// same offset.
func FileRID(node, path string, inode uint64, offset int64) string {
	h := sha256.New()
	h.Write([]byte(node))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write(strconv.AppendUint(nil, inode, 10))
	h.Write([]byte{0})
	h.Write(strconv.AppendInt(nil, offset, 10))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// MemoryRID identifies a record of an in-memory source (no replay after a
// restart).
func MemoryRID(bootID string, counter uint64) string {
	return bootID + "-" + strconv.FormatUint(counter, 10)
}

// eveTimeLayouts covers Suricata ("2026-10-20T10:59:01.123456+0900") and
// RFC 3339.
var eveTimeLayouts = []string{
	"2006-01-02T15:04:05.999999999-0700",
	time.RFC3339Nano,
}

// ParseTime parses an eve/nflog "timestamp".
func ParseTime(s string) (time.Time, bool) {
	for _, l := range eveTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Eve holds the eve fields OpenPicket uses.
type Eve struct {
	Timestamp   string `json:"timestamp"`
	EventType   string `json:"event_type"`
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Proto       string `json:"proto"`
	Direction   string `json:"direction"`
	CommunityID string `json:"community_id"`
	Flow        *struct {
		SrcIP  string `json:"src_ip"`
		DestIP string `json:"dest_ip"`
	} `json:"flow"`
	Alert *struct {
		SignatureID int64  `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
	TLS *struct {
		JA4 string `json:"ja4"`
	} `json:"tls"`
	// nflog
	Prefix string `json:"prefix"`
	// Tag appended by the agent.
	OpenPicket *Tag `json:"openpicket"`
}

// ParseEve decodes the fields of an eve or nflog line.
func ParseEve(line []byte) (*Eve, error) {
	var e Eve
	if err := json.Unmarshal(line, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// StringField extracts a top-level string field without decoding the whole
// line (for high-volume records). It does not unescape.
func StringField(line []byte, name string) string {
	key := append(append([]byte{'"'}, name...), '"', ':')
	i := bytes.Index(line, key)
	if i < 0 {
		return ""
	}
	rest := bytes.TrimLeft(line[i+len(key):], " ")
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	end := bytes.IndexByte(rest[1:], '"')
	if end < 0 {
		return ""
	}
	return string(rest[1 : 1+end])
}
