// Package audit provides structured audit logging for Bulwark gateway decisions.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Decision captures the authorization outcome for an audit event.
type Decision struct {
	Effect      string `json:"effect"`                 // "allow" or "deny"
	Reason      string `json:"reason"`                 // human-readable explanation
	Principal   string `json:"principal,omitempty"`    // resolved principal
	MatchedRule string `json:"matched_rule,omitempty"` // OPA rule ID or "default deny"
}

// Event is one audit record per request, emitted after the response is sent.
type Event struct {
	RequestID  string    `json:"request_id"`
	Timestamp  time.Time `json:"timestamp"`
	ClientIP   string    `json:"client_ip,omitempty"`
	Method     string    `json:"method,omitempty"`
	Host       string    `json:"host,omitempty"`
	Path       string    `json:"path,omitempty"`
	Upstream   string    `json:"upstream,omitempty"`
	StatusCode int       `json:"status_code"`
	LatencyMS  int64     `json:"latency_ms"`
	Decision   *Decision `json:"decision,omitempty"`
	Error      *string   `json:"error,omitempty"`

	// Latency is set by callers using Go duration types; Emit converts it to
	// LatencyMS for serialization. Not included in JSON output.
	Latency time.Duration `json:"-"`
}

// Logger is the interface for emitting audit events.
type Logger interface {
	Emit(event Event)
}

// JSONLogger writes one JSON object per line to an io.Writer.
// It is safe for concurrent use.
type JSONLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONLogger returns a Logger that writes newline-delimited JSON to w.
func NewJSONLogger(w io.Writer) *JSONLogger {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // preserve URLs and other values without mangling < > &
	return &JSONLogger{enc: enc}
}

// Emit serializes the event as a single JSON line.
// If Latency is set and LatencyMS is zero, LatencyMS is derived from Latency.
// Write errors are reported to stderr rather than propagated — a logger failure
// must not crash the gateway or affect the request path.
func (l *JSONLogger) Emit(event Event) {
	if event.LatencyMS == 0 && event.Latency > 0 {
		event.LatencyMS = event.Latency.Milliseconds()
	}
	l.mu.Lock()
	err := l.enc.Encode(event)
	l.mu.Unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bulwark: audit log write error: %v\n", err)
	}
}
