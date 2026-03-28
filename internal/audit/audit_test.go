package audit_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stormbane-security/bulwark/internal/audit"
)

func TestJSONAuditLogger_EmitsValidJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewJSONLogger(&buf)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/orders", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	event := audit.Event{
		RequestID: "req-001",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ClientIP:  "10.0.0.1",
		Method:    req.Method,
		Host:      req.Host,
		Path:      req.URL.Path,
		Upstream:  "http://api:8080",
		StatusCode: 200,
		Latency:   42 * time.Millisecond,
	}

	logger.Emit(event)

	var got map[string]any
	if err := json.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("output is not valid JSON: %v\nbuf: %s", err, buf.String())
	}

	fields := []string{"request_id", "timestamp", "client_ip", "method", "host", "path", "upstream", "status_code", "latency_ms"}
	for _, f := range fields {
		if _, ok := got[f]; !ok {
			t.Errorf("missing field %q in audit output", f)
		}
	}

	if got["request_id"] != "req-001" {
		t.Errorf("unexpected request_id: %v", got["request_id"])
	}
	if got["method"] != "GET" {
		t.Errorf("unexpected method: %v", got["method"])
	}
	if got["status_code"] != float64(200) {
		t.Errorf("unexpected status_code: %v", got["status_code"])
	}
	if got["latency_ms"] != float64(42) {
		t.Errorf("unexpected latency_ms: %v", got["latency_ms"])
	}
}

func TestJSONAuditLogger_OneLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewJSONLogger(&buf)

	for i := range 3 {
		logger.Emit(audit.Event{
			RequestID:  fmt.Sprintf("req-%d", i),
			Timestamp:  time.Now(),
			StatusCode: 200,
		})
	}

	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d\n%s", len(lines), buf.String())
	}
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

func TestJSONAuditLogger_DeniedDecision(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewJSONLogger(&buf)

	reason := "no matching rule"
	logger.Emit(audit.Event{
		RequestID:  "req-deny",
		Timestamp:  time.Now(),
		StatusCode: 403,
		Decision: &audit.Decision{
			Effect:      "deny",
			Reason:      reason,
			Principal:   "spiffe://example.com/workload/api",
			MatchedRule: "default deny",
		},
	})

	var got map[string]any
	if err := json.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	decision, ok := got["decision"].(map[string]any)
	if !ok {
		t.Fatal("expected decision object in output")
	}
	if decision["effect"] != "deny" {
		t.Errorf("unexpected effect: %v", decision["effect"])
	}
	if decision["reason"] != reason {
		t.Errorf("unexpected reason: %v", decision["reason"])
	}
}

func TestJSONAuditLogger_ConcurrentEmit(t *testing.T) {
	var buf syncBuffer
	logger := audit.NewJSONLogger(&buf)

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			logger.Emit(audit.Event{
				RequestID:  fmt.Sprintf("req-%d", i),
				Timestamp:  time.Now(),
				StatusCode: 200,
			})
		}(i)
	}
	wg.Wait()

	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != n {
		t.Errorf("expected %d lines, got %d", n, len(lines))
	}
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

// syncBuffer is a bytes.Buffer that is safe for concurrent reads after all
// writes are done (used only to capture output in tests).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Bytes()
}

func TestJSONAuditLogger_ErrorField(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewJSONLogger(&buf)

	errMsg := "upstream unreachable"
	logger.Emit(audit.Event{
		RequestID:  "req-err",
		Timestamp:  time.Now(),
		StatusCode: 502,
		Error:      &errMsg,
	})

	var got map[string]any
	if err := json.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got["error"] != errMsg {
		t.Errorf("unexpected error field: %v", got["error"])
	}
}
