package gateway_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/bulwark/internal/audit"
	"github.com/stormbane-security/bulwark/internal/authn"
	"github.com/stormbane-security/bulwark/internal/config"
	"github.com/stormbane-security/bulwark/internal/gateway"
	"github.com/stormbane-security/bulwark/internal/identity"
)

// newTestConfig builds a minimal config.Config suitable for gateway tests
// without going through file-based validation.
func newTestConfig(routes []config.RouteConfig) *config.Config {
	return &config.Config{
		Listeners: []config.ListenerConfig{{Addr: ":0"}},
		Routes:    routes,
	}
}

// silentAudit discards all audit events.
func silentAudit() audit.Logger {
	return audit.NewJSONLogger(io.Discard)
}

// upstreamEcho returns a test upstream server that echoes a fixed body and
// exposes the last request it received so tests can inspect headers.
type testUpstream struct {
	*httptest.Server
	lastReq *http.Request
}

func newTestUpstream(status int, body string) *testUpstream {
	tu := &testUpstream{}
	tu.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tu.lastReq = r
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	return tu
}

// ── route matching ────────────────────────────────────────────────────────────

func TestHandler_404OnNoRouteMatch(t *testing.T) {
	upstream := newTestUpstream(http.StatusOK, "hello")
	defer upstream.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	h, err := gateway.NewHandler(cfg, nil, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(),http.MethodGet, "http://other.internal/orders", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandler_MatchByHostAndPath(t *testing.T) {
	upstream := newTestUpstream(http.StatusOK, "matched")
	defer upstream.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	h, err := gateway.NewHandler(cfg, nil, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(),http.MethodGet, "http://api.internal/orders", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != "matched" {
		t.Errorf("unexpected body: %q", body)
	}
}

func TestHandler_LongestPathPrefixWins(t *testing.T) {
	rootUpstream := newTestUpstream(http.StatusOK, "root")
	defer rootUpstream.Close()
	v2Upstream := newTestUpstream(http.StatusOK, "v2")
	defer v2Upstream.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "root",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: rootUpstream.URL},
			Authn:    config.AuthnConfig{Required: false},
		},
		{
			ID:       "v2",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/v2"},
			Upstream: config.UpstreamConfig{URL: v2Upstream.URL},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	h, err := gateway.NewHandler(cfg, nil, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	tests := []struct {
		path     string
		wantBody string
	}{
		{"/v2/orders", "v2"},
		{"/v1/orders", "root"},
		{"/orders", "root"},
	}
	for _, tc := range tests {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(),http.MethodGet, "http://api.internal"+tc.path, nil)
		h.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		if string(body) != tc.wantBody {
			t.Errorf("path %s: expected body %q, got %q", tc.path, tc.wantBody, body)
		}
	}
}

func TestHandler_HostMismatchIs404(t *testing.T) {
	upstream := newTestUpstream(http.StatusOK, "ok")
	defer upstream.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	h, err := gateway.NewHandler(cfg, nil, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(),http.MethodGet, "http://other.internal/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 on host mismatch, got %d", rec.Code)
	}
}

// ── header stripping ──────────────────────────────────────────────────────────

func TestHandler_StripsBulwarkHeadersFromUpstream(t *testing.T) {
	upstream := newTestUpstream(http.StatusOK, "ok")
	defer upstream.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	h, err := gateway.NewHandler(cfg, nil, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(),http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("X-Bulwark-Subject", "attacker")
	req.Header.Set("X-Bulwark-Groups", "admins")
	req.Header.Set("X-Bulwark-Custom", "injected")
	h.ServeHTTP(rec, req)

	if upstream.lastReq == nil {
		t.Fatal("upstream did not receive request")
	}
	for _, name := range []string{"X-Bulwark-Subject", "X-Bulwark-Groups", "X-Bulwark-Custom"} {
		if upstream.lastReq.Header.Get(name) != "" {
			t.Errorf("upstream received header %q that should have been stripped", name)
		}
	}
}

func TestHandler_PreservesNonBulwarkHeaders(t *testing.T) {
	upstream := newTestUpstream(http.StatusOK, "ok")
	defer upstream.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	h, err := gateway.NewHandler(cfg, nil, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(),http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	if upstream.lastReq == nil {
		t.Fatal("upstream did not receive request")
	}
	// Phase 1: Authorization header is not yet stripped (that happens in Phase 6).
	// Non-Bulwark headers must pass through.
	if upstream.lastReq.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type not forwarded to upstream")
	}
}

// ── upstream errors ───────────────────────────────────────────────────────────

func TestHandler_502OnUnreachableUpstream(t *testing.T) {
	// Start a server, capture its URL, then close it so it's unreachable.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: deadURL},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	h, err := gateway.NewHandler(cfg, nil, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(),http.MethodGet, "http://api.internal/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rec.Code)
	}
}

func TestHandler_UpstreamErrorStatusProxied(t *testing.T) {
	upstream := newTestUpstream(http.StatusInternalServerError, "upstream error")
	defer upstream.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	h, err := gateway.NewHandler(cfg, nil, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(),http.MethodGet, "http://api.internal/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected upstream 500 to be proxied, got %d", rec.Code)
	}
}

// ── audit ─────────────────────────────────────────────────────────────────────

func TestHandler_AuditEventEmitted(t *testing.T) {
	upstream := newTestUpstream(http.StatusOK, "ok")
	defer upstream.Close()

	var captured []audit.Event
	logger := &captureLogger{events: &captured}

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	h, err := gateway.NewHandler(cfg, nil, logger)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(),http.MethodGet, "http://api.internal/orders", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	h.ServeHTTP(rec, req)

	if len(captured) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(captured))
	}
	ev := captured[0]
	if ev.RequestID == "" {
		t.Error("audit event missing request_id")
	}
	if ev.Method != http.MethodGet {
		t.Errorf("unexpected method: %q", ev.Method)
	}
	if ev.Host != "api.internal" {
		t.Errorf("unexpected host: %q", ev.Host)
	}
	if ev.Path != "/orders" {
		t.Errorf("unexpected path: %q", ev.Path)
	}
	if ev.StatusCode != http.StatusOK {
		t.Errorf("unexpected status: %d", ev.StatusCode)
	}
	if ev.ClientIP != "10.0.0.1" {
		t.Errorf("unexpected client_ip: %q", ev.ClientIP)
	}
	if ev.Upstream == "" {
		t.Error("audit event missing upstream")
	}
}

func TestHandler_AuditEventOn404(t *testing.T) {
	var captured []audit.Event
	logger := &captureLogger{events: &captured}

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: "http://localhost:1"},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	h, err := gateway.NewHandler(cfg, nil, logger)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(),http.MethodGet, "http://no-match.internal/", nil)
	h.ServeHTTP(rec, req)

	if len(captured) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(captured))
	}
	if captured[0].StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 in audit event, got %d", captured[0].StatusCode)
	}
	if captured[0].Upstream != "" {
		t.Errorf("expected empty upstream on 404, got %q", captured[0].Upstream)
	}
}

// ── authn pipeline ────────────────────────────────────────────────────────────

// stubAuth is a configurable authn.Authenticator for gateway pipeline tests.
type stubAuth struct {
	id  *identity.VerifiedIdentity
	err error
}

func (s *stubAuth) Authenticate(_ *http.Request) (*identity.VerifiedIdentity, error) {
	return s.id, s.err
}

func TestHandler_AuthnRequired_NoCredentials_Returns401(t *testing.T) {
	upstream := newTestUpstream(http.StatusOK, "ok")
	defer upstream.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: true},
		},
	})
	auth := map[string]authn.Authenticator{
		"r1": &stubAuth{err: errors.New("no credentials provided")},
	}
	h, err := gateway.NewHandler(cfg, auth, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestHandler_AuthnRequired_ValidCredentials_Proxied(t *testing.T) {
	upstream := newTestUpstream(http.StatusOK, "ok")
	defer upstream.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: true},
		},
	})
	verifiedID := &identity.VerifiedIdentity{
		Principal:      "oidc:auth.example.com:svc-123",
		Issuer:         "https://auth.example.com",
		AuthMethods:    []identity.AuthMethod{identity.AuthOIDC},
		AssuranceScore: 15,
	}
	auth := map[string]authn.Authenticator{
		"r1": &stubAuth{id: verifiedID},
	}
	h, err := gateway.NewHandler(cfg, auth, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandler_AuthnOptional_NoCredentials_Proxied(t *testing.T) {
	upstream := newTestUpstream(http.StatusOK, "ok")
	defer upstream.Close()

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: false},
		},
	})
	// Optional authn returns nil identity (no credentials) — should still proxy.
	auth := map[string]authn.Authenticator{
		"r1": &stubAuth{id: nil, err: nil},
	}
	h, err := gateway.NewHandler(cfg, auth, silentAudit())
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandler_AuditEventIncludesIdentity(t *testing.T) {
	upstream := newTestUpstream(http.StatusOK, "ok")
	defer upstream.Close()

	var captured []audit.Event
	logger := &captureLogger{events: &captured}

	cfg := newTestConfig([]config.RouteConfig{
		{
			ID:       "r1",
			Match:    config.MatchConfig{Host: "api.internal", PathPrefix: "/"},
			Upstream: config.UpstreamConfig{URL: upstream.URL},
			Authn:    config.AuthnConfig{Required: true},
		},
	})
	verifiedID := &identity.VerifiedIdentity{
		Principal:      "spiffe://example.com/svc",
		Issuer:         "https://spire.example.com",
		AuthMethods:    []identity.AuthMethod{identity.AuthSPIFFEJWT},
		AssuranceScore: 25,
	}
	auth := map[string]authn.Authenticator{
		"r1": &stubAuth{id: verifiedID},
	}
	h, err := gateway.NewHandler(cfg, auth, logger)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/orders", nil)
	h.ServeHTTP(rec, req)

	if len(captured) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(captured))
	}
	ev := captured[0]
	if ev.Identity == nil {
		t.Fatal("expected identity in audit event")
	}
	if ev.Identity.Principal != verifiedID.Principal {
		t.Errorf("principal: got %q, want %q", ev.Identity.Principal, verifiedID.Principal)
	}
	if ev.Identity.AssuranceScore != 25 {
		t.Errorf("score: got %d, want 25", ev.Identity.AssuranceScore)
	}
}

// captureLogger records emitted audit events for inspection in tests.
type captureLogger struct {
	events *[]audit.Event
}

func (l *captureLogger) Emit(e audit.Event) {
	*l.events = append(*l.events, e)
}
