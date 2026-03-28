// Package gateway implements the Bulwark request pipeline.
package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/stormbane-security/bulwark/internal/audit"
	"github.com/stormbane-security/bulwark/internal/config"
	"github.com/stormbane-security/bulwark/internal/proxy"
)

const bulwarkHeaderPrefix = "X-Bulwark-"

// Handler is the Phase 1 Bulwark HTTP handler.
// Pipeline (sequential):
//  1. Strip all X-Bulwark-* inbound headers (unconditional)
//  2. Route match → 404 on no match
//  3. Proxy to upstream → 502 on transport failure
//  4. Emit audit event (non-blocking)
type Handler struct {
	router   *router
	proxies  map[string]http.Handler // route ID → upstream proxy
	auditLog audit.Logger
}

// NewHandler constructs a Handler from cfg. Returns an error if any upstream
// URL is invalid.
func NewHandler(cfg *config.Config, auditLog audit.Logger) (*Handler, error) {
	proxies := make(map[string]http.Handler, len(cfg.Routes))
	for _, r := range cfg.Routes {
		p, err := proxy.New(r.Upstream.URL)
		if err != nil {
			return nil, fmt.Errorf("gateway: route %q: %w", r.ID, err)
		}
		proxies[r.ID] = p
	}
	return &Handler{
		router:   newRouter(cfg.Routes),
		proxies:  proxies,
		auditLog: auditLog,
	}, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := newRequestID()

	// Step 1: Strip all X-Bulwark-* headers from the inbound request.
	// This prevents clients from spoofing identity headers that Bulwark
	// would normally inject after authentication.
	for name := range r.Header {
		if strings.HasPrefix(name, bulwarkHeaderPrefix) {
			r.Header.Del(name)
		}
	}

	// Step 2: Route match.
	matched := h.router.match(r)
	if matched == nil {
		rw := &responseWriter{ResponseWriter: w, status: http.StatusNotFound}
		http.Error(rw, "not found", http.StatusNotFound)
		h.emitAudit(reqID, start, r, "", rw.status, nil)
		return
	}

	// Step 3: Proxy to upstream.
	rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
	h.proxies[matched.id].ServeHTTP(rw, r)

	// Step 4: Emit audit event.
	h.emitAudit(reqID, start, r, matched.upstream, rw.status, nil)
}

func (h *Handler) emitAudit(reqID string, start time.Time, r *http.Request, upstream string, status int, errMsg *string) {
	clientIP := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = ip
	}
	h.auditLog.Emit(audit.Event{
		RequestID:  reqID,
		Timestamp:  start,
		ClientIP:   clientIP,
		Method:     r.Method,
		Host:       r.Host,
		Path:       r.URL.Path,
		Upstream:   upstream,
		StatusCode: status,
		Latency:    time.Since(start),
		Error:      errMsg,
	})
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// responseWriter wraps http.ResponseWriter to capture the response status code
// and forward optional http.Flusher calls (required for streaming proxies).
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
