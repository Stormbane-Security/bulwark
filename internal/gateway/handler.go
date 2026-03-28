// Package gateway implements the Bulwark request pipeline.
package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/stormbane-security/bulwark/internal/audit"
	"github.com/stormbane-security/bulwark/internal/authn"
	"github.com/stormbane-security/bulwark/internal/config"
	"github.com/stormbane-security/bulwark/internal/identity"
	"github.com/stormbane-security/bulwark/internal/proxy"
)

const bulwarkHeaderPrefix = "X-Bulwark-"

// Handler is the Bulwark HTTP handler.
// Pipeline (sequential):
//  1. Strip all X-Bulwark-* inbound headers (unconditional)
//  2. Route match → 404 on no match
//  3. Authn (if configured for route) → 401 on failure
//  4. Proxy to upstream → 502 on transport failure
//  5. Emit audit event (non-blocking)
type Handler struct {
	router         *router
	proxies        map[string]http.Handler    // route ID → upstream proxy
	authenticators map[string]authn.Authenticator // route ID → authenticator (nil = no authn)
	auditLog       audit.Logger
}

// NewHandler constructs a Handler from cfg. Returns an error if any upstream
// URL is invalid.
// authenticators is the per-route authn map from BuildAuthn; pass nil or an
// empty map for routes that have no trust anchors configured.
func NewHandler(cfg *config.Config, authenticators map[string]authn.Authenticator, auditLog audit.Logger) (*Handler, error) {
	proxies := make(map[string]http.Handler, len(cfg.Routes))
	for _, r := range cfg.Routes {
		p, err := proxy.New(r.Upstream.URL)
		if err != nil {
			return nil, fmt.Errorf("gateway: route %q: %w", r.ID, err)
		}
		proxies[r.ID] = p
	}
	if authenticators == nil {
		authenticators = make(map[string]authn.Authenticator)
	}
	return &Handler{
		router:         newRouter(cfg.Routes),
		proxies:        proxies,
		authenticators: authenticators,
		auditLog:       auditLog,
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

	// Normalize the URL path to prevent route confusion via path traversal.
	// Without this, /public/../admin resolves to /admin on the upstream while
	// matching the /public route here — potentially bypassing auth on /admin.
	// We normalize both Path and RawPath so the proxy forwards the clean path.
	rawPath := r.URL.Path
	if rawPath == "" {
		rawPath = "/"
	}
	if cleaned := path.Clean(rawPath); cleaned != rawPath {
		r.URL.Path = cleaned
		r.URL.RawPath = "" // stale RawPath is cleared; proxy re-derives from Path
	}

	// Step 2: Route match.
	matched := h.router.match(r)
	if matched == nil {
		rw := &responseWriter{ResponseWriter: w, status: http.StatusNotFound}
		http.Error(rw, "not found", http.StatusNotFound)
		h.emitAudit(reqID, start, r, "", rw.status, nil, nil)
		return
	}

	// Step 3: Authn (if configured for this route).
	var id *identity.VerifiedIdentity
	if auth, ok := h.authenticators[matched.id]; ok {
		var err error
		id, err = auth.Authenticate(r)
		if err != nil {
			errMsg := err.Error()
			rw := &responseWriter{ResponseWriter: w, status: http.StatusUnauthorized}
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			h.emitAudit(reqID, start, r, matched.upstream, rw.status, &errMsg, nil)
			return
		}
	}

	// Step 4: Proxy to upstream.
	rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
	h.proxies[matched.id].ServeHTTP(rw, r)

	// Step 5: Emit audit event.
	h.emitAudit(reqID, start, r, matched.upstream, rw.status, nil, id)
}

func (h *Handler) emitAudit(reqID string, start time.Time, r *http.Request, upstream string, status int, errMsg *string, id *identity.VerifiedIdentity) {
	clientIP := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = ip
	}

	event := audit.Event{
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
	}
	if id != nil {
		methods := make([]string, len(id.AuthMethods))
		for i, m := range id.AuthMethods {
			methods[i] = string(m)
		}
		event.Identity = &audit.IdentityAudit{
			Principal:      id.Principal,
			Issuer:         id.Issuer,
			AuthMethods:    methods,
			AssuranceScore: id.AssuranceScore,
		}
	}

	h.auditLog.Emit(event)
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
