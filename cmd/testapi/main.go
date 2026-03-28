// testapi is a simple upstream service used for local development and
// integration testing of Bulwark. It exposes endpoints that correspond to the
// Rego policy rules written in Phase 4, and echoes the identity context
// Bulwark injects so you can verify the full auth flow end-to-end.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", ":9090", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/public", makeHandler("/public", "no auth required"))
	mux.HandleFunc("/orders", makeHandler("/orders",
		"GET: any authenticated identity (min_score >= 15)\nPOST: min_score >= 30"))
	mux.HandleFunc("/admin", makeHandler("/admin", "requires group: admin"))
	mux.HandleFunc("/payments", makeHandler("/payments",
		"POST: requires MTLS_SPIFFE + min_score >= 55"))
	mux.HandleFunc("/wallet", makeHandler("/wallet",
		"requires eth: principal (wallet-aware OIDC via Web3Auth/Privy)"))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "testapi listening on %s\n", *addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// makeHandler returns a handler that echoes the request and Bulwark-injected
// identity context as JSON. The policy note documents the Rego rule that
// Bulwark enforces on this endpoint — enforcement is in Bulwark, not here.
func makeHandler(path, policyNote string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"endpoint":          path,
			"rego_policy_note":  policyNote,
			"request": map[string]string{
				"method":      r.Method,
				"path":        r.URL.Path,
				"remote_addr": r.RemoteAddr,
			},
			"identity": extractIdentity(r),
		})
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// extractIdentity reads the identity headers and JWT that Bulwark injects
// after authentication. In Phase 1 these will be absent (no auth yet).
// After Phase 5 (JWT minting) and Phase 6 (header injection) they will carry
// the verified caller's principal, groups, and assurance score.
func extractIdentity(r *http.Request) map[string]string {
	id := map[string]string{}

	// Standard proxy headers injected by Bulwark post-auth (Phase 6).
	for _, h := range []string{"X-Remote-User", "X-Remote-Groups", "X-Forwarded-User",
		"X-Bulwark-Subject", "X-Bulwark-Groups", "X-Bulwark-Auth-Method"} {
		if v := r.Header.Get(h); v != "" {
			id[strings.ToLower(strings.ReplaceAll(h, "-", "_"))] = v
		}
	}

	// Bulwark-signed gateway JWT (Phase 5 — inject: jwt mode).
	// A real upstream validates this against Bulwark's JWKS endpoint.
	// Here we decode the sub claim for display only — NOT verifying the signature.
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		id["bearer_present"] = "true"
		if sub := jwtSubUnsafe(strings.TrimPrefix(auth, "Bearer ")); sub != "" {
			id["jwt_sub"] = sub
		}
	}

	if len(id) == 0 {
		id["_note"] = "no identity headers — auth not wired yet (Phase 1)"
	}
	return id
}

// jwtSubUnsafe extracts the sub claim from a JWT without verifying the
// signature. Used only for display in this test API.
func jwtSubUnsafe(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	sub, _ := claims["sub"].(string)
	return sub
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
