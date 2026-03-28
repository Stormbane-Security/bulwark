// Package proxy provides a thin wrapper around httputil.ReverseProxy.
package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// New returns an http.Handler that reverse-proxies requests to target.
// target must be a valid http or https URL (e.g. "http://upstream:8080").
// Write errors from the upstream are returned as 502 Bad Gateway.
func New(target string) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid target URL %q: %w", target, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("proxy: target URL scheme must be http or https, got %q", u.Scheme)
	}

	rp := httputil.NewSingleHostReverseProxy(u)

	// Replace the default error handler (which logs to stderr) with one that
	// writes 502 silently. The gateway audit log records the error.
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, _ error) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return rp, nil
}
