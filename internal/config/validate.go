package config

import (
	"fmt"
	"net/url"
)

// validate runs structural and semantic validation on a parsed Config.
func validate(cfg *Config) error {
	if len(cfg.Listeners) == 0 {
		return fmt.Errorf("config: at least one listener is required")
	}
	if len(cfg.Routes) == 0 {
		return fmt.Errorf("config: at least one route is required")
	}

	// Build policy ID set for reference checking; reject duplicates.
	policyIDs := make(map[string]struct{}, len(cfg.Policies))
	for i, p := range cfg.Policies {
		if _, exists := policyIDs[p.ID]; exists {
			return fmt.Errorf("config: policies[%d]: duplicate policy id %q", i, p.ID)
		}
		policyIDs[p.ID] = struct{}{}
	}

	// Build trust anchor ID set for reference checking; reject duplicates.
	anchorIDs := make(map[string]struct{}, len(cfg.TrustAnchors))
	for i, a := range cfg.TrustAnchors {
		if a.ID == "" {
			return fmt.Errorf("config: trust_anchors[%d]: id is required", i)
		}
		if _, exists := anchorIDs[a.ID]; exists {
			return fmt.Errorf("config: trust_anchors[%d]: duplicate trust anchor id %q", i, a.ID)
		}
		anchorIDs[a.ID] = struct{}{}
		if err := validateTrustAnchor(i, &cfg.TrustAnchors[i]); err != nil {
			return err
		}
	}

	for i := range cfg.Listeners {
		if err := validateListener(i, &cfg.Listeners[i]); err != nil {
			return err
		}
	}

	// Check for duplicate route IDs before validating individual routes.
	routeIDs := make(map[string]struct{}, len(cfg.Routes))
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		if r.ID != "" {
			if _, exists := routeIDs[r.ID]; exists {
				return fmt.Errorf("config: routes[%d]: duplicate route id %q", i, r.ID)
			}
			routeIDs[r.ID] = struct{}{}
		}
		if err := validateRoute(i, r, policyIDs, anchorIDs); err != nil {
			return err
		}
		// Apply defaults after validation so checks see the operator-supplied value.
		// Use &cfg.Routes[i], not a loop copy, so the assignment persists.
		if r.Match.PathPrefix == "" {
			r.Match.PathPrefix = "/"
		}
	}

	return nil
}

func validateListener(i int, l *ListenerConfig) error {
	if l.Addr == "" {
		return fmt.Errorf("config: listeners[%d]: addr is required", i)
	}
	if l.TLS != nil {
		if l.TLS.CertFile == "" {
			return fmt.Errorf("config: listeners[%d].tls: cert is required", i)
		}
		if l.TLS.KeyFile == "" {
			return fmt.Errorf("config: listeners[%d].tls: key is required", i)
		}
	}
	// mTLS without a CA bundle means Bulwark has no basis for verifying client certs.
	if l.MTLS != nil && l.MTLS.Enabled && l.MTLS.CABundle == "" {
		return fmt.Errorf("config: listeners[%d].mtls: ca_bundle is required when mtls is enabled", i)
	}
	return nil
}

func validateRoute(i int, r *RouteConfig, policyIDs, anchorIDs map[string]struct{}) error {
	if r.ID == "" {
		return fmt.Errorf("config: routes[%d]: id is required", i)
	}
	if r.Match.Host == "" {
		return fmt.Errorf("config: routes[%d]: match.host is required", i)
	}
	if err := validateUpstreamURL(i, r.Upstream.URL); err != nil {
		return err
	}
	if r.Upstream.Auth != nil {
		if err := validateUpstreamAuth(i, r.Upstream.Auth); err != nil {
			return err
		}
	}
	// required:true with no issuers and no trust anchors is a broken config.
	if r.Authn.Required && len(r.Authn.Issuers) == 0 && len(r.Authn.Trust) == 0 {
		return fmt.Errorf("config: routes[%d].authn: at least one issuer or trust anchor is required when authn.required is true", i)
	}
	for j := range r.Authn.Issuers {
		if err := validateIssuer(i, j, &r.Authn.Issuers[j]); err != nil {
			return err
		}
	}
	for j, anchorID := range r.Authn.Trust {
		if _, ok := anchorIDs[anchorID]; !ok {
			return fmt.Errorf("config: routes[%d].authn.trust[%d]: trust anchor %q is not defined", i, j, anchorID)
		}
	}
	if r.Policy != "" {
		if _, ok := policyIDs[r.Policy]; !ok {
			return fmt.Errorf("config: routes[%d]: policy %q is referenced but not defined", i, r.Policy)
		}
	}
	return nil
}

func validateUpstreamURL(routeIdx int, rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("config: routes[%d]: upstream.url is required", routeIdx)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("config: routes[%d]: upstream.url is not a valid URL: %w", routeIdx, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("config: routes[%d]: upstream.url scheme must be http or https, got %q", routeIdx, u.Scheme)
	}
	return nil
}

var validUpstreamAuthTypes = map[string]struct{}{
	"bulwark_jwt":   {},
	"mtls":          {},
	"static_bearer": {},
}

func validateUpstreamAuth(routeIdx int, auth *UpstreamAuth) error {
	if _, ok := validUpstreamAuthTypes[auth.Type]; !ok {
		return fmt.Errorf("config: routes[%d].upstream.auth: invalid type %q (must be bulwark_jwt, mtls, or static_bearer)", routeIdx, auth.Type)
	}
	return nil
}

var validTrustAnchorTypes = map[string]struct{}{
	"oidc":       {},
	"mtls":       {},
	"spiffe_jwt": {},
	"http_sig":   {},
}

func validateTrustAnchor(i int, a *TrustAnchorConfig) error {
	if _, ok := validTrustAnchorTypes[a.Type]; !ok {
		return fmt.Errorf("config: trust_anchors[%d] %q: invalid type %q (must be oidc, mtls, spiffe_jwt, or http_sig)", i, a.ID, a.Type)
	}
	switch a.Type {
	case "oidc", "spiffe_jwt":
		if a.Issuer == "" {
			return fmt.Errorf("config: trust_anchors[%d] %q: issuer is required for type %q", i, a.ID, a.Type)
		}
		if a.JWKSUri == "" {
			return fmt.Errorf("config: trust_anchors[%d] %q: jwks_uri is required for type %q", i, a.ID, a.Type)
		}
	}
	return nil
}

var validIssuerTypes = map[string]struct{}{
	"oidc":       {},
	"mtls":       {},
	"spiffe_jwt": {},
}

func validateIssuer(routeIdx, issuerIdx int, issuer *IssuerConfig) error {
	if _, ok := validIssuerTypes[issuer.Type]; !ok {
		return fmt.Errorf("config: routes[%d].authn.issuers[%d]: invalid type %q (must be oidc, mtls, or spiffe_jwt)", routeIdx, issuerIdx, issuer.Type)
	}
	return nil
}
