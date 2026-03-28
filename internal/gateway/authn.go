package gateway

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/stormbane-security/bulwark/internal/authn"
	authnoidc "github.com/stormbane-security/bulwark/internal/authn/oidc"
	authnspiffe "github.com/stormbane-security/bulwark/internal/authn/spiffe"
	"github.com/stormbane-security/bulwark/internal/config"
	"github.com/stormbane-security/bulwark/internal/identity"
)

// BuildAuthn constructs a per-route map of Authenticators from cfg.
// Each route that references trust anchors gets a MultiAuthn wrapping all of
// its configured authenticators. Routes with no trust anchors are not included
// in the returned map (authn is skipped for those routes).
//
// cache is the process-level jwk.Cache whose background goroutines are tied to
// the server context (created via jwk.NewCache(serverCtx) in serve.go).
func BuildAuthn(cfg *config.Config, cache *jwk.Cache) (map[string]authn.Authenticator, error) {
	// Index trust anchors by ID for O(1) lookup.
	anchors := make(map[string]*config.TrustAnchorConfig, len(cfg.TrustAnchors))
	for i := range cfg.TrustAnchors {
		a := &cfg.TrustAnchors[i]
		anchors[a.ID] = a
	}

	result := make(map[string]authn.Authenticator)

	for _, route := range cfg.Routes {
		if len(route.Authn.Trust) == 0 {
			continue
		}

		var authenticators []authn.Authenticator
		for _, anchorID := range route.Authn.Trust {
			anchor, ok := anchors[anchorID]
			if !ok {
				// Validation should have caught this, but be defensive.
				return nil, fmt.Errorf("gateway: route %q references unknown trust anchor %q", route.ID, anchorID)
			}
			a, err := buildAuthenticator(anchor, cache)
			if err != nil {
				return nil, fmt.Errorf("gateway: route %q, anchor %q: %w", route.ID, anchorID, err)
			}
			authenticators = append(authenticators, a)
		}

		result[route.ID] = authn.NewMultiAuthn(authenticators, route.Authn.Required, route.Authn.MinScore)
	}

	return result, nil
}

func buildAuthenticator(anchor *config.TrustAnchorConfig, cache *jwk.Cache) (authn.Authenticator, error) {
	score := anchor.Score

	switch anchor.Type {
	case "oidc":
		if score == 0 {
			score = identity.DefaultScores[identity.EvidenceJWT]
		}
		v, err := authnoidc.New(anchor.Issuer, anchor.Audience, anchor.JWKSUri, score, cache, anchor.PrincipalPrefix)
		if err != nil {
			return nil, err
		}
		if err := v.Register(); err != nil {
			return nil, fmt.Errorf("registering JWKS URI %q: %w", anchor.JWKSUri, err)
		}
		return v, nil

	case "spiffe_jwt":
		if score == 0 {
			score = identity.DefaultScores[identity.EvidenceSPIFFEJWT]
		}
		v, err := authnspiffe.New(anchor.Issuer, anchor.Audience, anchor.JWKSUri, anchor.SpiffeTrustDomain, score, cache)
		if err != nil {
			return nil, err
		}
		if err := v.Register(); err != nil {
			return nil, fmt.Errorf("registering JWKS URI %q: %w", anchor.JWKSUri, err)
		}
		return v, nil

	default:
		return nil, fmt.Errorf("unsupported trust anchor type %q (mtls and http_sig are not yet implemented)", anchor.Type)
	}
}
