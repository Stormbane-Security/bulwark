// Package spiffe implements SPIFFE JWT SVID authentication via a JWKS endpoint.
package spiffe

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/stormbane-security/bulwark/internal/authn"
	"github.com/stormbane-security/bulwark/internal/identity"
)

// Validator validates SPIFFE JWT SVIDs from a JWKS endpoint.
// The token subject must be a spiffe:// URI.
type Validator struct {
	issuer      string
	audience    string
	score       int
	jwksURI     string
	cache       *jwk.Cache
	trustDomain string // if non-empty and not "*", subjects must match spiffe://<domain>/
}

// New creates a Validator. cache is the process-level shared jwk.Cache.
// trustDomain restricts accepted SPIFFE IDs to a specific domain
// (e.g. "example.com"). Pass "" to accept any valid SPIFFE URI, or "*" to
// explicitly accept all trust domains (emits no extra check).
func New(issuer, audience, jwksURI, trustDomain string, score int, cache *jwk.Cache) (*Validator, error) {
	if issuer == "" {
		return nil, fmt.Errorf("spiffe: issuer is required")
	}
	if jwksURI == "" {
		return nil, fmt.Errorf("spiffe: jwks_uri is required")
	}
	if _, err := url.Parse(jwksURI); err != nil {
		return nil, fmt.Errorf("spiffe: invalid jwks_uri %q: %w", jwksURI, err)
	}
	return &Validator{
		issuer:      issuer,
		audience:    audience,
		jwksURI:     jwksURI,
		score:       score,
		cache:       cache,
		trustDomain: trustDomain,
	}, nil
}

// Register adds the JWKS URI to the shared cache for background refresh.
// Must be called once after New and before any Authenticate calls.
func (v *Validator) Register() error {
	return v.cache.Register(v.jwksURI)
}

// Authenticate validates the SPIFFE JWT SVID Bearer token in the Authorization header.
// Returns ErrNotApplicable if no Bearer token is present.
// Returns a non-nil error (causing 401) if the token is present but invalid,
// or if the subject is not a SPIFFE URI, or if it doesn't match the configured
// trust domain.
func (v *Validator) Authenticate(req *http.Request) (*identity.VerifiedIdentity, error) {
	raw, hasBearer := bearerToken(req)
	if !hasBearer {
		return nil, authn.ErrNotApplicable
	}
	if raw == "" {
		return nil, fmt.Errorf("spiffe: empty Bearer token")
	}

	keySet, err := v.cache.Get(req.Context(), v.jwksURI)
	if err != nil {
		return nil, fmt.Errorf("spiffe: fetching JWKS for issuer %q: %w", v.issuer, err)
	}

	opts := []jwt.ParseOption{
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
	}
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}

	token, err := jwt.Parse([]byte(raw), opts...)
	if err != nil {
		return nil, fmt.Errorf("spiffe: invalid token: %w", err)
	}

	sub := token.Subject()
	if !strings.HasPrefix(sub, "spiffe://") {
		return nil, fmt.Errorf("spiffe: token subject %q is not a SPIFFE URI", sub)
	}
	if v.trustDomain != "" && v.trustDomain != "*" {
		expected := "spiffe://" + v.trustDomain + "/"
		if !strings.HasPrefix(sub, expected) {
			return nil, fmt.Errorf("spiffe: subject %q does not belong to trust domain %q", sub, v.trustDomain)
		}
	}

	return &identity.VerifiedIdentity{
		Principal:      sub, // SPIFFE URI is the principal directly
		Issuer:         v.issuer,
		AuthMethods:    []identity.AuthMethod{identity.AuthSPIFFEJWT},
		AssuranceScore: v.score,
		Evidence: []identity.IdentityEvidence{
			{
				Type:      identity.EvidenceSPIFFEJWT,
				Issuer:    v.issuer,
				Subject:   sub,
				ExpiresAt: token.Expiration(),
				Score:     v.score,
			},
		},
	}, nil
}

// bearerToken extracts the token value from a Bearer Authorization header.
// Returns ("", false) if no Bearer header is present (ErrNotApplicable).
// Returns ("", true) if the header is present but the token part is empty (hard 401).
// Returns (token, true) for a non-empty token.
func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return "", false
	}
	return strings.TrimPrefix(auth, prefix), true
}
