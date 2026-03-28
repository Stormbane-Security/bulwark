// Package oidc implements JWT Bearer token authentication via a remote JWKS endpoint.
package oidc

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

// Validator validates JWT Bearer tokens against a remote JWKS endpoint.
// One shared jwk.Cache is used per process; each Validator registers its URI.
type Validator struct {
	issuer          string
	audience        string
	score           int
	jwksURI         string
	cache           *jwk.Cache
	principalPrefix string // if set, principal = prefix:sub; else oidc:<host>:<sub>
}

// New creates a Validator. cache is the process-level shared jwk.Cache created
// at server startup with a context tied to the server lifetime.
func New(issuer, audience, jwksURI string, score int, cache *jwk.Cache, principalPrefix string) (*Validator, error) {
	if issuer == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}
	if jwksURI == "" {
		return nil, fmt.Errorf("oidc: jwks_uri is required")
	}
	if _, err := url.Parse(jwksURI); err != nil {
		return nil, fmt.Errorf("oidc: invalid jwks_uri %q: %w", jwksURI, err)
	}
	return &Validator{
		issuer:          issuer,
		audience:        audience,
		jwksURI:         jwksURI,
		score:           score,
		cache:           cache,
		principalPrefix: principalPrefix,
	}, nil
}

// Register adds the JWKS URI to the shared cache for background refresh.
// Must be called once after New and before any Authenticate calls.
func (v *Validator) Register() error {
	return v.cache.Register(v.jwksURI)
}

// Authenticate validates the Bearer JWT in the Authorization header.
// Returns ErrNotApplicable if no Bearer token is present.
// Returns a non-nil error (causing 401) if the token is present but invalid.
func (v *Validator) Authenticate(req *http.Request) (*identity.VerifiedIdentity, error) {
	raw := bearerToken(req)
	if raw == "" {
		return nil, authn.ErrNotApplicable
	}

	keySet, err := v.cache.Get(req.Context(), v.jwksURI)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetching JWKS for issuer %q: %w", v.issuer, err)
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
		return nil, fmt.Errorf("oidc: invalid token: %w", err)
	}

	sub := token.Subject()
	return &identity.VerifiedIdentity{
		Principal:      v.normalizePrincipal(sub),
		Issuer:         v.issuer,
		AuthMethods:    []identity.AuthMethod{identity.AuthOIDC},
		AssuranceScore: v.score,
		Evidence: []identity.IdentityEvidence{
			{
				Type:      identity.EvidenceJWT,
				Issuer:    v.issuer,
				Subject:   sub,
				ExpiresAt: token.Expiration(),
				Score:     v.score,
			},
		},
	}, nil
}

func (v *Validator) normalizePrincipal(sub string) string {
	if v.principalPrefix != "" {
		return v.principalPrefix + ":" + sub
	}
	// Default format: oidc:<issuer-host>:<sub>
	issuerHost := v.issuer
	if u, err := url.Parse(v.issuer); err == nil && u.Host != "" {
		issuerHost = u.Host
	}
	return "oidc:" + issuerHost + ":" + sub
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	return strings.TrimPrefix(auth, prefix)
}
