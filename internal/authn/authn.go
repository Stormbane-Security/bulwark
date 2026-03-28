// Package authn defines the Authenticator interface and the MultiAuthn composite
// that runs all configured authenticators for a request.
package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/stormbane-security/bulwark/internal/identity"
)

// ErrNotApplicable signals that this authenticator has no credentials to
// inspect in the request (e.g. no Authorization header for a JWT authenticator,
// or no client cert for an mTLS authenticator). MultiAuthn silently skips it.
//
// Any other non-nil error means credentials were present but invalid — this
// causes an immediate 401 with no fallback to a lower assurance level.
var ErrNotApplicable = errors.New("authenticator not applicable to this request")

// Authenticator validates credentials in an HTTP request and returns a
// VerifiedIdentity on success.
//
// Implementations must return ErrNotApplicable if no relevant credentials are
// present. Malformed or invalid credentials must always return a non-nil error
// other than ErrNotApplicable — they must never silently degrade to anonymous.
type Authenticator interface {
	Authenticate(req *http.Request) (*identity.VerifiedIdentity, error)
}

// TrustEnricher enriches a VerifiedIdentity with additional context.
// In v1 this is a no-op; Anchor will plug in here in a future phase.
type TrustEnricher interface {
	Enrich(ctx context.Context, id *identity.VerifiedIdentity) (*identity.VerifiedIdentity, error)
}

// NoopEnricher implements TrustEnricher as a pass-through.
type NoopEnricher struct{}

// Enrich returns the identity unchanged.
func (NoopEnricher) Enrich(_ context.Context, id *identity.VerifiedIdentity) (*identity.VerifiedIdentity, error) {
	return id, nil
}

// MultiAuthn runs all configured authenticators for a request, collects
// evidence from each that succeeds, sums their assurance scores, correlates
// to a single principal, and enforces MinScore.
type MultiAuthn struct {
	authenticators []Authenticator
	required       bool
	minScore       int
}

// NewMultiAuthn creates a MultiAuthn.
//   - authenticators: the set of authenticators to run (in order).
//   - required: if true, at least one authenticator must succeed (else 401).
//   - minScore: minimum combined assurance score required (0 = no minimum).
func NewMultiAuthn(authenticators []Authenticator, required bool, minScore int) *MultiAuthn {
	return &MultiAuthn{
		authenticators: authenticators,
		required:       required,
		minScore:       minScore,
	}
}

// Authenticate runs all configured authenticators and returns a merged
// VerifiedIdentity.
//
//   - Returns nil, nil if !required and no credentials are present.
//   - Returns an error if required and no credentials, score is too low,
//     principals conflict, or any authenticator reports invalid credentials.
func (m *MultiAuthn) Authenticate(req *http.Request) (*identity.VerifiedIdentity, error) {
	var collected []*identity.VerifiedIdentity

	for _, auth := range m.authenticators {
		id, err := auth.Authenticate(req)
		if errors.Is(err, ErrNotApplicable) {
			continue
		}
		if err != nil {
			// Credentials were present but invalid — hard 401, no fallback.
			return nil, err
		}
		if id == nil {
			// Returning (nil, nil) violates the Authenticator contract — the correct
			// signal for "no credentials" is ErrNotApplicable. Treat it defensively
			// as not-applicable rather than appending a nil pointer that would panic
			// in merge.
			continue
		}
		collected = append(collected, id)
	}

	if len(collected) == 0 {
		if m.required {
			return nil, errors.New("no credentials provided")
		}
		return nil, nil // optional + no credentials = unauthenticated request (allowed)
	}

	merged, err := merge(collected)
	if err != nil {
		return nil, err
	}

	if m.minScore > 0 && merged.AssuranceScore < m.minScore {
		return nil, fmt.Errorf("insufficient assurance score: got %d, need %d",
			merged.AssuranceScore, m.minScore)
	}

	return merged, nil
}

// merge combines multiple VerifiedIdentities from different authenticators
// into a single identity with additive scores. Returns an error if two
// authenticators assert different principals.
func merge(ids []*identity.VerifiedIdentity) (*identity.VerifiedIdentity, error) {
	if len(ids) == 1 {
		return ids[0], nil
	}

	primary := ids[0]
	for _, id := range ids[1:] {
		if id.Principal != primary.Principal {
			return nil, fmt.Errorf("conflicting principals: %q and %q",
				primary.Principal, id.Principal)
		}
	}

	merged := &identity.VerifiedIdentity{
		Principal: primary.Principal,
		Issuer:    primary.Issuer,
		Claims:    primary.Claims,
	}
	for _, id := range ids {
		merged.AuthMethods = append(merged.AuthMethods, id.AuthMethods...)
		merged.Evidence = append(merged.Evidence, id.Evidence...)
		merged.AssuranceScore += id.AssuranceScore
		merged.Groups = append(merged.Groups, id.Groups...)
	}

	return merged, nil
}
