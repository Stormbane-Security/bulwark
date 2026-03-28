package authn_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stormbane-security/bulwark/internal/authn"
	"github.com/stormbane-security/bulwark/internal/identity"
)

// ── stub authenticators ───────────────────────────────────────────────────────

// stubAuth is a configurable Authenticator for use in tests.
type stubAuth struct {
	id  *identity.VerifiedIdentity
	err error
}

func (s *stubAuth) Authenticate(_ *http.Request) (*identity.VerifiedIdentity, error) {
	return s.id, s.err
}

func okAuth(principal string, score int) *stubAuth {
	return &stubAuth{
		id: &identity.VerifiedIdentity{
			Principal:      principal,
			AssuranceScore: score,
			AuthMethods:    []identity.AuthMethod{identity.AuthOIDC},
			Evidence: []identity.IdentityEvidence{
				{Type: identity.EvidenceJWT, Score: score},
			},
		},
	}
}

func notApplicableAuth() *stubAuth {
	return &stubAuth{err: authn.ErrNotApplicable}
}

func invalidAuth(msg string) *stubAuth {
	return &stubAuth{err: errors.New(msg)}
}

// ── ErrNotApplicable ──────────────────────────────────────────────────────────

func TestMultiAuthn_SkipsNotApplicable(t *testing.T) {
	m := authn.NewMultiAuthn([]authn.Authenticator{
		notApplicableAuth(),
		okAuth("oidc:auth.example.com:user-1", 15),
	}, true, 0)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	id, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == nil || id.Principal != "oidc:auth.example.com:user-1" {
		t.Errorf("unexpected identity: %+v", id)
	}
}

func TestMultiAuthn_AllNotApplicable_RequiredFails(t *testing.T) {
	m := authn.NewMultiAuthn([]authn.Authenticator{
		notApplicableAuth(),
		notApplicableAuth(),
	}, true, 0)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	_, err := m.Authenticate(req)
	if err == nil {
		t.Error("expected error when required=true and no credentials")
	}
}

func TestMultiAuthn_AllNotApplicable_OptionalReturnsNil(t *testing.T) {
	m := authn.NewMultiAuthn([]authn.Authenticator{
		notApplicableAuth(),
	}, false, 0)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	id, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != nil {
		t.Errorf("expected nil identity for optional route with no credentials, got %+v", id)
	}
}

// ── invalid credentials → hard 401 ───────────────────────────────────────────

func TestMultiAuthn_InvalidCredentialsPropagatesError(t *testing.T) {
	wantErr := errors.New("token expired")
	m := authn.NewMultiAuthn([]authn.Authenticator{
		&stubAuth{err: wantErr},
		okAuth("oidc:auth.example.com:user-1", 15),
	}, true, 0)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	_, err := m.Authenticate(req)
	if !errors.Is(err, wantErr) {
		t.Errorf("expected error %v, got %v", wantErr, err)
	}
}

// ── score accumulation ────────────────────────────────────────────────────────

func TestMultiAuthn_AddsScoresAcrossAuthenticators(t *testing.T) {
	m := authn.NewMultiAuthn([]authn.Authenticator{
		okAuth("spiffe://example.com/svc", 30),
		&stubAuth{
			id: &identity.VerifiedIdentity{
				Principal:      "spiffe://example.com/svc",
				AssuranceScore: 25,
				AuthMethods:    []identity.AuthMethod{identity.AuthSPIFFEJWT},
				Evidence: []identity.IdentityEvidence{
					{Type: identity.EvidenceSPIFFEJWT, Score: 25},
				},
			},
		},
	}, true, 0)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	id, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.AssuranceScore != 55 {
		t.Errorf("expected score 55 (30+25), got %d", id.AssuranceScore)
	}
	if len(id.Evidence) != 2 {
		t.Errorf("expected 2 evidence items, got %d", len(id.Evidence))
	}
}

// ── min_score ─────────────────────────────────────────────────────────────────

func TestMultiAuthn_MinScoreEnforced(t *testing.T) {
	m := authn.NewMultiAuthn([]authn.Authenticator{
		okAuth("oidc:auth.example.com:user-1", 15),
	}, true, 30)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	_, err := m.Authenticate(req)
	if err == nil {
		t.Error("expected error when score < min_score")
	}
}

func TestMultiAuthn_MinScorePassed(t *testing.T) {
	m := authn.NewMultiAuthn([]authn.Authenticator{
		okAuth("spiffe://example.com/svc", 30),
	}, true, 30)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	id, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.AssuranceScore != 30 {
		t.Errorf("expected score 30, got %d", id.AssuranceScore)
	}
}

// ── principal correlation ─────────────────────────────────────────────────────

func TestMultiAuthn_ConflictingPrincipalsRejected(t *testing.T) {
	m := authn.NewMultiAuthn([]authn.Authenticator{
		okAuth("oidc:auth.example.com:user-1", 15),
		okAuth("oidc:auth.example.com:user-2", 15),
	}, true, 0)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	_, err := m.Authenticate(req)
	if err == nil {
		t.Error("expected error for conflicting principals")
	}
}

func TestMultiAuthn_MatchingSPIFFEPrincipalsMerged(t *testing.T) {
	spiffeID := "spiffe://example.com/workload/api"
	m := authn.NewMultiAuthn([]authn.Authenticator{
		&stubAuth{
			id: &identity.VerifiedIdentity{
				Principal:      spiffeID,
				AssuranceScore: 30,
				AuthMethods:    []identity.AuthMethod{identity.AuthMTLSSPIFFE},
				Evidence:       []identity.IdentityEvidence{{Type: identity.EvidenceMTLSCert, Score: 30}},
			},
		},
		&stubAuth{
			id: &identity.VerifiedIdentity{
				Principal:      spiffeID,
				AssuranceScore: 25,
				AuthMethods:    []identity.AuthMethod{identity.AuthSPIFFEJWT},
				Evidence:       []identity.IdentityEvidence{{Type: identity.EvidenceSPIFFEJWT, Score: 25}},
			},
		},
	}, true, 0)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	id, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Principal != spiffeID {
		t.Errorf("unexpected principal: %q", id.Principal)
	}
	if id.AssuranceScore != 55 {
		t.Errorf("expected score 55, got %d", id.AssuranceScore)
	}
	if len(id.AuthMethods) != 2 {
		t.Errorf("expected 2 auth methods, got %d", len(id.AuthMethods))
	}
}

// ── empty authenticator list ──────────────────────────────────────────────────

func TestMultiAuthn_NoAuthenticators_Required_Fails(t *testing.T) {
	m := authn.NewMultiAuthn([]authn.Authenticator{}, true, 0)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	_, err := m.Authenticate(req)
	if err == nil {
		t.Error("expected error when required=true and no authenticators configured")
	}
}

func TestMultiAuthn_NoAuthenticators_Optional_ReturnsNil(t *testing.T) {
	m := authn.NewMultiAuthn([]authn.Authenticator{}, false, 0)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	id, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != nil {
		t.Errorf("expected nil identity, got %+v", id)
	}
}

// ── three-way merge ───────────────────────────────────────────────────────────

func TestMultiAuthn_ThreeAuthenticators_SamePrincipal_MergesAll(t *testing.T) {
	principal := "spiffe://example.com/svc"
	m := authn.NewMultiAuthn([]authn.Authenticator{
		&stubAuth{id: &identity.VerifiedIdentity{
			Principal: principal, AssuranceScore: 30,
			AuthMethods: []identity.AuthMethod{identity.AuthMTLSSPIFFE},
			Evidence:    []identity.IdentityEvidence{{Type: identity.EvidenceMTLSCert, Score: 30}},
		}},
		&stubAuth{id: &identity.VerifiedIdentity{
			Principal: principal, AssuranceScore: 25,
			AuthMethods: []identity.AuthMethod{identity.AuthSPIFFEJWT},
			Evidence:    []identity.IdentityEvidence{{Type: identity.EvidenceSPIFFEJWT, Score: 25}},
		}},
		&stubAuth{id: &identity.VerifiedIdentity{
			Principal: principal, AssuranceScore: 15,
			AuthMethods: []identity.AuthMethod{identity.AuthOIDC},
			Evidence:    []identity.IdentityEvidence{{Type: identity.EvidenceJWT, Score: 15}},
		}},
	}, true, 0)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	id, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.AssuranceScore != 70 {
		t.Errorf("expected score 70 (30+25+15), got %d", id.AssuranceScore)
	}
	if len(id.AuthMethods) != 3 {
		t.Errorf("expected 3 auth methods, got %d", len(id.AuthMethods))
	}
	if len(id.Evidence) != 3 {
		t.Errorf("expected 3 evidence items, got %d", len(id.Evidence))
	}
}

func TestMultiAuthn_ThirdAuthenticatorConflicts_Rejected(t *testing.T) {
	principal := "spiffe://example.com/svc"
	m := authn.NewMultiAuthn([]authn.Authenticator{
		okAuth(principal, 30),
		okAuth(principal, 25), // same principal — fine
		okAuth("oidc:auth.example.com:different-user", 15), // conflicts
	}, true, 0)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	_, err := m.Authenticate(req)
	if err == nil {
		t.Error("expected error when third authenticator has a conflicting principal")
	}
}

// ── min_score = 0 ─────────────────────────────────────────────────────────────

func TestMultiAuthn_MinScoreZero_AnyScorePasses(t *testing.T) {
	// minScore=0 means "no minimum" — even a score of 1 should pass.
	m := authn.NewMultiAuthn([]authn.Authenticator{
		okAuth("oidc:auth.example.com:svc", 1),
	}, true, 0)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api/", nil)
	id, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.AssuranceScore != 1 {
		t.Errorf("expected score 1, got %d", id.AssuranceScore)
	}
}

// ── NoopEnricher ──────────────────────────────────────────────────────────────

func TestNoopEnricher_PassesThrough(t *testing.T) {
	enricher := authn.NoopEnricher{}
	original := &identity.VerifiedIdentity{Principal: "spiffe://example.com/svc"}
	got, err := enricher.Enrich(t.Context(), original)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != original {
		t.Error("NoopEnricher should return the same pointer")
	}
}
