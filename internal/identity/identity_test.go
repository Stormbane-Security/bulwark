package identity_test

import (
	"testing"

	"github.com/stormbane-security/bulwark/internal/identity"
)

func TestDefaultScores_AllTypesPresent(t *testing.T) {
	types := []identity.EvidenceType{
		identity.EvidenceJWT,
		identity.EvidenceMTLSCert,
		identity.EvidenceSPIFFEJWT,
		identity.EvidenceAnchorAssertion,
	}
	for _, et := range types {
		if _, ok := identity.DefaultScores[et]; !ok {
			t.Errorf("DefaultScores missing entry for %q", et)
		}
	}
}

func TestDefaultScores_MTLSWithSPIFFEHigherThanPlainMTLS(t *testing.T) {
	plain := identity.DefaultScores[identity.EvidenceMTLSCert]
	if identity.ScoreMTLSWithSPIFFE <= plain {
		t.Errorf("SPIFFE mTLS score %d should be > plain mTLS score %d",
			identity.ScoreMTLSWithSPIFFE, plain)
	}
}

func TestDefaultScores_AnchorHighest(t *testing.T) {
	anchor := identity.DefaultScores[identity.EvidenceAnchorAssertion]
	for et, score := range identity.DefaultScores {
		if et != identity.EvidenceAnchorAssertion && score >= anchor {
			t.Errorf("EvidenceType %q score %d should be < AnchorAssertion score %d",
				et, score, anchor)
		}
	}
}

func TestVerifiedIdentity_ScoreEqualsEvidenceSum(t *testing.T) {
	id := &identity.VerifiedIdentity{
		Principal:      "spiffe://example.com/svc",
		AuthMethods:    []identity.AuthMethod{identity.AuthMTLSSPIFFE, identity.AuthSPIFFEJWT},
		AssuranceScore: identity.ScoreMTLSWithSPIFFE + identity.DefaultScores[identity.EvidenceSPIFFEJWT],
		Evidence: []identity.IdentityEvidence{
			{Type: identity.EvidenceMTLSCert, Score: identity.ScoreMTLSWithSPIFFE},
			{Type: identity.EvidenceSPIFFEJWT, Score: identity.DefaultScores[identity.EvidenceSPIFFEJWT]},
		},
	}
	total := 0
	for _, e := range id.Evidence {
		total += e.Score
	}
	if id.AssuranceScore != total {
		t.Errorf("AssuranceScore %d != sum of evidence scores %d", id.AssuranceScore, total)
	}
}

func TestAuthMethodConstants(t *testing.T) {
	methods := []identity.AuthMethod{
		identity.AuthOIDC,
		identity.AuthMTLS,
		identity.AuthMTLSSPIFFE,
		identity.AuthSPIFFEJWT,
	}
	seen := make(map[identity.AuthMethod]bool)
	for _, m := range methods {
		if seen[m] {
			t.Errorf("duplicate AuthMethod value: %q", m)
		}
		seen[m] = true
		if m == "" {
			t.Error("AuthMethod must not be empty string")
		}
	}
}
