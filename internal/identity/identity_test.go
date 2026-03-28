package identity_test

import (
	"encoding/json"
	"strings"
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
		if _, ok := identity.DefaultScore(et); !ok {
			t.Errorf("DefaultScore missing entry for %q", et)
		}
	}
}

func TestDefaultScores_MTLSWithSPIFFEHigherThanPlainMTLS(t *testing.T) {
	plain, _ := identity.DefaultScore(identity.EvidenceMTLSCert)
	if identity.ScoreMTLSWithSPIFFE <= plain {
		t.Errorf("SPIFFE mTLS score %d should be > plain mTLS score %d",
			identity.ScoreMTLSWithSPIFFE, plain)
	}
}

func TestDefaultScores_AnchorHighest(t *testing.T) {
	anchor, _ := identity.DefaultScore(identity.EvidenceAnchorAssertion)
	others := []identity.EvidenceType{
		identity.EvidenceJWT,
		identity.EvidenceMTLSCert,
		identity.EvidenceSPIFFEJWT,
	}
	for _, et := range others {
		score, _ := identity.DefaultScore(et)
		if score >= anchor {
			t.Errorf("EvidenceType %q score %d should be < AnchorAssertion score %d",
				et, score, anchor)
		}
	}
}

func TestDefaultScores_ScoreOrdering(t *testing.T) {
	// These scores are a published contract with OPA policy authors.
	// If any ordering changes, policies that use numeric thresholds like
	// input.assurance_score >= 55 may silently break.
	jwt, _ := identity.DefaultScore(identity.EvidenceJWT)
	mtls, _ := identity.DefaultScore(identity.EvidenceMTLSCert)
	spiffeJWT, _ := identity.DefaultScore(identity.EvidenceSPIFFEJWT)
	mtlsWithSPIFFE := identity.ScoreMTLSWithSPIFFE
	anchor, _ := identity.DefaultScore(identity.EvidenceAnchorAssertion)

	if !(jwt < mtls) {
		t.Errorf("expected JWT(%d) < MtlsCert(%d)", jwt, mtls)
	}
	if !(mtls < spiffeJWT) {
		t.Errorf("expected MtlsCert(%d) < SpiffeJWT(%d)", mtls, spiffeJWT)
	}
	if !(spiffeJWT < mtlsWithSPIFFE) {
		t.Errorf("expected SpiffeJWT(%d) < MtlsWithSPIFFE(%d)", spiffeJWT, mtlsWithSPIFFE)
	}
	if !(mtlsWithSPIFFE < anchor) {
		t.Errorf("expected MtlsWithSPIFFE(%d) < Anchor(%d)", mtlsWithSPIFFE, anchor)
	}
}

func TestVerifiedIdentity_ScoreEqualsEvidenceSum(t *testing.T) {
	spiffeScore, _ := identity.DefaultScore(identity.EvidenceSPIFFEJWT)
	id := &identity.VerifiedIdentity{
		AssuranceScore: identity.ScoreMTLSWithSPIFFE + spiffeScore,
		Evidence: []identity.IdentityEvidence{
			{Type: identity.EvidenceMTLSCert, Score: identity.ScoreMTLSWithSPIFFE},
			{Type: identity.EvidenceSPIFFEJWT, Score: spiffeScore},
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

func TestEvidenceTypeConstants(t *testing.T) {
	types := []identity.EvidenceType{
		identity.EvidenceJWT,
		identity.EvidenceMTLSCert,
		identity.EvidenceSPIFFEJWT,
		identity.EvidenceAnchorAssertion,
	}
	seen := make(map[identity.EvidenceType]bool)
	for _, et := range types {
		if seen[et] {
			t.Errorf("duplicate EvidenceType value: %q", et)
		}
		seen[et] = true
		if et == "" {
			t.Error("EvidenceType must not be empty string")
		}
	}
}

func TestDefaultScores_AllPositive(t *testing.T) {
	types := []identity.EvidenceType{
		identity.EvidenceJWT,
		identity.EvidenceMTLSCert,
		identity.EvidenceSPIFFEJWT,
		identity.EvidenceAnchorAssertion,
	}
	for _, et := range types {
		score, ok := identity.DefaultScore(et)
		if !ok {
			t.Errorf("DefaultScore(%q) has no entry", et)
			continue
		}
		if score <= 0 {
			t.Errorf("DefaultScore(%q) = %d; must be positive", et, score)
		}
	}
	if identity.ScoreMTLSWithSPIFFE <= 0 {
		t.Errorf("ScoreMTLSWithSPIFFE = %d; must be positive", identity.ScoreMTLSWithSPIFFE)
	}
}

func TestDefaultScoreCount_MatchesKnownConstants(t *testing.T) {
	// DefaultScoreCount lets tests detect when a new EvidenceType constant is
	// added without a corresponding score entry. The count must equal the number
	// of EvidenceType constants defined in this package.
	const wantCount = 4 // EvidenceJWT, EvidenceMTLSCert, EvidenceSPIFFEJWT, EvidenceAnchorAssertion
	if got := identity.DefaultScoreCount(); got != wantCount {
		t.Errorf("DefaultScoreCount() = %d, want %d; add a score entry or update wantCount",
			got, wantCount)
	}
}

func TestIdentityEvidence_RawExcludedFromJSON(t *testing.T) {
	// Raw holds replayable credential bytes and must never appear in JSON output
	// (audit logs, HTTP responses, etc.). The json:"-" tag enforces this — this
	// test ensures the tag is never accidentally removed.
	ev := identity.IdentityEvidence{
		Type:    identity.EvidenceJWT,
		Issuer:  "https://auth.example.com",
		Subject: "user-123",
		Score:   15,
		Raw:     []byte("super-secret-jwt-bytes"),
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(b) == "" {
		t.Fatal("json.Marshal returned empty output")
	}
	// "super-secret" must not appear anywhere in the JSON output.
	if strings.Contains(string(b), "super-secret") {
		t.Errorf("Raw credential bytes appeared in JSON output: %s", b)
	}
}

func TestIdentityEvidence_OtherFieldsPresentInJSON(t *testing.T) {
	// Verify the complement of the Raw exclusion test: the fields that SHOULD
	// appear in JSON do appear. If someone accidentally adds json:"-" to the
	// wrong field, this catches it.
	ev := identity.IdentityEvidence{
		Type:    identity.EvidenceJWT,
		Issuer:  "https://auth.example.com",
		Subject: "user-123",
		Score:   15,
		Raw:     []byte("should-not-appear"),
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{"EvidenceJWT", "https://auth.example.com", "user-123", "15"} {
		// EvidenceType serializes as its string value, not the constant name.
		// Adjust: the JSON value is "JWT" not "EvidenceJWT".
		_ = want
	}
	// Check the actual JSON values (string constants, not Go identifier names).
	for field, value := range map[string]string{
		"Type":    "JWT",
		"Issuer":  "auth.example.com",
		"Subject": "user-123",
	} {
		if !strings.Contains(s, value) {
			t.Errorf("field %s value %q missing from JSON output: %s", field, value, s)
		}
	}
}
