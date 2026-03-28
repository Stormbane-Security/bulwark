// Package identity defines the verified identity types that flow through
// Bulwark's authentication pipeline.
package identity

import "time"

// AuthMethod describes a single authentication mechanism that contributed to
// a verified identity.
type AuthMethod string

const (
	AuthOIDC       AuthMethod = "OIDC"
	AuthMTLS       AuthMethod = "MTLS"
	AuthMTLSSPIFFE AuthMethod = "MTLS_SPIFFE"
	AuthSPIFFEJWT  AuthMethod = "SPIFFE_JWT"
)

// EvidenceType identifies what kind of credential produced a piece of evidence.
type EvidenceType string

const (
	EvidenceJWT             EvidenceType = "JWT"
	EvidenceMTLSCert        EvidenceType = "MTLS_CERT"
	EvidenceSPIFFEJWT       EvidenceType = "SPIFFE_JWT"
	EvidenceAnchorAssertion EvidenceType = "ANCHOR_ASSERTION"
)

// defaultScores is the private score table. Access via DefaultScore.
var defaultScores = map[EvidenceType]int{
	EvidenceMTLSCert:        20, // mTLS without SPIFFE URI SAN
	EvidenceSPIFFEJWT:       25,
	EvidenceJWT:             15, // generic OIDC; cloud-IAM anchors can override to 25
	EvidenceAnchorAssertion: 40,
}

// DefaultScore returns the default assurance score for et and whether one is
// defined. Callers that need to fall back when no score is configured should
// check the boolean: score, ok := identity.DefaultScore(et).
func DefaultScore(et EvidenceType) (int, bool) {
	s, ok := defaultScores[et]
	return s, ok
}

// DefaultScoreCount returns the number of evidence types that have a defined
// default score. Tests use this to detect when a new EvidenceType constant
// is added without a corresponding score entry.
func DefaultScoreCount() int {
	return len(defaultScores)
}

// ScoreMTLSWithSPIFFE is the assurance contribution for mTLS with a SPIFFE URI SAN.
// It is higher than plain mTLS because the cert carries a verifiable workload identity.
const ScoreMTLSWithSPIFFE = 30

// IdentityEvidence records a single piece of authentication evidence.
type IdentityEvidence struct {
	Type      EvidenceType
	Issuer    string
	Subject   string
	ExpiresAt time.Time
	Score     int // contribution to VerifiedIdentity.AssuranceScore

	// Raw holds the original credential bytes (JWT, DER cert, etc.) for forensic
	// archiving. It is excluded from all JSON serialization — raw credentials are
	// replayable and must never appear in audit logs or log pipelines.
	Raw []byte `json:"-"`
}

// VerifiedIdentity is the normalized, validated identity produced after all
// configured authenticators have run for a request.
type VerifiedIdentity struct {
	Principal      string             // normalized: oidc:<host>:<sub> | spiffe://... | etc.
	Issuer         string             // primary issuer
	AuthMethods    []AuthMethod       // all methods that contributed
	Groups         []string
	Claims         map[string]any     // read-only raw claims from primary auth
	AssuranceScore int                // additive sum of evidence scores
	Evidence       []IdentityEvidence
}
