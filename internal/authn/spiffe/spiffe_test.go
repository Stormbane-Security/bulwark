package spiffe_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/stormbane-security/bulwark/internal/authn"
	authnspiffe "github.com/stormbane-security/bulwark/internal/authn/spiffe"
)

const (
	testIssuer   = "https://spire.example.com"
	testAudience = "https://api.internal"
)

type testKeys struct {
	private *rsa.PrivateKey
	keySet  jwk.Set
}

func newTestKeys(t *testing.T) *testKeys {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	privKey, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatalf("building JWK: %v", err)
	}
	if err := privKey.Set(jwk.KeyIDKey, "spire-key-1"); err != nil {
		t.Fatalf("setting key ID: %v", err)
	}
	if err := privKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("setting algorithm: %v", err)
	}
	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("extracting public key: %v", err)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pubKey); err != nil {
		t.Fatalf("adding key to set: %v", err)
	}
	return &testKeys{private: priv, keySet: set}
}

func (k *testKeys) mint(t *testing.T, subject string, opts ...func(*jwt.Builder)) string {
	t.Helper()
	b := jwt.NewBuilder().
		Issuer(testIssuer).
		Subject(subject).
		Audience([]string{testAudience}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour))
	for _, opt := range opts {
		opt(b)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatalf("building token: %v", err)
	}
	privKey, err := jwk.FromRaw(k.private)
	if err != nil {
		t.Fatalf("building JWK: %v", err)
	}
	if err := privKey.Set(jwk.KeyIDKey, "spire-key-1"); err != nil {
		t.Fatalf("setting key ID: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return string(signed)
}

func newJWKSServer(t *testing.T, set jwk.Set) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(set); err != nil {
			t.Errorf("serving JWKS: %v", err)
		}
	}))
}

func newValidator(t *testing.T, jwksURL, trustDomain string) *authnspiffe.Validator {
	t.Helper()
	cache := jwk.NewCache(t.Context())
	v, err := authnspiffe.New(testIssuer, testAudience, jwksURL, trustDomain, 25, cache)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return v
}

// ── no credentials → ErrNotApplicable ────────────────────────────────────────

func TestValidator_NoBearerToken_NotApplicable(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	_, err := v.Authenticate(req)
	if err != authn.ErrNotApplicable {
		t.Errorf("expected ErrNotApplicable, got %v", err)
	}
}

// ── valid SPIFFE JWT ──────────────────────────────────────────────────────────

func TestValidator_ValidSPIFFEToken_ReturnsIdentity(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	subject := "spiffe://example.com/workload/api"
	v := newValidator(t, srv.URL, "example.com")
	raw := keys.mint(t, subject)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	id, err := v.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Principal != subject {
		t.Errorf("principal: got %q, want %q", id.Principal, subject)
	}
	if id.AssuranceScore != 25 {
		t.Errorf("score: got %d, want 25", id.AssuranceScore)
	}
}

func TestValidator_AnyTrustDomain_AcceptsAll(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "") // no trust domain restriction
	subjects := []string{
		"spiffe://example.com/workload/a",
		"spiffe://other.org/service/b",
	}
	for _, sub := range subjects {
		raw := keys.mint(t, sub)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		id, err := v.Authenticate(req)
		if err != nil {
			t.Errorf("subject %q: unexpected error: %v", sub, err)
			continue
		}
		if id.Principal != sub {
			t.Errorf("subject %q: principal %q != expected", sub, id.Principal)
		}
	}
}

// ── non-SPIFFE subject → error ────────────────────────────────────────────────

func TestValidator_EmptyBearerToken_HardFails(t *testing.T) {
	// Same security property as OIDC: "Authorization: Bearer " must hard-fail,
	// not silently pass through as anonymous on optional-auth routes.
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer ")
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for empty Bearer token")
	}
	if err == authn.ErrNotApplicable {
		t.Error("empty Bearer token must hard-fail, not return ErrNotApplicable")
	}
}

func TestValidator_NonSPIFFESubject_HardFails(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "")
	raw := keys.mint(t, "user@example.com") // not a spiffe:// URI

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for non-SPIFFE subject")
	}
	if err == authn.ErrNotApplicable {
		t.Error("non-SPIFFE subject should hard-fail, not return ErrNotApplicable")
	}
}

// ── trust domain enforcement ──────────────────────────────────────────────────

func TestValidator_WrongTrustDomain_Rejected(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "example.com")
	raw := keys.mint(t, "spiffe://evil.com/workload") // wrong domain

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for wrong trust domain")
	}
}

func TestValidator_TrustDomainTrailingSlash_FailsClosed(t *testing.T) {
	// A misconfigured trust domain with a trailing slash (e.g. "example.com/")
	// produces expected prefix "spiffe://example.com//" which no valid SPIFFE
	// ID will match. This fails closed — all auth attempts are rejected.
	// Documented here so the behavior is known and not mistaken for a security hole.
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "example.com/") // trailing slash config mistake
	raw := keys.mint(t, "spiffe://example.com/workload")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("trailing slash in trust domain should fail closed — no valid SPIFFE ID can match")
	}
}

func TestValidator_WildcardTrustDomain_AcceptsAll(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "*")
	raw := keys.mint(t, "spiffe://any.domain/workload")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	if _, err := v.Authenticate(req); err != nil {
		t.Errorf("unexpected error for wildcard trust domain: %v", err)
	}
}

// ── invalid tokens ────────────────────────────────────────────────────────────

func TestValidator_ExpiredToken(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "example.com")
	raw := keys.mint(t, "spiffe://example.com/workload", func(b *jwt.Builder) {
		b.Expiration(time.Now().Add(-time.Hour))
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestValidator_BadSignature(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "example.com")
	otherKeys := newTestKeys(t)
	raw := otherKeys.mint(t, "spiffe://example.com/workload")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for bad signature")
	}
}

// ── not-before claim ──────────────────────────────────────────────────────────

func TestValidator_NotYetValidToken(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "example.com")
	raw := keys.mint(t, "spiffe://example.com/workload", func(b *jwt.Builder) {
		b.NotBefore(time.Now().Add(time.Hour)) // valid only in 1 hour
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for not-yet-valid token (nbf in future)")
	}
}

// ── trust domain boundary ─────────────────────────────────────────────────────

func TestValidator_TrustDomainBoundary_PrefixAttack(t *testing.T) {
	// "example.com.evil" must NOT match trust domain "example.com".
	// The "/" terminator in the prefix check prevents this.
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, "example.com")
	raw := keys.mint(t, "spiffe://example.com.evil/workload")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error: example.com.evil must not match trust domain example.com")
	}
}

// ── JWKS server unreachable → fail closed ────────────────────────────────────

func TestValidator_JWKSUnreachable_FailsClosed(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	keys := newTestKeys(t)
	cache := jwk.NewCache(t.Context())
	v, err := authnspiffe.New(testIssuer, testAudience, deadURL, "example.com", 25, cache)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}

	raw := keys.mint(t, "spiffe://example.com/workload")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err = v.Authenticate(req)
	if err == nil {
		t.Error("expected error when JWKS server is unreachable")
	}
	if err == authn.ErrNotApplicable {
		t.Error("unreachable JWKS must fail closed (error), not return ErrNotApplicable")
	}
}

// ── constructor validation ────────────────────────────────────────────────────

func TestNew_MissingIssuerReturnsError(t *testing.T) {
	cache := jwk.NewCache(t.Context())
	_, err := authnspiffe.New("", testAudience, "https://spire.example.com/jwks", "", 25, cache)
	if err == nil {
		t.Error("expected error for missing issuer")
	}
}

func TestNew_MissingJWKSUriReturnsError(t *testing.T) {
	cache := jwk.NewCache(t.Context())
	_, err := authnspiffe.New(testIssuer, testAudience, "", "", 25, cache)
	if err == nil {
		t.Error("expected error for missing jwks_uri")
	}
}

func TestNew_NonHTTPJWKSUriReturnsError(t *testing.T) {
	// file:// or other non-HTTP URIs must be rejected at construction time.
	cache := jwk.NewCache(t.Context())
	for _, uri := range []string{
		"file:///etc/spire/jwks.json",
		"ftp://spire.example.com/jwks.json",
	} {
		_, err := authnspiffe.New(testIssuer, testAudience, uri, "", 25, cache)
		if err == nil {
			t.Errorf("expected error for non-http jwks_uri %q", uri)
		}
	}
}
