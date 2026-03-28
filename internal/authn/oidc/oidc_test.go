package oidc_test

import (
	"context"
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
	authnoidc "github.com/stormbane-security/bulwark/internal/authn/oidc"
)

const (
	testIssuer   = "https://auth.example.com"
	testAudience = "https://api.internal"
	testSubject  = "svc-workload-123"
)

// testKeys holds a test RSA key pair and the corresponding JWKS.
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
	if err := privKey.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
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

func (k *testKeys) mint(t *testing.T, opts ...func(*jwt.Builder)) string {
	t.Helper()
	b := jwt.NewBuilder().
		Issuer(testIssuer).
		Subject(testSubject).
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
		t.Fatalf("building JWK from private key: %v", err)
	}
	if err := privKey.Set(jwk.KeyIDKey, "test-key-1"); err != nil {
		t.Fatalf("setting key ID: %v", err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return string(signed)
}

// newJWKSServer returns a test server that serves the given key set as JWKS.
func newJWKSServer(t *testing.T, set jwk.Set) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(set); err != nil {
			t.Errorf("serving JWKS: %v", err)
		}
	}))
}

// newValidator creates a Validator pointing at the test JWKS server.
func newValidator(t *testing.T, jwksURL string, score int, principalPrefix string) *authnoidc.Validator {
	t.Helper()
	cache := jwk.NewCache(t.Context())
	v, err := authnoidc.New(testIssuer, testAudience, jwksURL, score, cache, principalPrefix)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
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

	v := newValidator(t, srv.URL, 15, "")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	_, err := v.Authenticate(req)
	if err != authn.ErrNotApplicable {
		t.Errorf("expected ErrNotApplicable, got %v", err)
	}
}

func TestValidator_NonBearerAuthHeader_NotApplicable(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, 15, "")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err := v.Authenticate(req)
	if err != authn.ErrNotApplicable {
		t.Errorf("expected ErrNotApplicable for Basic auth, got %v", err)
	}
}

// ── valid token ───────────────────────────────────────────────────────────────

func TestValidator_ValidToken_ReturnsIdentity(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, 15, "")
	raw := keys.mint(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	id, err := v.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == nil {
		t.Fatal("expected identity, got nil")
	}
	wantPrincipal := "oidc:auth.example.com:" + testSubject
	if id.Principal != wantPrincipal {
		t.Errorf("principal: got %q, want %q", id.Principal, wantPrincipal)
	}
	if id.AssuranceScore != 15 {
		t.Errorf("score: got %d, want 15", id.AssuranceScore)
	}
	if id.Issuer != testIssuer {
		t.Errorf("issuer: got %q, want %q", id.Issuer, testIssuer)
	}
	if len(id.Evidence) != 1 || id.Evidence[0].Subject != testSubject {
		t.Errorf("evidence: got %+v", id.Evidence)
	}
}

func TestValidator_ValidToken_CustomScore(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, 25, "") // cloud-IAM score override
	raw := keys.mint(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	id, err := v.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.AssuranceScore != 25 {
		t.Errorf("score: got %d, want 25", id.AssuranceScore)
	}
}

// ── principal normalization ───────────────────────────────────────────────────

func TestValidator_PrincipalPrefix(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, 15, "gh")
	raw := keys.mint(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	id, err := v.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantPrincipal := "gh:" + testSubject
	if id.Principal != wantPrincipal {
		t.Errorf("principal: got %q, want %q", id.Principal, wantPrincipal)
	}
}

// ── invalid tokens ────────────────────────────────────────────────────────────

func TestValidator_ExpiredToken(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, 15, "")
	raw := keys.mint(t, func(b *jwt.Builder) {
		b.Expiration(time.Now().Add(-time.Hour))
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestValidator_WrongIssuer(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, 15, "")
	raw := keys.mint(t, func(b *jwt.Builder) {
		b.Issuer("https://evil.example.com")
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for wrong issuer")
	}
}

func TestValidator_WrongAudience(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, 15, "")
	raw := keys.mint(t, func(b *jwt.Builder) {
		b.Audience([]string{"https://other-api.internal"})
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for wrong audience")
	}
}

func TestValidator_BadSignature(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, 15, "")

	// Mint with a different key not in the JWKS.
	otherKeys := newTestKeys(t)
	raw := otherKeys.mint(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for bad signature")
	}
}

func TestValidator_MalformedToken(t *testing.T) {
	keys := newTestKeys(t)
	srv := newJWKSServer(t, keys.keySet)
	defer srv.Close()

	v := newValidator(t, srv.URL, 15, "")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.internal/", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	_, err := v.Authenticate(req)
	if err == nil {
		t.Error("expected error for malformed token")
	}
	if err == authn.ErrNotApplicable {
		t.Error("malformed token should not return ErrNotApplicable — it must hard-fail")
	}
}

// ── JWKS cache hit ────────────────────────────────────────────────────────────

func TestValidator_JWKSCacheHit(t *testing.T) {
	keys := newTestKeys(t)
	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(keys.keySet); err != nil {
			t.Errorf("serving JWKS: %v", err)
		}
	}))
	defer srv.Close()

	// Use a single shared cache for both calls (simulates the real server setup).
	cache := jwk.NewCache(t.Context())
	v, err := authnoidc.New(testIssuer, testAudience, srv.URL, 15, cache, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}

	raw := keys.mint(t)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://api.internal/", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		if _, err := v.Authenticate(req); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}

	// The JWKS server may be fetched once (initial) or more due to background
	// refresh, but must never be fetched on every request.
	if fetchCount > 2 {
		t.Errorf("JWKS fetched %d times for 3 requests — cache is not working", fetchCount)
	}
}

// ── constructor validation ────────────────────────────────────────────────────

func TestNew_MissingIssuerReturnsError(t *testing.T) {
	cache := jwk.NewCache(t.Context())
	_, err := authnoidc.New("", testAudience, "https://auth.example.com/.well-known/jwks.json", 15, cache, "")
	if err == nil {
		t.Error("expected error for missing issuer")
	}
}

func TestNew_MissingJWKSUriReturnsError(t *testing.T) {
	cache := jwk.NewCache(t.Context())
	_, err := authnoidc.New(testIssuer, testAudience, "", 15, cache, "")
	if err == nil {
		t.Error("expected error for missing jwks_uri")
	}
}
