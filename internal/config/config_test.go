package config_test

import (
	"strings"
	"testing"

	"github.com/stormbane-security/bulwark/internal/config"
)

// ── happy path ────────────────────────────────────────────────────────────────

func TestLoad_ValidMinimal(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8080"

routes:
  - id: test-route
    match:
      host: api.internal
      path_prefix: /
    upstream:
      url: http://localhost:9090
    authn:
      required: false
`
	cfg, err := config.LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Listeners) != 1 {
		t.Errorf("expected 1 listener, got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[0].Addr != ":8080" {
		t.Errorf("expected addr :8080, got %q", cfg.Listeners[0].Addr)
	}
	if len(cfg.Routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(cfg.Routes))
	}
	if cfg.Routes[0].ID != "test-route" {
		t.Errorf("expected route id test-route, got %q", cfg.Routes[0].ID)
	}
	if cfg.Routes[0].Upstream.URL != "http://localhost:9090" {
		t.Errorf("unexpected upstream url: %q", cfg.Routes[0].Upstream.URL)
	}
}

func TestLoad_OIDCIssuer(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8443"

routes:
  - id: api
    match:
      host: api.internal
      path_prefix: /
    upstream:
      url: http://api:8080
      auth:
        type: bulwark_jwt
    authn:
      required: true
      issuers:
        - type: oidc
          issuer: https://auth.example.com
          audience: api.internal
          jwks_uri: https://auth.example.com/.well-known/jwks.json
    policy: api-policy

policies:
  - id: api-policy
    rego_path: /etc/bulwark/policy/api.rego
`
	cfg, err := config.LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	route := cfg.Routes[0]
	if !route.Authn.Required {
		t.Error("expected authn required")
	}
	if len(route.Authn.Issuers) != 1 {
		t.Fatalf("expected 1 issuer, got %d", len(route.Authn.Issuers))
	}
	issuer := route.Authn.Issuers[0]
	if issuer.Type != "oidc" {
		t.Errorf("expected type oidc, got %q", issuer.Type)
	}
	if issuer.Issuer != "https://auth.example.com" {
		t.Errorf("unexpected issuer: %q", issuer.Issuer)
	}
	if route.Policy != "api-policy" {
		t.Errorf("expected policy api-policy, got %q", route.Policy)
	}
	if len(cfg.Policies) != 1 || cfg.Policies[0].ID != "api-policy" {
		t.Errorf("unexpected policies: %+v", cfg.Policies)
	}
}

func TestLoad_MTLSListener(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8443"
    tls:
      cert: /etc/bulwark/tls/server.crt
      key: /etc/bulwark/tls/server.key
    mtls:
      enabled: true
      ca_bundle: /etc/bulwark/cas/clients.pem

routes:
  - id: svc
    match:
      host: svc.internal
      path_prefix: /
    upstream:
      url: http://svc:8080
    authn:
      required: true
      issuers:
        - type: mtls
`
	cfg, err := config.LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	l := cfg.Listeners[0]
	if l.TLS == nil {
		t.Fatal("expected TLS config")
	}
	if l.TLS.CertFile != "/etc/bulwark/tls/server.crt" {
		t.Errorf("unexpected cert: %q", l.TLS.CertFile)
	}
	if l.MTLS == nil || !l.MTLS.Enabled {
		t.Error("expected mTLS enabled")
	}
	if l.MTLS.CABundle != "/etc/bulwark/cas/clients.pem" {
		t.Errorf("unexpected ca_bundle: %q", l.MTLS.CABundle)
	}
}

func TestLoad_RouteMatchDefaults(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8080"

routes:
  - id: r
    match:
      host: api.internal
    upstream:
      url: http://api:8080
    authn:
      required: false
`
	cfg, err := config.LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Routes[0].Match.PathPrefix != "/" {
		t.Errorf("expected default path_prefix /, got %q", cfg.Routes[0].Match.PathPrefix)
	}
}

// ── upstream auth types ───────────────────────────────────────────────────────

func TestLoad_UpstreamAuthTypes(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "bulwark_jwt",
			yaml: `
listeners:
  - addr: ":8080"
routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
      auth:
        type: bulwark_jwt
    authn:
      required: false
`,
		},
		{
			name: "mtls",
			yaml: `
listeners:
  - addr: ":8080"
routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
      auth:
        type: mtls
        cert: /a.crt
        key: /a.key
    authn:
      required: false
`,
		},
		{
			name: "static_bearer",
			yaml: `
listeners:
  - addr: ":8080"
routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
      auth:
        type: static_bearer
        bearer_token: secret
    authn:
      required: false
`,
		},
		{
			name: "invalid type",
			yaml: `
listeners:
  - addr: ":8080"
routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
      auth:
        type: magic
    authn:
      required: false
`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.LoadReader(strings.NewReader(tc.yaml))
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Routes[0].Upstream.Auth == nil {
				t.Error("expected upstream auth to be set")
			}
		})
	}
}

// ── structural errors ─────────────────────────────────────────────────────────

func TestLoad_UnknownFieldsRejected(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8080"
    unknown_field: oops

routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
    authn:
      required: false
`
	_, err := config.LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error for unknown field, got nil")
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	_, err := config.LoadReader(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for empty config, got nil")
	}
	if err.Error() != "config file is empty" {
		t.Errorf("expected actionable empty-file message, got %q", err.Error())
	}
}

func TestLoad_NoListeners(t *testing.T) {
	yaml := `
routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
    authn:
      required: false
`
	_, err := config.LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error when no listeners defined")
	}
}

func TestLoad_NoRoutes(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8080"
`
	_, err := config.LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error when no routes defined")
	}
}

func TestLoad_PolicyReferencedButNotDefined(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8080"

routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
    authn:
      required: false
    policy: missing-policy
`
	_, err := config.LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error when policy referenced but not defined")
	}
}

// ── new validation: duplicate IDs ─────────────────────────────────────────────

func TestLoad_DuplicateRouteIDs(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8080"

routes:
  - id: same
    match:
      host: a.internal
      path_prefix: /
    upstream:
      url: http://a:8080
    authn:
      required: false
  - id: same
    match:
      host: b.internal
      path_prefix: /
    upstream:
      url: http://b:8080
    authn:
      required: false
`
	_, err := config.LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error for duplicate route id")
	}
}

func TestLoad_DuplicatePolicyIDs(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8080"

routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
    authn:
      required: false
    policy: p

policies:
  - id: p
    rego_path: /a.rego
  - id: p
    rego_path: /b.rego
`
	_, err := config.LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error for duplicate policy id")
	}
}

// ── new validation: authn.required with no issuers ───────────────────────────

func TestLoad_AuthnRequiredWithNoIssuers(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8080"

routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
    authn:
      required: true
`
	_, err := config.LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error when authn.required is true but no issuers are defined")
	}
}

// ── new validation: upstream URL scheme ──────────────────────────────────────

func TestLoad_UpstreamURLScheme(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "http ok", url: "http://svc:8080"},
		{name: "https ok", url: "https://svc:8080"},
		{name: "file rejected", url: "file:///etc/passwd", wantErr: true},
		{name: "ftp rejected", url: "ftp://svc:21", wantErr: true},
		{name: "no scheme rejected", url: "svc:8080", wantErr: true},
		{name: "empty rejected", url: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstreamLine := ""
			if tc.url != "" {
				upstreamLine = "url: " + tc.url
			}
			yaml := `
listeners:
  - addr: ":8080"
routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      ` + upstreamLine + `
    authn:
      required: false
`
			_, err := config.LoadReader(strings.NewReader(yaml))
			if tc.wantErr && err == nil {
				t.Errorf("expected error for upstream url %q, got nil", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for upstream url %q: %v", tc.url, err)
			}
		})
	}
}

// ── new validation: mTLS enabled without CA bundle ───────────────────────────

func TestLoad_MTLSEnabledWithoutCABundle(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8443"
    tls:
      cert: /srv.crt
      key: /srv.key
    mtls:
      enabled: true

routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
    authn:
      required: false
`
	_, err := config.LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error when mtls enabled but ca_bundle is empty")
	}
}

// ── new validation: invalid issuer type ──────────────────────────────────────

func TestLoad_InvalidIssuerType(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8080"

routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
    authn:
      required: true
      issuers:
        - type: magic-issuer
`
	_, err := config.LoadReader(strings.NewReader(yaml))
	if err == nil {
		t.Error("expected error for invalid issuer type")
	}
}

// ── env var expansion ─────────────────────────────────────────────────────────

func TestLoad_BearerTokenEnvExpansion(t *testing.T) {
	t.Setenv("TEST_BULWARK_TOKEN", "expanded-secret")

	yaml := `
listeners:
  - addr: ":8080"

routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
      auth:
        type: static_bearer
        bearer_token: ${TEST_BULWARK_TOKEN}
    authn:
      required: false
`
	cfg, err := config.LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := cfg.Routes[0].Upstream.Auth.BearerToken
	if got != "expanded-secret" {
		t.Errorf("expected bearer token to be expanded, got %q", got)
	}
}

func TestLoad_BearerTokenLiteralUnchanged(t *testing.T) {
	yaml := `
listeners:
  - addr: ":8080"

routes:
  - id: r
    match:
      host: h
      path_prefix: /
    upstream:
      url: http://x:1
      auth:
        type: static_bearer
        bearer_token: literal-token
    authn:
      required: false
`
	cfg, err := config.LoadReader(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Routes[0].Upstream.Auth.BearerToken != "literal-token" {
		t.Errorf("expected literal token unchanged")
	}
}
