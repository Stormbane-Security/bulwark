package config_test

import (
	"strings"
	"testing"

	"github.com/patrickputman/bulwark/internal/config"
)

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
	if route.Authn.Required != true {
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
	if len(cfg.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(cfg.Policies))
	}
	if cfg.Policies[0].ID != "api-policy" {
		t.Errorf("expected policy id api-policy, got %q", cfg.Policies[0].ID)
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
		t.Error("expected error for empty config, got nil")
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

func TestLoad_UpstreamAuthTypes(t *testing.T) {
	tests := []struct {
		name    string
		authYAML string
		wantErr bool
	}{
		{
			name:     "bulwark_jwt",
			authYAML: "type: bulwark_jwt",
		},
		{
			name:     "mtls",
			authYAML: "type: mtls\n        cert: /a.crt\n        key: /a.key",
		},
		{
			name:     "static_bearer",
			authYAML: "type: static_bearer\n        bearer_token: secret",
		},
		{
			name:     "invalid type",
			authYAML: "type: magic",
			wantErr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			yaml := "listeners:\n  - addr: \":8080\"\nroutes:\n  - id: r\n    match:\n      host: h\n      path_prefix: /\n    upstream:\n      url: http://x:1\n      auth:\n        " + tc.authYAML + "\n    authn:\n      required: false\n"
			cfg, err := config.LoadReader(strings.NewReader(yaml))
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
	// path_prefix should default to "/"
	if cfg.Routes[0].Match.PathPrefix != "/" {
		t.Errorf("expected default path_prefix /, got %q", cfg.Routes[0].Match.PathPrefix)
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
