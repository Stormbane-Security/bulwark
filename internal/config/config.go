// Package config handles loading and validating Bulwark configuration from YAML.
package config

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the root Bulwark configuration.
type Config struct {
	Listeners []ListenerConfig `yaml:"listeners"`
	Routes    []RouteConfig    `yaml:"routes"`
	Policies  []PolicyConfig   `yaml:"policies"`
}

// ListenerConfig defines a network listener.
type ListenerConfig struct {
	Addr string      `yaml:"addr"`
	TLS  *TLSConfig  `yaml:"tls,omitempty"`
	MTLS *MTLSConfig `yaml:"mtls,omitempty"`
}

// TLSConfig holds server TLS cert/key paths.
type TLSConfig struct {
	CertFile string `yaml:"cert"`
	KeyFile  string `yaml:"key"`
}

// MTLSConfig controls mTLS client certificate requirements.
type MTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CABundle string `yaml:"ca_bundle,omitempty"`
}

// RouteConfig maps inbound requests to an upstream and a policy.
type RouteConfig struct {
	ID       string         `yaml:"id"`
	Match    MatchConfig    `yaml:"match"`
	Upstream UpstreamConfig `yaml:"upstream"`
	Authn    AuthnConfig    `yaml:"authn"`
	Policy   string         `yaml:"policy,omitempty"`
}

// MatchConfig defines what requests a route applies to.
type MatchConfig struct {
	Host       string `yaml:"host"`
	PathPrefix string `yaml:"path_prefix,omitempty"`
}

// UpstreamConfig defines where to proxy requests and how to authenticate to the upstream.
type UpstreamConfig struct {
	URL  string        `yaml:"url"`
	Auth *UpstreamAuth `yaml:"auth,omitempty"`
}

// UpstreamAuth defines how Bulwark authenticates to the upstream service.
// Type must be one of: bulwark_jwt, mtls, static_bearer.
type UpstreamAuth struct {
	Type        string `yaml:"type"`
	CertFile    string `yaml:"cert,omitempty"`
	KeyFile     string `yaml:"key,omitempty"`
	BearerToken string `yaml:"bearer_token,omitempty"`
}

// AuthnConfig defines authentication requirements for a route.
type AuthnConfig struct {
	Required bool           `yaml:"required"`
	Issuers  []IssuerConfig `yaml:"issuers,omitempty"`
}

// IssuerConfig defines a trusted identity issuer for a route.
// Type must be one of: oidc, mtls, spiffe_jwt.
type IssuerConfig struct {
	Type     string `yaml:"type"`
	Issuer   string `yaml:"issuer,omitempty"`
	Audience string `yaml:"audience,omitempty"`
	JWKSUri  string `yaml:"jwks_uri,omitempty"`
}

// PolicyConfig maps a policy ID to a Rego policy file.
type PolicyConfig struct {
	ID       string `yaml:"id"`
	RegoPath string `yaml:"rego_path"`
}

// Load reads and validates a Bulwark config from a file path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer f.Close()
	return LoadReader(f)
}

// LoadReader reads and validates a Bulwark config from an io.Reader.
func LoadReader(r io.Reader) (*Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true) // reject unknown fields

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validate runs structural validation on a parsed Config.
func validate(cfg *Config) error {
	if len(cfg.Listeners) == 0 {
		return fmt.Errorf("config: at least one listener is required")
	}
	if len(cfg.Routes) == 0 {
		return fmt.Errorf("config: at least one route is required")
	}

	// Build policy ID set for reference checking.
	policyIDs := make(map[string]struct{}, len(cfg.Policies))
	for _, p := range cfg.Policies {
		policyIDs[p.ID] = struct{}{}
	}

	for i, l := range cfg.Listeners {
		if l.Addr == "" {
			return fmt.Errorf("config: listeners[%d]: addr is required", i)
		}
		if l.TLS != nil {
			if l.TLS.CertFile == "" {
				return fmt.Errorf("config: listeners[%d].tls: cert is required", i)
			}
			if l.TLS.KeyFile == "" {
				return fmt.Errorf("config: listeners[%d].tls: key is required", i)
			}
		}
	}

	for i, r := range cfg.Routes {
		if r.ID == "" {
			return fmt.Errorf("config: routes[%d]: id is required", i)
		}
		if r.Match.Host == "" {
			return fmt.Errorf("config: routes[%d]: match.host is required", i)
		}
		if r.Upstream.URL == "" {
			return fmt.Errorf("config: routes[%d]: upstream.url is required", i)
		}
		if r.Upstream.Auth != nil {
			if err := validateUpstreamAuth(i, r.Upstream.Auth); err != nil {
				return err
			}
		}
		if r.Policy != "" {
			if _, ok := policyIDs[r.Policy]; !ok {
				return fmt.Errorf("config: routes[%d]: policy %q is referenced but not defined", i, r.Policy)
			}
		}

		// Apply defaults.
		if cfg.Routes[i].Match.PathPrefix == "" {
			cfg.Routes[i].Match.PathPrefix = "/"
		}
	}

	return nil
}

var validUpstreamAuthTypes = map[string]struct{}{
	"bulwark_jwt":   {},
	"mtls":          {},
	"static_bearer": {},
}

func validateUpstreamAuth(routeIdx int, auth *UpstreamAuth) error {
	if _, ok := validUpstreamAuthTypes[auth.Type]; !ok {
		return fmt.Errorf("config: routes[%d].upstream.auth: invalid type %q (must be bulwark_jwt, mtls, or static_bearer)", routeIdx, auth.Type)
	}
	return nil
}
