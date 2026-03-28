// Package config handles loading and validating Bulwark configuration from YAML.
package config

import (
	"errors"
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

// MTLSConfig controls mTLS client certificate requirements on a listener.
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

// UpstreamConfig defines where to proxy requests and how Bulwark authenticates to the upstream.
type UpstreamConfig struct {
	URL  string        `yaml:"url"`
	Auth *UpstreamAuth `yaml:"auth,omitempty"`
}

// UpstreamAuth defines how Bulwark authenticates itself to an upstream service.
// Type must be one of: bulwark_jwt, mtls, static_bearer.
type UpstreamAuth struct {
	Type        string `yaml:"type"`
	CertFile    string `yaml:"cert,omitempty"`
	KeyFile     string `yaml:"key,omitempty"`
	// BearerToken supports ${ENV_VAR} references; never put plaintext secrets here.
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

// PolicyConfig maps a policy ID to a Rego policy file on disk.
type PolicyConfig struct {
	ID       string `yaml:"id"`
	RegoPath string `yaml:"rego_path"`
}

// Load reads and validates a Bulwark config from a file path.
func Load(path string) (_ *Config, err error) {
	//nolint:gosec // path is the operator-supplied --config flag; reading it is intentional (G304)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing config: %w", cerr)
		}
	}()
	return LoadReader(f)
}

// LoadReader reads and validates a Bulwark config from an io.Reader.
func LoadReader(r io.Reader) (*Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true) // reject unknown fields — typos in security config must fail loudly

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("config file is empty")
		}
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	expandEnvVars(&cfg)

	return &cfg, nil
}

// expandEnvVars replaces ${VAR} references in sensitive config fields with
// their environment variable values. This keeps secrets out of config files.
// Unset variables expand to an empty string.
func expandEnvVars(cfg *Config) {
	for i := range cfg.Routes {
		auth := cfg.Routes[i].Upstream.Auth
		if auth != nil && auth.BearerToken != "" {
			auth.BearerToken = os.ExpandEnv(auth.BearerToken)
		}
	}
}
