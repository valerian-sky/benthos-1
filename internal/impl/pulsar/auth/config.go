package auth

import (
	"errors"
)

// Config contains configuration params for Pulsar authentication.
type Config struct {
	OAuth2 OAuth2Config `json:"oauth2" yaml:"oauth2"`
	Token  TokenConfig  `json:"token" yaml:"token"`
	Tls    TlsConfig    `json:"tls" yaml:"tls"`
}

// OAuth2Config contains configuration params for Pulsar OAuth2 authentication.
type OAuth2Config struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	Audience       string `json:"audience" yaml:"audience"`
	IssuerURL      string `json:"issuer_url" yaml:"issuer_url"`
	PrivateKeyFile string `json:"private_key_file" yaml:"private_key_file"`
}

// TokenConfig contains configuration params for Pulsar Token authentication.
type TokenConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Token   string `json:"token" yaml:"token"`
}

// TlsConfig contains configuration params for Pulsar Token tls.
type TlsConfig struct {
	Enabled                    bool   `json:"enabled" yaml:"enabled"`
	RootCAsFile                string `json:"root_cas_file" yaml:"root_cas_file"`
	CertFile                   string `json:"cert_file" yaml:"cert_file"`
	KeyFile                    string `json:"key_file" yaml:"key_file"`
	TLSAllowInsecureConnection bool   `json:"allow_insecure_connection" yaml:"allow_insecure_connection"`
}

// New creates a new Config instance.
func New() Config {
	return Config{
		OAuth2: NewOAuth(),
		Token:  NewToken(),
		Tls:    NewTls(),
	}
}

// NewOAuth creates a new OAuth2Config instance.
func NewOAuth() OAuth2Config {
	return OAuth2Config{
		Enabled:        false,
		PrivateKeyFile: "",
		Audience:       "",
		IssuerURL:      "",
	}
}

// NewToken creates a new TokenConfig instance.
func NewToken() TokenConfig {
	return TokenConfig{
		Enabled: false,
		Token:   "",
	}
}

func NewTls() TlsConfig {
	return TlsConfig{
		Enabled:                    false,
		RootCAsFile:                "",
		CertFile:                   "",
		KeyFile:                    "",
		TLSAllowInsecureConnection: true,
	}
}

// Validate checks whether Config is valid.
func (c *Config) Validate() error {
	if c.OAuth2.Enabled && c.Token.Enabled {
		return errors.New("only one auth method can be enabled at once")
	}
	if c.OAuth2.Enabled {
		return c.OAuth2.Validate()
	}
	if c.Token.Enabled {
		return c.Token.Validate()
	}
	if c.Tls.Enabled {
		return c.Tls.Validate()
	}
	return nil
}

// Validate checks whether OAuth2Config is valid.
func (c *OAuth2Config) Validate() error {
	if c.Audience == "" {
		return errors.New("oauth2 audience is empty")
	}
	if c.IssuerURL == "" {
		return errors.New("oauth2 issuer URL is empty")
	}
	if c.PrivateKeyFile == "" {
		return errors.New("oauth2 private key file is empty")
	}
	return nil
}

// ToMap returns OAuth2Config as a map representing OAuth2 client credentails.
func (c *OAuth2Config) ToMap() map[string]string {
	// Pulsar docs: https://pulsar.apache.org/docs/en/2.8.0/security-oauth2/#go-client
	return map[string]string{
		"type":       "client_credentials",
		"issuerUrl":  c.IssuerURL,
		"audience":   c.Audience,
		"privateKey": c.PrivateKeyFile,
	}
}

// Validate checks whether TokenConfig is valid.
func (c *TokenConfig) Validate() error {
	if c.Token == "" {
		return errors.New("token is empty")
	}
	return nil
}

// Validate checks whether TlsConfig is valid.
func (c *TlsConfig) Validate() error {
	if c.CertFile == "" {
		return errors.New("missing cert_file field in client certificate config")
	}
	if c.KeyFile == "" {
		return errors.New("missing key_file field in client certificate config")
	}
	if c.RootCAsFile == "" {
		return errors.New("missing root_cas_file field in client certificate config")
	}
	return nil
}
