// Package config loads the server configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Config is the complete runtime configuration.
type Config struct {
	ListenAddr string
	// PublicURL is the externally visible URL of the MCP endpoint, e.g.
	// https://mail-mcp.example.net/mcp. It is the RFC 9728 resource identifier.
	PublicURL *url.URL

	OAuthIssuer           string
	OAuthAudience         string
	OAuthJWKSURL          string
	OAuthAllowedSubject   string
	OAuthSubjectClaim     string
	OAuthIntrospectionURL string

	JMAPSessionURL string
	JMAPUsername   string
	JMAPPassword   string
}

// MCPPath returns the path component of the public MCP URL ("/mcp" by default).
func (c *Config) MCPPath() string {
	if p := c.PublicURL.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

// ResourceMetadataURL returns the path-suffixed RFC 9728 metadata URL for the
// MCP endpoint, which is what the WWW-Authenticate challenge points to.
func (c *Config) ResourceMetadataURL() string {
	u := *c.PublicURL
	p := strings.TrimSuffix(c.MCPPath(), "/")
	u.Path = "/.well-known/oauth-protected-resource" + p
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// FromEnv reads the configuration using getenv (normally os.Getenv). All
// problems are collected so that a misconfigured deployment fails once with
// a complete list.
func FromEnv(getenv func(string) string) (*Config, error) {
	var errs []error
	req := func(name string) string {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
		return v
	}
	opt := func(name, def string) string {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			return v
		}
		return def
	}
	absURL := func(name, v string) *url.URL {
		if v == "" {
			return nil
		}
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, fmt.Errorf("%s must be an absolute http(s) URL", name))
			return nil
		}
		return u
	}

	c := &Config{
		ListenAddr:            opt("LISTEN_ADDR", ":8080"),
		OAuthIssuer:           req("OAUTH_ISSUER"),
		OAuthAudience:         req("OAUTH_AUDIENCE"),
		OAuthAllowedSubject:   req("OAUTH_ALLOWED_SUBJECT"),
		OAuthSubjectClaim:     opt("OAUTH_SUBJECT_CLAIM", "sub"),
		OAuthIntrospectionURL: opt("OAUTH_INTROSPECTION_URL", ""),
		JMAPSessionURL:        req("JMAP_SESSION_URL"),
		JMAPUsername:          req("JMAP_USERNAME"),
	}

	publicURL := req("PUBLIC_URL")
	c.PublicURL = absURL("PUBLIC_URL", publicURL)
	if c.PublicURL != nil && (c.PublicURL.RawQuery != "" || c.PublicURL.Fragment != "") {
		errs = append(errs, errors.New("PUBLIC_URL must not have a query or fragment"))
	}
	absURL("OAUTH_ISSUER", c.OAuthIssuer)
	absURL("JMAP_SESSION_URL", c.JMAPSessionURL)
	absURL("OAUTH_INTROSPECTION_URL", c.OAuthIntrospectionURL)

	c.OAuthJWKSURL = opt("OAUTH_JWKS_URL", "")
	if c.OAuthJWKSURL == "" && c.OAuthIssuer != "" {
		// Kanidm publishes the per-client JWKS at <issuer>/public_key.jwk.
		c.OAuthJWKSURL = strings.TrimSuffix(c.OAuthIssuer, "/") + "/public_key.jwk"
	}
	absURL("OAUTH_JWKS_URL", c.OAuthJWKSURL)

	if pwFile := req("JMAP_PASSWORD_FILE"); pwFile != "" {
		b, err := os.ReadFile(pwFile)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("JMAP_PASSWORD_FILE: %w", err))
		case strings.TrimSpace(string(b)) == "":
			errs = append(errs, errors.New("JMAP_PASSWORD_FILE is empty"))
		default:
			c.JMAPPassword = strings.TrimRight(string(b), "\r\n")
		}
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}
