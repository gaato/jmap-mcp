// Package config loads the server configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/gaato/jmap-mcp/internal/urlpolicy"
)

// Connector is one MCP client application (e.g. Claude or ChatGPT) with its
// own OAuth client at the authorization server. Each connector gets its own
// MCP endpoint and protected resource metadata, because Kanidm issuers are
// per client and some MCP clients only use the first authorization server.
type Connector struct {
	Name     string
	Issuer   string // exact expected iss
	Audience string // required aud value (the Kanidm client name)
	JWKSURL  string

	// Derived from PUBLIC_BASE_URL and Name.
	MCPPath             string // /<name>/mcp
	Resource            string // PUBLIC_BASE_URL + MCPPath, the RFC 9728 resource
	MetadataPath        string // /.well-known/oauth-protected-resource/<name>/mcp
	ResourceMetadataURL string // PUBLIC_BASE_URL + MetadataPath
}

// Config is the complete runtime configuration.
type Config struct {
	ListenAddr    string
	PublicBaseURL string // scheme://host[:port], no trailing slash
	Connectors    []Connector

	// Shared by all connectors.
	OAuthAllowedSubject   string
	OAuthIntrospectionURL string

	JMAPSessionURL string
	// JMAPAllowedOrigin is an optional second origin (besides the session
	// URL's) that redirects and the session's apiUrl may point to.
	JMAPAllowedOrigin string
	JMAPUsername      string
	JMAPPassword      string
}

// MetadataPrefix is the RFC 9728 well-known path. Only the path-suffixed
// form exists; the bare prefix is deliberately not served.
const MetadataPrefix = "/.well-known/oauth-protected-resource"

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var connectorName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// envKey maps a connector name to its environment variable infix:
// "my-app" -> "MY_APP".
func envKey(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
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
		u, err := urlpolicy.Parse(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %w", name, err))
			return nil
		}
		return u
	}

	c := &Config{
		ListenAddr:            opt("LISTEN_ADDR", ":8080"),
		OAuthAllowedSubject:   req("OAUTH_ALLOWED_SUBJECT"),
		OAuthIntrospectionURL: req("OAUTH_INTROSPECTION_URL"),
		JMAPSessionURL:        req("JMAP_SESSION_URL"),
		JMAPUsername:          req("JMAP_USERNAME"),
	}

	if base := absURL("PUBLIC_BASE_URL", req("PUBLIC_BASE_URL")); base != nil {
		if (base.Path != "" && base.Path != "/") || base.RawQuery != "" {
			errs = append(errs, errors.New("PUBLIC_BASE_URL must be scheme://host[:port] without path or query"))
		} else {
			c.PublicBaseURL = base.Scheme + "://" + base.Host
		}
	}
	if c.OAuthAllowedSubject != "" && !uuidRE.MatchString(c.OAuthAllowedSubject) {
		errs = append(errs, errors.New("OAUTH_ALLOWED_SUBJECT must be a lowercase hyphenated UUID (the Kanidm account uuid)"))
	}
	absURL("JMAP_SESSION_URL", c.JMAPSessionURL)
	if v := opt("JMAP_ALLOWED_ORIGIN", ""); v != "" {
		if u := absURL("JMAP_ALLOWED_ORIGIN", v); u != nil {
			if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
				errs = append(errs, errors.New("JMAP_ALLOWED_ORIGIN must be scheme://host[:port] without path or query"))
			} else {
				c.JMAPAllowedOrigin = urlpolicy.Origin(u)
			}
		}
	}
	absURL("OAUTH_INTROSPECTION_URL", c.OAuthIntrospectionURL)

	seenName := map[string]bool{}
	seenIssuer := map[string]string{}
	seenAudience := map[string]string{}
	connectors := req("CONNECTORS")
	for _, raw := range strings.Split(connectors, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if !connectorName.MatchString(name) {
			errs = append(errs, fmt.Errorf("CONNECTORS: invalid name %q (use lowercase letters, digits, - and _)", name))
			continue
		}
		key := envKey(name)
		if seenName[key] {
			errs = append(errs, fmt.Errorf("CONNECTORS: duplicate connector %q", name))
			continue
		}
		seenName[key] = true

		prefix := "CONNECTOR_" + key + "_"
		cn := Connector{
			Name:     name,
			Issuer:   req(prefix + "ISSUER"),
			Audience: req(prefix + "AUDIENCE"),
			JWKSURL:  opt(prefix+"JWKS_URL", ""),
		}
		absURL(prefix+"ISSUER", cn.Issuer)
		if cn.JWKSURL == "" && cn.Issuer != "" {
			// Kanidm publishes the per-client JWKS at <issuer>/public_key.jwk.
			cn.JWKSURL = strings.TrimSuffix(cn.Issuer, "/") + "/public_key.jwk"
		}
		absURL(prefix+"JWKS_URL", cn.JWKSURL)
		// Sharing an issuer or audience would let one connector's tokens work
		// on another connector's endpoint.
		if other, dup := seenIssuer[cn.Issuer]; dup && cn.Issuer != "" {
			errs = append(errs, fmt.Errorf("connectors %q and %q share the issuer %s", other, name, cn.Issuer))
		}
		if other, dup := seenAudience[cn.Audience]; dup && cn.Audience != "" {
			errs = append(errs, fmt.Errorf("connectors %q and %q share the audience %s", other, name, cn.Audience))
		}
		seenIssuer[cn.Issuer], seenAudience[cn.Audience] = name, name

		cn.MCPPath = "/" + name + "/mcp"
		cn.MetadataPath = MetadataPrefix + cn.MCPPath
		c.Connectors = append(c.Connectors, cn)
	}
	if connectors != "" && len(seenName) == 0 {
		errs = append(errs, errors.New("CONNECTORS must list at least one connector"))
	}

	if pwFile := req("JMAP_PASSWORD_FILE"); pwFile != "" {
		pw, err := readSecretFile(pwFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("JMAP_PASSWORD_FILE: %w", err))
		}
		c.JMAPPassword = pw
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	for i := range c.Connectors {
		cn := &c.Connectors[i]
		cn.Resource = c.PublicBaseURL + cn.MCPPath
		cn.ResourceMetadataURL = c.PublicBaseURL + cn.MetadataPath
	}
	return c, nil
}

// readSecretFile reads a secret from a regular, non-symlink file that is not
// accessible by group or others. The file is opened once with O_NOFOLLOW
// (and O_NONBLOCK, so a FIFO cannot hang startup); the checks use fstat on
// that descriptor and the content is read from it, so the path cannot be
// swapped between check and read.
func readSecretFile(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return "", errors.New("must not be a symlink")
		}
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	switch {
	case !fi.Mode().IsRegular():
		return "", errors.New("must be a regular file")
	case fi.Mode().Perm()&0o077 != 0:
		return "", fmt.Errorf("permissions %04o are too open; group/other must have no access (e.g. chmod 0400)", fi.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return "", err
	}
	pw := strings.TrimRight(string(b), "\r\n")
	if strings.TrimSpace(pw) == "" {
		return "", errors.New("is empty")
	}
	return pw, nil
}
