package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestFromEnv(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("s3cret pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := FromEnv(env(map[string]string{
		"PUBLIC_URL":            "https://mail-mcp.example.net/mcp",
		"OAUTH_ISSUER":          "https://id.example.net/oauth2/openid/mcp_jmap",
		"OAUTH_AUDIENCE":        "mcp_jmap",
		"OAUTH_ALLOWED_SUBJECT": "uuid",
		"JMAP_SESSION_URL":      "https://mail.example.net/.well-known/jmap",
		"JMAP_USERNAME":         "me",
		"JMAP_PASSWORD_FILE":    pw,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.JMAPPassword != "s3cret pass" || c.ListenAddr != ":8080" || c.OAuthSubjectClaim != "sub" {
		t.Fatalf("config = %+v", c)
	}
	if c.OAuthJWKSURL != "https://id.example.net/oauth2/openid/mcp_jmap/public_key.jwk" {
		t.Fatalf("jwks = %q", c.OAuthJWKSURL)
	}
	if c.MCPPath() != "/mcp" || c.ResourceMetadataURL() != "https://mail-mcp.example.net/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("paths: %q %q", c.MCPPath(), c.ResourceMetadataURL())
	}
}

func TestFromEnvFailsFast(t *testing.T) {
	_, err := FromEnv(env(map[string]string{"PUBLIC_URL": "not a url", "JMAP_PASSWORD_FILE": "/nonexistent"}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"OAUTH_ISSUER is required", "OAUTH_AUDIENCE is required", "OAUTH_ALLOWED_SUBJECT is required",
		"JMAP_SESSION_URL is required", "JMAP_USERNAME is required", "PUBLIC_URL must be", "JMAP_PASSWORD_FILE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}
