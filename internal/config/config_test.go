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

func validEnv(t *testing.T) map[string]string {
	t.Helper()
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("s3cret pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"PUBLIC_BASE_URL":                    "https://mail-mcp.example.net",
		"CONNECTORS":                         "claude, chatgpt",
		"CONNECTOR_CLAUDE_ISSUER":            "https://id.example.net/oauth2/openid/mcp-jmap-claude",
		"CONNECTOR_CLAUDE_AUDIENCE":          "mcp-jmap-claude",
		"CONNECTOR_CHATGPT_ISSUER":           "https://id.example.net/oauth2/openid/mcp-jmap-chatgpt",
		"CONNECTOR_CHATGPT_AUDIENCE":         "mcp-jmap-chatgpt",
		"CONNECTOR_CHATGPT_JWKS_URL":         "https://id.example.net/custom.jwk",
		"OAUTH_ALLOWED_SUBJECT":              "uuid",
		"JMAP_SESSION_URL":                   "https://mail.example.net/.well-known/jmap",
		"JMAP_USERNAME":                      "me",
		"JMAP_PASSWORD_FILE":                 pw,
		"UNRELATED_CONNECTOR_IGNORED_ISSUER": "x",
	}
}

func TestFromEnv(t *testing.T) {
	c, err := FromEnv(env(validEnv(t)))
	if err != nil {
		t.Fatal(err)
	}
	if c.JMAPPassword != "s3cret pass" || c.ListenAddr != ":8080" || c.OAuthSubjectClaim != "sub" {
		t.Fatalf("config = %+v", c)
	}
	if len(c.Connectors) != 2 {
		t.Fatalf("connectors = %+v", c.Connectors)
	}
	cl, gpt := c.Connectors[0], c.Connectors[1]
	want := Connector{
		Name:                "claude",
		Issuer:              "https://id.example.net/oauth2/openid/mcp-jmap-claude",
		Audience:            "mcp-jmap-claude",
		JWKSURL:             "https://id.example.net/oauth2/openid/mcp-jmap-claude/public_key.jwk",
		MCPPath:             "/claude/mcp",
		Resource:            "https://mail-mcp.example.net/claude/mcp",
		MetadataPath:        "/.well-known/oauth-protected-resource/claude/mcp",
		ResourceMetadataURL: "https://mail-mcp.example.net/.well-known/oauth-protected-resource/claude/mcp",
	}
	if cl != want {
		t.Fatalf("claude = %+v", cl)
	}
	if gpt.JWKSURL != "https://id.example.net/custom.jwk" || gpt.Resource != "https://mail-mcp.example.net/chatgpt/mcp" {
		t.Fatalf("chatgpt = %+v", gpt)
	}
}

func TestFromEnvTrailingSlashBase(t *testing.T) {
	e := validEnv(t)
	e["PUBLIC_BASE_URL"] = "https://mail-mcp.example.net/"
	c, err := FromEnv(env(e))
	if err != nil {
		t.Fatal(err)
	}
	if c.Connectors[0].Resource != "https://mail-mcp.example.net/claude/mcp" {
		t.Fatalf("resource = %q", c.Connectors[0].Resource)
	}
}

func TestFromEnvFailsFast(t *testing.T) {
	_, err := FromEnv(env(map[string]string{"PUBLIC_BASE_URL": "not a url", "JMAP_PASSWORD_FILE": "/nonexistent"}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"CONNECTORS is required", "OAUTH_ALLOWED_SUBJECT is required",
		"JMAP_SESSION_URL is required", "JMAP_USERNAME is required", "PUBLIC_BASE_URL must be", "JMAP_PASSWORD_FILE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

func TestFromEnvConnectorErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(map[string]string)
		want string
	}{
		{"missing issuer", func(e map[string]string) { delete(e, "CONNECTOR_CLAUDE_ISSUER") }, "CONNECTOR_CLAUDE_ISSUER is required"},
		{"missing audience", func(e map[string]string) { delete(e, "CONNECTOR_CHATGPT_AUDIENCE") }, "CONNECTOR_CHATGPT_AUDIENCE is required"},
		{"duplicate name", func(e map[string]string) { e["CONNECTORS"] = "claude,chatgpt,claude" }, `duplicate connector "claude"`},
		{"names colliding in env", func(e map[string]string) {
			e["CONNECTORS"] = "my-app,my_app"
			e["CONNECTOR_MY_APP_ISSUER"] = "https://id.example.net/x"
			e["CONNECTOR_MY_APP_AUDIENCE"] = "x"
		}, `duplicate connector "my_app"`},
		{"shared issuer", func(e map[string]string) {
			e["CONNECTOR_CHATGPT_ISSUER"] = e["CONNECTOR_CLAUDE_ISSUER"]
		}, "share the issuer"},
		{"shared audience", func(e map[string]string) {
			e["CONNECTOR_CHATGPT_AUDIENCE"] = e["CONNECTOR_CLAUDE_AUDIENCE"]
		}, "share the audience"},
		{"bad name", func(e map[string]string) { e["CONNECTORS"] = "Claude" }, "invalid name"},
		{"empty list", func(e map[string]string) { e["CONNECTORS"] = " , " }, "at least one connector"},
		{"base with path", func(e map[string]string) { e["PUBLIC_BASE_URL"] = "https://mail-mcp.example.net/x" }, "without path"},
		{"bad issuer", func(e map[string]string) { e["CONNECTOR_CLAUDE_ISSUER"] = "id.example.net" }, "CONNECTOR_CLAUDE_ISSUER must be"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnv(t)
			tc.mod(e)
			_, err := FromEnv(env(e))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
