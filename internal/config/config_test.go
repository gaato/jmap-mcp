package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
		"OAUTH_ALLOWED_SUBJECT":              "0b4c6a8e-7f0e-4b7b-9d4e-2f3a5c6d7e8f",
		"OAUTH_INTROSPECTION_URL":            "https://id.example.net/oauth2/token/introspect",
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
	if c.JMAPPassword != "s3cret pass" || c.ListenAddr != ":8080" {
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
		{"missing introspection", func(e map[string]string) { delete(e, "OAUTH_INTROSPECTION_URL") }, "OAUTH_INTROSPECTION_URL is required"},
		{"subject not a uuid", func(e map[string]string) { e["OAUTH_ALLOWED_SUBJECT"] = "gaato" }, "must be a lowercase hyphenated UUID"},
		{"subject uppercase uuid", func(e map[string]string) {
			e["OAUTH_ALLOWED_SUBJECT"] = "0B4C6A8E-7F0E-4B7B-9D4E-2F3A5C6D7E8F"
		}, "must be a lowercase hyphenated UUID"},
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

func TestFromEnvRequiresHTTPS(t *testing.T) {
	for _, name := range []string{"PUBLIC_BASE_URL", "CONNECTOR_CLAUDE_ISSUER", "CONNECTOR_CHATGPT_JWKS_URL",
		"OAUTH_INTROSPECTION_URL", "JMAP_SESSION_URL", "JMAP_ALLOWED_ORIGIN"} {
		t.Run(name, func(t *testing.T) {
			e := validEnv(t)
			e[name] = "http://plain.example.net"
			_, err := FromEnv(env(e))
			if err == nil || !strings.Contains(err.Error(), name+" must use https") {
				t.Fatalf("err = %v", err)
			}
			e[name] = "https://user:pw@id.example.net"
			if _, err := FromEnv(env(e)); err == nil || !strings.Contains(err.Error(), name+" must not contain credentials") {
				t.Fatalf("userinfo: err = %v", err)
			}
		})
	}
	e := validEnv(t)
	e["JMAP_SESSION_URL"] = "https://mail.example.net/.well-known/jmap#x"
	if _, err := FromEnv(env(e)); err == nil || !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("fragment: err = %v", err)
	}
}

func TestFromEnvAllowsLoopbackHTTP(t *testing.T) {
	e := validEnv(t)
	e["PUBLIC_BASE_URL"] = "http://localhost:8080"
	e["JMAP_SESSION_URL"] = "http://127.0.0.1:8081/.well-known/jmap"
	e["OAUTH_INTROSPECTION_URL"] = "http://[::1]:8443/oauth2/token/introspect"
	e["JMAP_ALLOWED_ORIGIN"] = "https://Mail.Example.net:443"
	c, err := FromEnv(env(e))
	if err != nil {
		t.Fatal(err)
	}
	if c.JMAPAllowedOrigin != "https://mail.example.net" {
		t.Fatalf("origin = %q", c.JMAPAllowedOrigin)
	}
}

func TestPasswordFileChecks(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	open := filepath.Join(dir, "open")
	link := filepath.Join(dir, "link")
	_ = os.WriteFile(good, []byte("pw\n"), 0o400)
	_ = os.WriteFile(open, []byte("pw\n"), 0o640)
	_ = os.Symlink(good, link)
	cases := map[string]string{
		good: "",
		open: "too open",
		link: "symlink",
		dir:  "regular file",
	}
	for path, want := range cases {
		e := validEnv(t)
		e["JMAP_PASSWORD_FILE"] = path
		_, err := FromEnv(env(e))
		if want == "" {
			if err != nil {
				t.Errorf("%s: %v", path, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", path, err, want)
		}
	}
}

func TestPasswordFileFIFOAndEmpty(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	for path, want := range map[string]string{fifo: "regular file", empty: "is empty"} {
		e := validEnv(t)
		e["JMAP_PASSWORD_FILE"] = path
		done := make(chan error, 1)
		go func() { _, err := FromEnv(env(e)); done <- err }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: err = %v, want %q", path, err, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: reading the secret blocked", path)
		}
	}
}

func TestPasswordFileReadThroughDescriptor(t *testing.T) {
	// The content returned is what the checked descriptor reads, even if
	// the path is replaced by a symlink afterwards.
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	_ = os.WriteFile(p, []byte("first\n"), 0o600)
	got, err := readSecretFile(p)
	if err != nil || got != "first" {
		t.Fatalf("got %q, %v", got, err)
	}
	other := filepath.Join(dir, "other")
	_ = os.WriteFile(other, []byte("second"), 0o644)
	_ = os.Remove(p)
	_ = os.Symlink(other, p)
	if _, err := readSecretFile(p); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink swapped in: err = %v", err)
	}
}
