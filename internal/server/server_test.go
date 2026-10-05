package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gaato/jmap-mcp/internal/config"
	"github.com/gaato/jmap-mcp/internal/jmap/jmaptest"
	"github.com/gaato/jmap-mcp/internal/mailtools"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	base    = "https://mail-mcp.example.net"
	subject = "0b4c6a8e-7f0e-4b7b-9d4e-2f3a5c6d7e8f"
)

// connector is one test OAuth client with its own signing key, as Kanidm
// gives every OAuth2 client its own key object.
type connector struct {
	name, issuer, audience, kid string
	key                         *ecdsa.PrivateKey
	jwks                        *httptest.Server
}

func newConnector(t *testing.T, name string) *connector {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &connector{
		name:     name,
		issuer:   "https://id.example.net/oauth2/openid/mcp-jmap-" + name,
		audience: "mcp-jmap-" + name,
		kid:      "kid-" + name,
		key:      key,
	}
	raw, _ := key.PublicKey.Bytes()
	enc := base64.RawURLEncoding.EncodeToString
	c.jwks = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "kid": c.kid, "use": "sig", "alg": "ES256",
			"x": enc(raw[1:33]), "y": enc(raw[33:]),
		}}})
	}))
	t.Cleanup(c.jwks.Close)
	return c
}

// token mints a Kanidm-shaped access token for this connector.
func (c *connector) token(t *testing.T, scope string) string {
	return c.tokenWith(t, scope, c.issuer, c.audience)
}

func (c *connector) tokenWith(t *testing.T, scope, iss, aud string) string {
	t.Helper()
	now := time.Now().Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": iss, "sub": subject, "aud": aud, "exp": now + 900, "nbf": now, "iat": now,
		"jti": "j1", "client_id": aud, "scope": scope, "session_id": "j1",
	})
	tok.Header["kid"] = c.kid
	tok.Header["typ"] = "at+jwt"
	s, err := tok.SignedString(c.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (c *connector) prmURL() string {
	return base + "/.well-known/oauth-protected-resource/" + c.name + "/mcp"
}

type fixture struct {
	srv             *httptest.Server
	claude, chatgpt *connector
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{claude: newConnector(t, "claude"), chatgpt: newConnector(t, "chatgpt")}
	mail := jmaptest.New()
	t.Cleanup(mail.Close)

	intro := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	t.Cleanup(intro.Close)

	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte(jmaptest.Password), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"PUBLIC_BASE_URL":         base,
		"CONNECTORS":              "claude,chatgpt",
		"OAUTH_ALLOWED_SUBJECT":   subject,
		"OAUTH_INTROSPECTION_URL": intro.URL,
		"JMAP_SESSION_URL":        mail.SessionURL(),
		"JMAP_USERNAME":           jmaptest.Username,
		"JMAP_PASSWORD_FILE":      pw,
	}
	for _, c := range []*connector{f.claude, f.chatgpt} {
		p := "CONNECTOR_" + strings.ToUpper(c.name) + "_"
		vars[p+"ISSUER"], vars[p+"AUDIENCE"], vars[p+"JWKS_URL"] = c.issuer, c.audience, c.jwks.URL
	}
	cfg, err := config.FromEnv(func(k string) string { return vars[k] })
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	tools := mailtools.New(jmaptest.MustClient(t, cfg.JMAPSessionURL, cfg.JMAPUsername, cfg.JMAPPassword), log)
	h, err := New(cfg, Verifiers(cfg, log), tools, log)
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewServer(h)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) post(t *testing.T, path, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func TestProtectedResourceMetadataPerConnector(t *testing.T) {
	f := setup(t)
	for _, c := range []*connector{f.claude, f.chatgpt} {
		resp, err := http.Get(f.srv.URL + "/.well-known/oauth-protected-resource/" + c.name + "/mcp")
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", c.name, resp.StatusCode)
		}
		want := map[string]any{
			"resource":                 base + "/" + c.name + "/mcp",
			"authorization_servers":    []any{c.issuer},
			"scopes_supported":         []any{"mail_read"},
			"bearer_methods_supported": []any{"header"},
		}
		for k, v := range want {
			got, _ := json.Marshal(doc[k])
			exp, _ := json.Marshal(v)
			if string(got) != string(exp) {
				t.Errorf("%s: %s = %s, want %s", c.name, k, got, exp)
			}
		}
	}
}

func TestNoBareOrUnknownEndpoints(t *testing.T) {
	f := setup(t)
	for _, p := range []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/mcp",
		"/.well-known/oauth-protected-resource/other/mcp",
	} {
		resp, err := http.Get(f.srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, resp.StatusCode)
		}
	}
	for _, p := range []string{"/mcp", "/other/mcp"} {
		if resp := f.post(t, p, f.claude.token(t, "mail_read")); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, resp.StatusCode)
		}
	}
}

func TestChallengePointsAtMatchingMetadata(t *testing.T) {
	f := setup(t)
	for _, c := range []*connector{f.claude, f.chatgpt} {
		resp := f.post(t, "/"+c.name+"/mcp", "")
		want := `Bearer resource_metadata="` + c.prmURL() + `", scope="mail_read"`
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != want {
			t.Errorf("%s: %d %q, want %q", c.name, resp.StatusCode, resp.Header.Get("WWW-Authenticate"), want)
		}
	}
}

func TestTokensDoNotCrossConnectors(t *testing.T) {
	f := setup(t)
	cases := []struct {
		name     string
		token    string
		endpoint *connector
	}{
		{"claude token on chatgpt", f.claude.token(t, "mail_read"), f.chatgpt},
		{"chatgpt token on claude", f.chatgpt.token(t, "mail_read"), f.claude},
		// Even if both clients shared a signing key, iss/aud pinning must
		// keep the tokens apart: a token signed by the endpoint's own key but
		// carrying the other connector's iss/aud is rejected.
		{"claude claims, chatgpt key, on chatgpt",
			f.chatgpt.tokenWith(t, "mail_read", f.claude.issuer, f.claude.audience), f.chatgpt},
		{"chatgpt claims, claude key, on claude",
			f.claude.tokenWith(t, "mail_read", f.chatgpt.issuer, f.chatgpt.audience), f.claude},
		{"right issuer, wrong audience",
			f.claude.tokenWith(t, "mail_read", f.claude.issuer, f.chatgpt.audience), f.claude},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := f.post(t, "/"+tc.endpoint.name+"/mcp", tc.token)
			want := `Bearer error="invalid_token", resource_metadata="` + tc.endpoint.prmURL() + `", scope="mail_read"`
			if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != want {
				t.Fatalf("%d %q, want 401 %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"), want)
			}
		})
	}
	// Sanity: each token works on its own endpoint (any non-401/403 status
	// means the auth layer let it through).
	for _, c := range []*connector{f.claude, f.chatgpt} {
		if resp := f.post(t, "/"+c.name+"/mcp", c.token(t, "mail_read")); resp.StatusCode == 401 || resp.StatusCode == 403 {
			t.Errorf("%s: own token rejected with %d", c.name, resp.StatusCode)
		}
	}
}

func TestInsufficientScope(t *testing.T) {
	f := setup(t)
	resp := f.post(t, "/chatgpt/mcp", f.chatgpt.token(t, "offline_access"))
	want := `Bearer error="insufficient_scope", resource_metadata="` + f.chatgpt.prmURL() + `", scope="mail_read"`
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("WWW-Authenticate") != want {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func connect(t *testing.T, ctx context.Context, url, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   url,
		HTTPClient: &http.Client{Transport: bearer{token}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestEndToEnd(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs := connect(t, ctx, f.srv.URL+"/claude/mcp", f.claude.token(t, "mail_read offline_access"))
	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range lt.Tools {
		names[tool.Name] = true
		a := tool.Annotations
		if a == nil || !a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint ||
			a.OpenWorldHint == nil || *a.OpenWorldHint {
			t.Errorf("%s: annotations %+v", tool.Name, a)
		}
	}
	for _, n := range []string{"search", "fetch", "list_mailboxes", "search_emails", "get_email", "get_thread"} {
		if !names[n] {
			t.Errorf("tool %s missing", n)
		}
	}

	// The ChatGPT endpoint serves the same tools against the same mailbox.
	cs = connect(t, ctx, f.srv.URL+"/chatgpt/mcp", f.chatgpt.token(t, "mail_read"))
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "search", Arguments: map[string]any{"query": "newsletter"}})
	if err != nil || res.IsError {
		t.Fatalf("search: %v %+v", err, res)
	}
	// ChatGPT contract: structuredContent plus the same JSON as text content.
	text := res.Content[0].(*mcp.TextContent).Text
	var sr struct {
		Results []struct{ ID, Title, URL string }
	}
	if err := json.Unmarshal([]byte(text), &sr); err != nil || len(sr.Results) != 1 || sr.Results[0].ID != "e3" {
		t.Fatalf("search text = %q", text)
	}

	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "fetch", Arguments: map[string]any{"id": "e3"}})
	if err != nil || res.IsError {
		t.Fatalf("fetch: %v %+v", err, res)
	}
	text = res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "UNTRUSTED EMAIL CONTENT") || strings.Contains(text, "<script") {
		t.Fatalf("fetch text = %q", text)
	}
}

func TestNewRequiresVerifierPerConnector(t *testing.T) {
	cfg := &config.Config{Connectors: []config.Connector{{Name: "claude", MCPPath: "/claude/mcp"}}}
	if _, err := New(cfg, nil, mailtools.New(nil, nil), slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("expected error for missing verifier")
	}
}

func TestHTTPServerLimits(t *testing.T) {
	s := HTTPServer(":0", http.NotFoundHandler())
	if s.ReadTimeout != 30*time.Second || s.WriteTimeout != 90*time.Second ||
		s.ReadHeaderTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes != 64<<10 {
		t.Fatalf("server = %+v", s)
	}
	if mailtools.ToolBudget+20*time.Second > s.WriteTimeout {
		t.Fatalf("tool budget %v leaves too little margin below WriteTimeout %v", mailtools.ToolBudget, s.WriteTimeout)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	f := setup(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("x", MaxRequestBodyBytes) + `"}}`
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/claude/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+f.claude.token(t, "mail_read"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", resp.StatusCode)
	}
}

func TestKeyServerOutageIs503(t *testing.T) {
	f := setup(t)
	f.claude.jwks.Close() // key server gone before the first request
	resp := f.post(t, "/claude/mcp", f.claude.token(t, "mail_read"))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", resp.StatusCode)
	}
}
