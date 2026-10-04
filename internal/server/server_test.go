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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gaato/jmap-mcp/internal/config"
	"github.com/gaato/jmap-mcp/internal/jmap"
	"github.com/gaato/jmap-mcp/internal/jmap/jmaptest"
	"github.com/gaato/jmap-mcp/internal/mailtools"
	"github.com/gaato/jmap-mcp/internal/tokenauth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	issuer   = "https://id.example.net/oauth2/openid/mcp_jmap"
	audience = "mcp_jmap"
	subject  = "0b4c6a8e-7f0e-4b7b-9d4e-2f3a5c6d7e8f"
)

type fixture struct {
	srv  *httptest.Server
	cfg  *config.Config
	key  *ecdsa.PrivateKey
	mail *jmaptest.Server
}

func setup(t *testing.T) *fixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := key.PublicKey.Bytes()
	enc := base64.RawURLEncoding.EncodeToString
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256",
			"x": enc(raw[1:33]), "y": enc(raw[33:]),
		}}})
	}))
	t.Cleanup(jwks.Close)
	mail := jmaptest.New()
	t.Cleanup(mail.Close)

	pub, _ := url.Parse("https://mail-mcp.example.net/mcp")
	cfg := &config.Config{PublicURL: pub, OAuthIssuer: issuer, OAuthAudience: audience}
	v := tokenauth.New(tokenauth.Options{Issuer: issuer, Audience: audience, JWKSURL: jwks.URL, AllowedSubject: subject})
	tools := mailtools.New(jmap.NewClient(mail.SessionURL(), jmaptest.Username, jmaptest.Password, nil), nil)
	srv := httptest.NewServer(New(cfg, v.Verify, tools, slogDiscard()))
	t.Cleanup(srv.Close)
	return &fixture{srv: srv, cfg: cfg, key: key, mail: mail}
}

func (f *fixture) token(t *testing.T, scope string) string {
	t.Helper()
	now := time.Now().Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": issuer, "sub": subject, "aud": audience, "exp": now + 900, "nbf": now, "iat": now,
		"jti": "j1", "client_id": audience, "scope": scope, "session_id": "j1",
	})
	tok.Header["kid"] = "k1"
	tok.Header["typ"] = "at+jwt"
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestProtectedResourceMetadata(t *testing.T) {
	f := setup(t)
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp, err := http.Get(f.srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", p, resp.StatusCode)
		}
		want := map[string]any{
			"resource":                 "https://mail-mcp.example.net/mcp",
			"authorization_servers":    []any{issuer},
			"scopes_supported":         []any{"mail_read"},
			"bearer_methods_supported": []any{"header"},
		}
		for k, v := range want {
			got, _ := json.Marshal(doc[k])
			exp, _ := json.Marshal(v)
			if string(got) != string(exp) {
				t.Errorf("%s: %s = %s, want %s", p, k, got, exp)
			}
		}
	}
	if got := f.cfg.ResourceMetadataURL(); got != "https://mail-mcp.example.net/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("ResourceMetadataURL = %q", got)
	}
}

func TestMCPRequiresToken(t *testing.T) {
	f := setup(t)
	resp, err := http.Post(f.srv.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	want := `Bearer resource_metadata="https://mail-mcp.example.net/.well-known/oauth-protected-resource/mcp", scope="mail_read"`
	if got := resp.Header.Get("WWW-Authenticate"); got != want {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestEndToEnd(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   f.srv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{f.token(t, "mail_read offline_access")}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

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

func TestEndToEndInsufficientScope(t *testing.T) {
	f := setup(t)
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+f.token(t, "offline_access"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden ||
		!strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), `Bearer error="insufficient_scope"`) {
		t.Fatalf("status %d, %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

func slogDiscard() *slog.Logger { return slog.New(slog.DiscardHandler) }
