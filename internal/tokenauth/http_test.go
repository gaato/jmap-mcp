package tokenauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

const testPRM = "https://mail-mcp.example.net/.well-known/oauth-protected-resource/mcp"

func protected(t *testing.T, env *testEnv) (http.Handler, *bool) {
	t.Helper()
	called := new(bool)
	h := Middleware(env.verifier(nil).Verify, testPRM)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		if _, ok := w.(*challengeWriter); ok {
			t.Error("next handler got the wrapping writer")
		}
		if ti := auth.TokenInfoFromContext(r.Context()); ti == nil || ti.UserID != testSubject {
			t.Errorf("token info = %+v", ti)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	return h, called
}

func do(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestChallengeWithoutToken(t *testing.T) {
	env := newEnv(t, newSigner(t, "k1"))
	h, called := protected(t, env)
	rec := do(h, "")
	if rec.Code != http.StatusUnauthorized || *called {
		t.Fatalf("code = %d", rec.Code)
	}
	want := `Bearer resource_metadata="` + testPRM + `", scope="mail_read"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestChallengeInvalidToken(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	h, called := protected(t, env)
	c := env.kanidmClaims()
	c["aud"] = "someone_else"
	rec := do(h, sign(t, k, c, "at+jwt"))
	if rec.Code != http.StatusUnauthorized || *called {
		t.Fatalf("code = %d", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(got, `Bearer error="invalid_token", resource_metadata="`+testPRM+`"`) {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	if strings.Contains(rec.Body.String(), "aud") {
		t.Fatalf("rejection reason leaked to client: %q", rec.Body.String())
	}
}

func TestInsufficientScope(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	h, called := protected(t, env)
	c := env.kanidmClaims()
	c["scope"] = "offline_access"
	rec := do(h, sign(t, k, c, "at+jwt"))
	if rec.Code != http.StatusForbidden || *called {
		t.Fatalf("code = %d", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(got, `Bearer error="insufficient_scope", `) || !strings.Contains(got, `scope="mail_read"`) ||
		!strings.Contains(got, `resource_metadata="`+testPRM+`"`) {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestValidTokenPasses(t *testing.T) {
	k := newSigner(t, "k1")
	env := newEnv(t, k)
	h, called := protected(t, env)
	// The SDK middleware checks expiry against the real clock, so mint a
	// token that is valid now.
	env.now = timeNow()
	rec := do(h, sign(t, k, env.kanidmClaims(), "at+jwt"))
	if rec.Code != http.StatusNoContent || !*called {
		t.Fatalf("code = %d body=%q", rec.Code, rec.Body.String())
	}
}
