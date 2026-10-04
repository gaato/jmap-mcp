package tokenauth

import (
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// Scope is the only scope this resource server understands. Kanidm scope
// names must match ^[0-9a-zA-Z_]+$, hence the underscore.
const Scope = "mail_read"

// ProtectedResourceMetadata returns the RFC 9728 document for resource.
func ProtectedResourceMetadata(resource, issuer string) *oauthex.ProtectedResourceMetadata {
	return &oauthex.ProtectedResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   []string{issuer},
		ScopesSupported:        []string{Scope},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "JMAP mail (read-only)",
	}
}

// Middleware protects next with auth.RequireBearerToken and adds the RFC 6750
// error codes the SDK leaves out of its WWW-Authenticate challenge:
// error="invalid_token" on 401 when a token was presented, and
// error="insufficient_scope" on 403. The SDK answers 500 when the verifier
// fails for reasons other than a bad token; that only happens when the JWKS
// or introspection endpoint is unavailable, so it is turned into 503.
func Middleware(verify auth.TokenVerifier, resourceMetadataURL string) func(http.Handler) http.Handler {
	require := auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetadataURL,
		Scopes:              []string{Scope},
		ClockSkew:           DefaultLeeway,
	})
	return func(next http.Handler) http.Handler {
		// The SDK middleware passes our wrapper through on success; hand the
		// original writer to next so that flushing (SSE) keeps working.
		inner := require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cw, ok := w.(*challengeWriter); ok {
				w = cw.ResponseWriter
			}
			next.ServeHTTP(w, r)
		}))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cw := &challengeWriter{ResponseWriter: w, hadToken: r.Header.Get("Authorization") != ""}
			inner.ServeHTTP(cw, r)
		})
	}
}

type challengeWriter struct {
	http.ResponseWriter
	hadToken bool
}

func (c *challengeWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *challengeWriter) WriteHeader(code int) {
	var errCode string
	switch {
	case code == http.StatusForbidden:
		errCode = "insufficient_scope"
	case code == http.StatusUnauthorized && c.hadToken:
		errCode = "invalid_token"
	}
	h := c.ResponseWriter.Header()
	if v := h.Get("WWW-Authenticate"); errCode != "" && strings.HasPrefix(v, "Bearer ") {
		h.Set("WWW-Authenticate", `Bearer error="`+errCode+`", `+strings.TrimPrefix(v, "Bearer "))
	}
	if code == http.StatusInternalServerError {
		h.Set("Retry-After", "30")
		code = http.StatusServiceUnavailable
	}
	c.ResponseWriter.WriteHeader(code)
}
