// Package server wires the MCP endpoint, the OAuth protected resource
// metadata and the bearer-token middleware into one http.Handler.
package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gaato/jmap-mcp/internal/config"
	"github.com/gaato/jmap-mcp/internal/mailtools"
	"github.com/gaato/jmap-mcp/internal/tokenauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Version is reported to MCP clients.
var Version = "dev"

// MaxRequestBodyBytes bounds MCP request bodies.
const MaxRequestBodyBytes = 256 << 10

// HTTPServer returns an http.Server with conservative limits. In stateless
// mode each POST's response (JSON or a short SSE stream) ends when its tool
// call returns, and every tool call has a total budget of
// mailtools.ToolBudget (60 s) across all its JMAP requests, so the 90 s
// WriteTimeout leaves 30 s of margin.
func HTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
}

// New returns the HTTP handler for the whole server. verifiers maps each
// connector name to the token verifier for that connector's OAuth client;
// every connector in cfg must have one.
func New(cfg *config.Config, verifiers map[string]auth.TokenVerifier, tools *mailtools.Tools, log *slog.Logger) (http.Handler, error) {
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "jmap-mcp", Version: Version},
		&mcp.ServerOptions{Instructions: mailtools.Instructions})
	tools.Register(mcpServer)

	// One stateless handler serves all connectors; what differs per connector
	// is only which tokens are accepted in front of it.
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{
			Stateless: true,
			// The SDK's DNS-rebinding guard rejects requests that arrive on a
			// loopback listener with a non-loopback Host, which is exactly the
			// reverse-proxy setup this server is meant for. Every request must
			// carry a valid bearer token, which a rebinding attacker cannot
			// obtain, so the guard adds nothing here.
			DisableLocalhostProtection: true,
			// Tool calls are tiny JSON-RPC messages.
			MaxRequestBodyBytes: MaxRequestBodyBytes,
			// Stop work for clients that went away (protocol >= 2026-07-28).
			PropagateRequestCancellation: true,
		})

	// The bare /.well-known/oauth-protected-resource is intentionally not
	// served (404): each connector has its own issuer, and a client that
	// guessed the bare document would pick up the wrong authorization server.
	mux := http.NewServeMux()
	for _, cn := range cfg.Connectors {
		verify, ok := verifiers[cn.Name]
		if !ok {
			return nil, fmt.Errorf("no token verifier for connector %q", cn.Name)
		}
		mux.Handle(cn.MCPPath, tokenauth.Middleware(verify, cn.ResourceMetadataURL)(streamable))
		mux.Handle(cn.MetadataPath, auth.ProtectedResourceMetadataHandler(
			tokenauth.ProtectedResourceMetadata(cn.Resource, cn.Issuer)))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	return logRequests(log, mux), nil
}

// Verifiers builds one token verifier per connector. All connectors share
// the allowed subject and the introspection endpoint; each has its own
// issuer, audience and JWKS cache.
func Verifiers(cfg *config.Config, log *slog.Logger) map[string]auth.TokenVerifier {
	out := make(map[string]auth.TokenVerifier, len(cfg.Connectors))
	for _, cn := range cfg.Connectors {
		out[cn.Name] = tokenauth.New(tokenauth.Options{
			Issuer:           cn.Issuer,
			Audience:         cn.Audience,
			JWKSURL:          cn.JWKSURL,
			AllowedSubject:   cfg.OAuthAllowedSubject,
			IntrospectionURL: cfg.OAuthIntrospectionURL,
			Logger:           log.With("connector", cn.Name),
		}).Verify
	}
	return out
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) Flush() {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	_ = http.NewResponseController(s.ResponseWriter).Flush()
}

// logRequests logs method, path, status and duration. It never logs headers
// (which carry the bearer token) or bodies.
func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		log.InfoContext(r.Context(), "request", "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "duration_ms", time.Since(start).Milliseconds())
	})
}
