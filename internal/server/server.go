// Package server wires the MCP endpoint, the OAuth protected resource
// metadata and the bearer-token middleware into one http.Handler.
package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gaato/jmap-mcp/internal/config"
	"github.com/gaato/jmap-mcp/internal/mailtools"
	"github.com/gaato/jmap-mcp/internal/tokenauth"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Version is reported to MCP clients.
var Version = "dev"

// New returns the HTTP handler for the whole server.
func New(cfg *config.Config, verify auth.TokenVerifier, tools *mailtools.Tools, log *slog.Logger) http.Handler {
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "jmap-mcp", Version: Version},
		&mcp.ServerOptions{Instructions: mailtools.Instructions})
	tools.Register(mcpServer)

	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{
			Stateless: true,
			// The SDK's DNS-rebinding guard rejects requests that arrive on a
			// loopback listener with a non-loopback Host, which is exactly the
			// reverse-proxy setup this server is meant for. Every request must
			// carry a valid bearer token, which a rebinding attacker cannot
			// obtain, so the guard adds nothing here.
			DisableLocalhostProtection: true,
		})

	mcpPath := cfg.MCPPath()
	prm := auth.ProtectedResourceMetadataHandler(
		tokenauth.ProtectedResourceMetadata(cfg.PublicURL.String(), cfg.OAuthIssuer))

	mux := http.NewServeMux()
	mux.Handle(mcpPath, tokenauth.Middleware(verify, cfg.ResourceMetadataURL())(streamable))
	mux.Handle("/.well-known/oauth-protected-resource", prm)
	if suffix := strings.TrimSuffix(mcpPath, "/"); suffix != "" {
		mux.Handle("/.well-known/oauth-protected-resource"+suffix, prm)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	return logRequests(log, mux)
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
