// Command jmap-mcp is a read-only MCP server for a JMAP mailbox, protected
// by OAuth 2.1 bearer tokens.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gaato/jmap-mcp/internal/config"
	"github.com/gaato/jmap-mcp/internal/jmap"
	"github.com/gaato/jmap-mcp/internal/mailtools"
	"github.com/gaato/jmap-mcp/internal/server"
	"github.com/gaato/jmap-mcp/internal/tokenauth"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}

	verifier := tokenauth.New(tokenauth.Options{
		Issuer:           cfg.OAuthIssuer,
		Audience:         cfg.OAuthAudience,
		JWKSURL:          cfg.OAuthJWKSURL,
		SubjectClaim:     cfg.OAuthSubjectClaim,
		AllowedSubject:   cfg.OAuthAllowedSubject,
		IntrospectionURL: cfg.OAuthIntrospectionURL,
		Logger:           log,
	})
	mail := jmap.NewClient(cfg.JMAPSessionURL, cfg.JMAPUsername, cfg.JMAPPassword, nil)
	handler := server.New(cfg, verifier.Verify, mailtools.New(mail, log), log)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "resource", cfg.PublicURL.String(),
			"issuer", cfg.OAuthIssuer, "audience", cfg.OAuthAudience)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
