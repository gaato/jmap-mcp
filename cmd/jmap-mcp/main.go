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

	mail, err := jmap.NewClient(cfg.JMAPSessionURL, cfg.JMAPAllowedOrigin, cfg.JMAPUsername, cfg.JMAPPassword)
	if err != nil {
		return err
	}
	handler, err := server.New(cfg, server.Verifiers(cfg, log), mailtools.New(mail, log), log)
	if err != nil {
		return err
	}

	srv := server.HTTPServer(cfg.ListenAddr, handler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		for _, cn := range cfg.Connectors {
			log.Info("connector", "name", cn.Name, "resource", cn.Resource,
				"issuer", cn.Issuer, "audience", cn.Audience)
		}
		log.Info("listening", "addr", cfg.ListenAddr)
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
