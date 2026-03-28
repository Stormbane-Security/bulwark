package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stormbane-security/bulwark/internal/audit"
	"github.com/stormbane-security/bulwark/internal/config"
	"github.com/stormbane-security/bulwark/internal/gateway"
	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Bulwark gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				return fmt.Errorf("--config is required")
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}
			return serve(cfg)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "path to bulwark.yaml")
	return cmd
}

func serve(cfg *config.Config) error {
	auditLog := audit.NewJSONLogger(os.Stdout)

	if len(cfg.Listeners) == 0 {
		return fmt.Errorf("no listeners configured")
	}

	// Phase 1: single listener only. Multi-listener support deferred.
	if len(cfg.Listeners) > 1 {
		fmt.Fprintf(os.Stderr, "bulwark: warning: %d listeners configured, only the first will be started in this build\n", len(cfg.Listeners))
	}
	l := cfg.Listeners[0]

	handler, err := gateway.NewHandler(cfg, auditLog)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}

	srv := &http.Server{
		Addr:    l.Addr,
		Handler: handler,
	}

	// Bind the listener early so we fail fast on address conflicts.
	ln, err := net.Listen("tcp", l.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", l.Addr, err)
	}

	fmt.Fprintf(os.Stderr, "bulwark listening on %s\n", l.Addr)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-quit:
		fmt.Fprintf(os.Stderr, "bulwark shutting down (%s)\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
