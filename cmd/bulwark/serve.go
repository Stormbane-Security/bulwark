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

	"github.com/patrickputman/bulwark/internal/audit"
	"github.com/patrickputman/bulwark/internal/config"
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
	_ = auditLog // will be wired into the pipeline in Phase 1

	if len(cfg.Listeners) == 0 {
		return fmt.Errorf("no listeners configured")
	}

	// Phase 0: single listener only. Full pipeline wired in Phase 1.
	if len(cfg.Listeners) > 1 {
		fmt.Fprintf(os.Stderr, "bulwark: warning: %d listeners configured, only the first will be started in this build\n", len(cfg.Listeners))
	}
	l := cfg.Listeners[0]

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not implemented", http.StatusNotImplemented)
	})

	srv := &http.Server{
		Addr:    l.Addr,
		Handler: mux,
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
