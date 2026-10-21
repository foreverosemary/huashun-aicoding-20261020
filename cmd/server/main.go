package main

import (
	"bannerfp/internal/api"
	"bannerfp/internal/fingerprint"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}
func run() error {
	addr := flag.String("addr", env("LISTEN_ADDR", ":8080"), "listen address")
	rules := flag.String("rules", env("RULES_PATH", "rules/fingerprints.json"), "external rule file")
	health := flag.Bool("healthcheck", false, "probe health and exit")
	flag.Parse()
	if *health {
		client := http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://127.0.0.1:8080/health")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("health status: %d", resp.StatusCode)
		}
		return nil
	}
	engine, err := fingerprint.Load(*rules)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *addr, Handler: api.Handler(engine), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", *addr, "rules", len(engine.Rules))
		done <- server.ListenAndServe()
	}()
	select {
	case err := <-done:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return err
		}
		return nil
	}
}
func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
