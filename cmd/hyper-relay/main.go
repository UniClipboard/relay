// SPDX-License-Identifier: AGPL-3.0-only

// Command hyper-relay is the standalone, zero-knowledge Relay HTTP API v1
// microservice for self-hosted and Cloud-managed UniClipboard hybrid sync
// transfers. It shares its credential abstraction (internal/auth) with the
// future P2P/DERP relay service while remaining completely decoupled in
// process and runtime behavior.
package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/uniclipboard/relay/internal/auth"
	"github.com/uniclipboard/relay/internal/hyper"
)

func main() {
	addr := firstNonEmpty(os.Getenv("HYPER_ADDR"), os.Getenv("UNIC_RELAY_ADDR"))
	if addr == "" {
		addr = ":8080"
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck(addr))
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	authorizer, err := auth.LoadStaticFromEnv(os.Getenv)
	if err != nil {
		logger.Error("failed to load shared relay credentials", "error", err)
		os.Exit(1)
	}

	cfg := hyper.Config{
		Origin:     firstNonEmpty(os.Getenv("HYPER_ORIGIN"), os.Getenv("UNIC_RELAY_ORIGIN")),
		Authorizer: authorizer,
	}

	if n, ok := parseEnvInt64("HYPER_MAX_TRANSFER_BYTES", "UNIC_RELAY_MAX_BYTES"); ok && n > 0 {
		cfg.MaxTransferBytes = n
	}
	if n, ok := parseEnvInt("HYPER_MAX_SENDERS"); ok && n > 0 {
		cfg.MaxSendersPerMailbox = n
	}
	if n, ok := parseEnvInt("HYPER_MAX_TRANSFERS"); ok && n > 0 {
		cfg.MaxTransfersPerMailbox = n
	}
	if d, ok := parseEnvDuration("HYPER_DEFAULT_TTL"); ok && d > 0 {
		cfg.DefaultTTL = d
	}
	if d, ok := parseEnvDuration("HYPER_MAX_TTL"); ok && d > 0 {
		cfg.MaxTTL = d
	}
	if d, ok := parseEnvDuration("HYPER_KEEPALIVE_INTERVAL"); ok && d > 0 {
		cfg.KeepaliveInterval = d
	}

	storageMode := "memory"
	if storageDir := strings.TrimSpace(os.Getenv("HYPER_STORAGE_DIR")); storageDir != "" {
		diskStore, err := hyper.NewDiskChunkStore(storageDir)
		if err != nil {
			logger.Error("failed to initialize disk chunk store", "error", err)
			os.Exit(1)
		}
		cfg.Store = diskStore
		storageMode = "disk"
	}

	sweepInterval := time.Minute
	if d, ok := parseEnvDuration("HYPER_SWEEP_INTERVAL"); ok && d > 0 {
		sweepInterval = d
	}

	srv := hyper.New(cfg)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	stopSweep := make(chan struct{})
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				srv.Sweep()
			case <-stopSweep:
				return
			}
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		logger.Info("hyper-relay shutting down")
		close(stopSweep)
		<-sweepDone
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		_ = srv.Close()
	}()

	authSummary := authorizer.Summary()
	logger.Info(
		"hyper-relay listening",
		"addr", addr,
		"storage_mode", storageMode,
		"has_origin", cfg.Origin != "",
		"has_access_key", authSummary.HasAccessKey,
		"allowed_pubkeys", authSummary.AllowedPubKeyCount,
	)

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("hyper-relay exited with error", "error", err)
		_ = srv.Close()
		os.Exit(1)
	}
	<-shutdownDone
	logger.Info("hyper-relay stopped")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func parseEnvInt64(keys ...string) (int64, bool) {
	for _, k := range keys {
		if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
			if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func parseEnvInt(keys ...string) (int, bool) {
	for _, k := range keys {
		if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func parseEnvDuration(keys ...string) (time.Duration, bool) {
	for _, k := range keys {
		if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
			if d, err := time.ParseDuration(raw); err == nil {
				return d, true
			}
		}
	}
	return 0, false
}

func runHealthcheck(addr string) int {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		port = "8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
