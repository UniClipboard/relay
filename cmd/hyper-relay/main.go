// SPDX-License-Identifier: AGPL-3.0-only

// Command hyper-relay is the standalone, zero-knowledge Hyper Relay control
// plane microservice. Clients upload and download encrypted chunks directly to
// S3-compatible object storage (Tencent COS, Cloudflare R2, AWS S3, Aliyun OSS,
// MinIO) using short-lived SigV4 presigned URLs issued by this service.
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
	"github.com/uniclipboard/relay/internal/s3store"
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

	objectStore, err := s3store.LoadFromEnv(os.Getenv)
	if err != nil {
		logger.Error("failed to initialize S3 object storage", "error", err)
		os.Exit(1)
	}

	cfg := hyper.Config{
		Origin:      firstNonEmpty(os.Getenv("HYPER_ORIGIN"), os.Getenv("UNIC_RELAY_ORIGIN")),
		Authorizer:  authorizer,
		ObjectStore: objectStore,
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
	if d, ok := parseEnvDuration("S3_PRESIGN_TTL"); ok && d > 0 {
		cfg.PresignTTL = d
	}
	if d, ok := parseEnvDuration("HYPER_KEEPALIVE_INTERVAL"); ok && d > 0 {
		cfg.KeepaliveInterval = d
	}

	sweepInterval := time.Minute
	if d, ok := parseEnvDuration("HYPER_SWEEP_INTERVAL"); ok && d > 0 {
		sweepInterval = d
	}

	srv, err := hyper.New(cfg)
	if err != nil {
		logger.Error("failed to initialize hyper-relay server", "error", err)
		os.Exit(1)
	}
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
				sweepCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				srv.Sweep(sweepCtx)
				cancel()
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
		"storage_mode", "s3-direct",
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
