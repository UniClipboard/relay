// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func osTokenConfigured() bool { return os.Getenv("UC_RELAY_TOKEN") != "" }
func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func logCloudFailure() {
	log.Print("Cloud synchronization failed; policy freshness rules remain in effect")
}
func main() {
	health := flag.Bool("healthcheck", false, "check the local public listener")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("positional arguments are not supported")
	}
	publicAddr := env("UC_GATEWAY_BIND", ":3340")
	if *health {
		client := http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get("http://127.0.0.1:" + env("UC_GATEWAY_HEALTH_PORT", "3340") + "/healthz")
		if err != nil {
			os.Exit(1)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	allowLocal, err := strconv.ParseBool(env("UC_RELAY_ALLOW_UNAUTHENTICATED_LOCAL", "false"))
	if err != nil {
		log.Fatal("UC_RELAY_ALLOW_UNAUTHENTICATED_LOCAL must be a boolean")
	}
	cfg := config{bind: publicAddr, allowLocal: allowLocal, mode: env("UC_GATEWAY_MODE", "static"), relayURL: env("UC_RELAY_UPSTREAM", "http://relay:3340"), cloudURL: env("UC_CLOUD_URL", "https://cloud.uniclipboard.app"), nodeID: os.Getenv("UC_RELAY_NODE_ID"), managementFile: os.Getenv("UC_RELAY_MANAGEMENT_FILE"), tokenFile: os.Getenv("UC_RELAY_TOKEN_FILE")}
	g, err := newGateway(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer g.close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	public := &http.Server{Addr: publicAddr, Handler: g.publicHandler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	private := &http.Server{Addr: env("UC_GATEWAY_INTERNAL_BIND", ":3341"), Handler: g.privateHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	errors := make(chan error, 2)
	go func() { errors <- private.ListenAndServe() }()
	go func() { errors <- public.ListenAndServe() }()
	go g.runCloud(ctx)
	log.Print("starting gateway listeners")
	listenerFailed := false
	select {
	case <-ctx.Done():
	case <-errors:
		listenerFailed = true
		log.Print("gateway listener stopped")
		cancel()
	}
	g.close()
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	public.Shutdown(shutdown)
	private.Shutdown(shutdown)
	if listenerFailed {
		log.Fatal("gateway could not serve its listeners")
	}
}
