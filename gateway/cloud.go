// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type policy struct {
	RelayID        string   `json:"relay_id"`
	Revision       int64    `json:"revision"`
	Admit          bool     `json:"admit_new_connections"`
	MaxConnections int      `json:"max_connections_per_endpoint"`
	ReceiveRate    int64    `json:"client_rx_bytes_per_second"`
	Blocked        []string `json:"blocked_endpoint_ids"`
	GeneratedAt    string   `json:"generated_at"`
	blocked        map[string]bool
}

func (g *gateway) request(ctx context.Context, method, path string, body []byte, etag string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, g.cfg.cloudURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot create Cloud request")
	}
	if path != "/api/relay/v1/keys" {
		secret, e := readSecret(g.cfg.managementFile)
		if e != nil {
			return nil, e
		}
		req.Header.Set("Authorization", "Bearer "+string(secret))
		clear(secret)
		req.Header.Set("X-Relay-Node-ID", g.cfg.nodeID)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.client.Do(req)
	req.Header.Del("Authorization")
	if err != nil {
		return nil, errors.New("Cloud request failed")
	}
	return resp, nil
}

func (g *gateway) syncCloud(ctx context.Context) error {
	g.syncMu.Lock()
	defer g.syncMu.Unlock()
	resp, err := g.request(ctx, "GET", "/api/relay/v1/keys", nil, "")
	if err != nil {
		return err
	}
	var jwks struct {
		Keys []struct{ Kty, Crv, Alg, Use, Kid, X string }
	}
	err = decodeCloud(resp.Body, &jwks)
	resp.Body.Close()
	if resp.StatusCode != 200 || err != nil {
		return errors.New("invalid Cloud key response")
	}
	keys := map[string][]byte{}
	for _, k := range jwks.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" || (k.Alg != "" && k.Alg != "EdDSA") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		b, e := base64.RawURLEncoding.DecodeString(k.X)
		if e != nil || len(b) != ed25519.PublicKeySize {
			return errors.New("invalid verification key")
		}
		if _, exists := keys[k.Kid]; exists {
			return errors.New("duplicate verification key ID")
		}
		keys[k.Kid] = b
	}
	if len(keys) == 0 {
		return errors.New("no verification keys available")
	}
	g.mu.Lock()
	etag := g.etag
	g.mu.Unlock()
	resp, err = g.request(ctx, "GET", "/api/relay/v1/gateway/config", nil, etag)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 304 {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.policy == nil {
			return errors.New("unchanged response without a policy")
		}
		g.lastPolicy = time.Now()
		g.keys = keys
		return nil
	}
	if resp.StatusCode != 200 {
		return errors.New("Cloud configuration request failed")
	}
	var fields map[string]json.RawMessage
	if decodeCloud(resp.Body, &fields) != nil {
		return errors.New("invalid Cloud policy")
	}
	for _, name := range []string{"relay_id", "revision", "admit_new_connections", "max_connections_per_endpoint", "client_rx_bytes_per_second", "blocked_endpoint_ids", "generated_at"} {
		raw, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("Cloud policy is missing a required field")
		}
	}
	encoded, _ := json.Marshal(fields)
	var p policy
	if json.Unmarshal(encoded, &p) != nil || p.RelayID == "" || p.Revision < 0 || p.MaxConnections < 1 || p.ReceiveRate < 0 || p.ReceiveRate > 1<<40 || resp.Header.Get("ETag") == "" {
		return errors.New("invalid Cloud policy")
	}
	if _, err := time.Parse(time.RFC3339Nano, p.GeneratedAt); err != nil {
		return errors.New("invalid policy generation time")
	}
	p.blocked = map[string]bool{}
	for _, id := range p.Blocked {
		if !canonicalEndpoint(id) {
			return errors.New("invalid blocked endpoint ID")
		}
		p.blocked[id] = true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.policy != nil && (p.RelayID != g.policy.RelayID || p.Revision < g.policy.Revision) {
		return errors.New("Cloud policy identity or revision regressed")
	}
	if g.policy != nil && p.Revision == g.policy.Revision {
		previous, current := *g.policy, p
		previous.GeneratedAt = ""
		current.GeneratedAt = ""
		if !reflect.DeepEqual(previous, current) {
			return errors.New("Cloud policy changed without a new revision")
		}
	}
	g.policy = &p
	g.keys = keys
	g.lastPolicy = time.Now()
	g.etag = resp.Header.Get("ETag")
	return nil
}

type credentialClaims struct {
	jwt.RegisteredClaims
	RelayID string `json:"relay_id"`
}

func (g *gateway) verifyJWT(raw, endpoint, relay string) bool {
	if len(raw) > 16384 {
		return false
	}
	claims := credentialClaims{}
	_, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("missing verification key ID")
		}
		key := g.keys[kid]
		if len(key) != ed25519.PublicKeySize {
			return nil, errors.New("unknown verification key ID")
		}
		return ed25519.PublicKey(key), nil
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer("https://cloud.uniclipboard.app"), jwt.WithAudience("uc-relay"), jwt.WithSubject(endpoint), jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	return err == nil && claims.NotBefore != nil && claims.ExpiresAt != nil && claims.ExpiresAt.After(claims.NotBefore.Time) && claims.RelayID == relay
}

type telemetry struct {
	RelayID     string    `json:"relay_id"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Revision    int64     `json:"revision"`
	Active      int       `json:"active_connections"`
	Accepted    uint64    `json:"accepted_connections"`
	Denied      uint64    `json:"denied_connections"`
	Ingress     *uint64   `json:"ingress_bytes"`
	Egress      *uint64   `json:"egress_bytes"`
}

func (g *gateway) flushTelemetry(ctx context.Context, now time.Time) {
	g.telemetryMu.Lock()
	defer g.telemetryMu.Unlock()
	g.mu.Lock()
	if g.policy != nil {
		active := 0
		for _, n := range g.endpoints {
			active += n
		}
		g.pending = append(g.pending, telemetry{RelayID: g.policy.RelayID, Revision: g.policy.Revision, WindowStart: g.windowStart, WindowEnd: now, Active: active, Accepted: g.accepted, Denied: g.denied})
	}
	g.windowStart = now
	g.accepted = 0
	g.denied = 0
	g.mu.Unlock()
	// Keep at most 24 hours of unsent, non-secret aggregate windows.
	if len(g.pending) > 2880 {
		log.Print("telemetry queue exceeded 24 hours; oldest aggregate windows discarded")
		g.pending = g.pending[len(g.pending)-2880:]
	}
	for len(g.pending) > 0 {
		body, err := json.Marshal(g.pending[0])
		if err != nil {
			return
		}
		resp, err := g.request(ctx, "POST", "/api/relay/v1/gateway/telemetry", body, "")
		if err != nil {
			log.Print("telemetry delivery failed; aggregate window retained")
			return
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Print("telemetry delivery failed; aggregate window retained")
			return
		}
		g.pending = g.pending[1:]
	}
}

func (g *gateway) runCloud(ctx context.Context) {
	if g.cfg.mode != "cloud" {
		return
	}
	// Keep configuration polling independent of a telemetry retry backlog.
	go func() {
		g.mu.Lock()
		g.windowStart = time.Now().UTC()
		g.mu.Unlock()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				windowContext, cancel := context.WithTimeout(ctx, 20*time.Second)
				g.mu.Lock()
				end := g.windowStart.Add(30 * time.Second)
				g.mu.Unlock()
				g.flushTelemetry(windowContext, end)
				cancel()
			}
		}
	}()
	poll := time.NewTicker(30 * time.Second)
	defer poll.Stop()
	if g.syncCloud(ctx) != nil {
		logCloudFailure()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			if g.syncCloud(ctx) != nil {
				logCloudFailure()
			}
		}
	}
}

func decodeCloud(body io.Reader, value any) error {
	b, err := io.ReadAll(io.LimitReader(body, (1<<20)+1))
	if err != nil || len(b) > 1<<20 {
		return errors.New("Cloud response exceeded its size limit")
	}
	return json.Unmarshal(b, value)
}
