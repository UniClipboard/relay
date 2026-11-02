// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const staticToken = "0123456789abcdef0123456789abcdef"

func secretFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	return address
}

func stack(t *testing.T, cfg config) (*gateway, string, string) {
	t.Helper()
	backend := freeAddress(t)
	cfg.relayURL = "http://" + backend
	g, err := newGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	private := httptest.NewServer(g.privateHandler())
	public := httptest.NewServer(g.publicHandler())
	cmd := exec.Command("../target/debug/uniclipboard-relay", "--bind", backend, "--gateway-url", private.URL)
	cmd.Env = append(os.Environ(), "RUST_LOG=off")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		public.CloseClientConnections()
		private.CloseClientConnections()
		cmd.Process.Kill()
		cmd.Wait()
		public.Close()
		private.Close()
		g.close()
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(cfg.relayURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return g, public.URL, cfg.relayURL
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("relay did not become healthy")
	return nil, "", ""
}

type probe struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Scanner
}

func connectProbe(t *testing.T, url, token string, seed int, want string) *probe {
	t.Helper()
	cmd := exec.Command("../target/debug/examples/relay_probe", url, secretFile(t, token), fmt.Sprint(seed))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); cmd.Process.Kill(); cmd.Wait() })
	result := make(chan string, 1)
	s := bufio.NewScanner(stdout)
	go func() {
		if s.Scan() {
			result <- s.Text()
		} else {
			result <- "no-result"
		}
	}()
	select {
	case got := <-result:
		if got != want {
			t.Fatalf("client result %q, want %q", got, want)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("client timed out")
	}
	return &probe{cmd, input, s}
}
func (p *probe) close() { p.input.Close(); p.cmd.Wait() }
func (p *probe) ping(t *testing.T) {
	t.Helper()
	if _, err := io.WriteString(p.input, "ping\n"); err != nil {
		t.Fatal(err)
	}
	result := make(chan string, 1)
	go func() {
		if p.output.Scan() {
			result <- p.output.Text()
		} else {
			result <- "closed"
		}
	}()
	select {
	case got := <-result:
		if got != "pong" {
			t.Fatalf("existing connection did not survive policy update: %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("existing connection ping timed out")
	}
}

func endpoint(t *testing.T, seed int) string {
	t.Helper()
	out, err := exec.Command("../target/debug/examples/relay_probe", "id", fmt.Sprint(seed)).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestStaticRelayEndToEnd(t *testing.T) {
	g, url, backend := stack(t, config{mode: "static", tokenFile: secretFile(t, staticToken)})
	connectProbe(t, url, "", 7, "denied")
	connectProbe(t, url, strings.Repeat("x", 32), 7, "denied")
	connectProbe(t, url, strings.Repeat("x", 513), 7, "denied")
	connectProbe(t, backend, staticToken, 7, "denied")
	p := connectProbe(t, url, staticToken, 7, "connected")
	p.close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		active := len(g.endpoints)
		g.mu.Unlock()
		if active == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// A real upstream client sends and receives a datagram through the public gateway.
	cmd := exec.Command("../target/debug/examples/relay_probe", url, secretFile(t, staticToken), "forward")
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "forwarded" {
		t.Fatalf("forwarding failed: %v %s", err, out)
	}
	resp, err := http.Post(url+"/internal/admit", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("private RPC is publicly reachable")
	}
}

type cloudFixture struct {
	mu               sync.Mutex
	policy           policy
	pub              ed25519.PublicKey
	key              ed25519.PrivateKey
	kid              string
	outage           bool
	telemetryFailure bool
	policyBody       []byte
	windows          map[string]string
	attempts         int
}

func cloud(t *testing.T) (*cloudFixture, *httptest.Server) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &cloudFixture{pub: pub, key: key, kid: "key-1", policy: policy{RelayID: "node-1", Revision: 1, Admit: true, MaxConnections: 1, ReceiveRate: 1048576, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}, windows: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.outage {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/api/relay/v1/keys" {
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": c.kid, "x": base64.RawURLEncoding.EncodeToString(c.pub)}}})
			return
		}
		if r.Header.Get("Authorization") != "Bearer management-secret" || r.Header.Get("X-Relay-Node-ID") != "node-1" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/relay/v1/gateway/config":
			if c.policyBody != nil {
				w.Header().Set("ETag", `"invalid"`)
				w.Write(c.policyBody)
				return
			}
			etag := fmt.Sprintf(`"%d"`, c.policy.Revision)
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(304)
				return
			}
			p := c.policy
			if p.Blocked == nil {
				p.Blocked = []string{}
			}
			json.NewEncoder(w).Encode(p)
		case "/api/relay/v1/gateway/telemetry":
			var v map[string]any
			if json.NewDecoder(r.Body).Decode(&v) != nil {
				w.WriteHeader(400)
				return
			}
			if v["revision"] == nil || v["active_connections"] == nil || v["accepted_connections"] == nil || v["denied_connections"] == nil {
				w.WriteHeader(400)
				return
			}
			b, _ := json.Marshal(v)
			id := fmt.Sprint(v["window_start"], v["window_end"])
			if previous, ok := c.windows[id]; ok && previous != string(b) {
				t.Error("telemetry retry changed window")
			}
			c.windows[id] = string(b)
			c.attempts++
			if c.telemetryFailure {
				w.WriteHeader(503)
				return
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return c, srv
}
func (c *cloudFixture) token(t *testing.T, subject string, modify func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{"iss": "https://cloud.uniclipboard.app", "aud": "uc-relay", "sub": subject, "relay_id": "node-1", "nbf": now.Add(-time.Second).Unix(), "exp": now.Add(10 * time.Minute).Unix()}
	if modify != nil {
		modify(claims)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = c.kid
	s, err := tok.SignedString(c.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCloudRelayEndToEnd(t *testing.T) {
	c, srv := cloud(t)
	g, url, _ := stack(t, config{mode: "cloud", nodeID: "node-1", managementFile: secretFile(t, "management-secret"), cloudURL: srv.URL})
	id := endpoint(t, 7)
	valid := c.token(t, id, nil)
	connectProbe(t, url, valid, 7, "denied") // Startup remains closed before the first successful policy load.
	if err := g.syncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{"wrong endpoint", func(m jwt.MapClaims) { m["sub"] = endpoint(t, 8) }},
		{"wrong relay", func(m jwt.MapClaims) { m["relay_id"] = "other" }},
		{"wrong issuer", func(m jwt.MapClaims) { m["iss"] = "https://other.invalid" }},
		{"wrong audience", func(m jwt.MapClaims) { m["aud"] = "other" }},
		{"expired", func(m jwt.MapClaims) { m["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"future nbf", func(m jwt.MapClaims) { m["nbf"] = time.Now().Add(time.Minute).Unix() }},
		{"missing exp", func(m jwt.MapClaims) { delete(m, "exp") }},
		{"missing nbf", func(m jwt.MapClaims) { delete(m, "nbf") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { connectProbe(t, url, c.token(t, id, tc.mutate), 7, "denied") })
	}
	connectProbe(t, url, valid[:len(valid)-12]+strings.Repeat("a", 12), 7, "denied")
	connectProbe(t, url, "not-a-jwt", 7, "denied")
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": id})
	tok.Header["kid"] = "key-1"
	hs, _ := tok.SignedString([]byte(staticToken))
	connectProbe(t, url, hs, 7, "denied")
	// A signed credential longer than the old 512-character limit must connect.
	long := c.token(t, id, func(m jwt.MapClaims) { m["padding"] = strings.Repeat("x", 600) })
	p := connectProbe(t, url, long, 7, "connected")
	connectProbe(t, url, valid, 7, "denied")
	p.close()
	time.Sleep(50 * time.Millisecond)
	p = connectProbe(t, url, valid, 7, "connected")
	c.mu.Lock()
	c.policy.Revision++
	c.policy.Blocked = []string{id}
	c.mu.Unlock()
	if err := g.syncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	connectProbe(t, url, valid, 7, "denied")
	// Existing connections remain active after a policy change.
	g.mu.Lock()
	active := g.endpoints[id]
	g.mu.Unlock()
	if active != 1 {
		t.Fatalf("existing connection lost: %d", active)
	}
	p.ping(t)
	p.close()
	c.mu.Lock()
	c.policy.Revision++
	c.policy.Blocked = nil
	c.policy.Admit = false
	c.mu.Unlock()
	if err := g.syncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	connectProbe(t, url, valid, 7, "denied")
	c.mu.Lock()
	c.policy.Revision++
	c.policy.Admit = true
	c.mu.Unlock()
	if err := g.syncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.outage = true
	c.mu.Unlock()
	if g.syncCloud(context.Background()) == nil {
		t.Fatal("expected Cloud outage")
	}
	p = connectProbe(t, url, valid, 7, "connected")
	p.close()
	// Advance only policy freshness. JWT verification still uses the real clock.
	g.mu.Lock()
	g.lastPolicy = time.Now().Add(-5*time.Minute - time.Second)
	g.mu.Unlock()
	connectProbe(t, url, valid, 7, "denied")
	c.mu.Lock()
	c.outage = false
	c.mu.Unlock()
	if err := g.syncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	p = connectProbe(t, url, valid, 7, "connected")
	p.close()
	// Rotation replaces the public key set; no token state is retained.
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c.mu.Lock()
	c.pub = pub
	c.key = key
	c.kid = "key-2"
	c.mu.Unlock()
	if err := g.syncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotated := c.token(t, id, nil)
	p = connectProbe(t, url, rotated, 7, "connected")
	p.close()
	connectProbe(t, url, valid, 7, "denied")
}

func TestTelemetryIdleAndRetryEndToEnd(t *testing.T) {
	c, srv := cloud(t)
	g, url, _ := stack(t, config{mode: "cloud", nodeID: "node-1", managementFile: secretFile(t, "management-secret"), cloudURL: srv.URL})
	if err := g.syncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	connectProbe(t, url, "invalid", 7, "denied")
	c.mu.Lock()
	c.telemetryFailure = true
	c.mu.Unlock()
	now := time.Now().UTC()
	g.flushTelemetry(context.Background(), now)
	c.mu.Lock()
	attempts := c.attempts
	c.telemetryFailure = false
	c.mu.Unlock()
	if attempts != 1 {
		t.Fatalf("telemetry attempts: %d", attempts)
	}
	g.flushTelemetry(context.Background(), now.Add(30*time.Second))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.attempts != 3 || len(c.windows) != 2 {
		t.Fatalf("retry or idle window missing: attempts=%d windows=%d", c.attempts, len(c.windows))
	}
}

func TestBrowserTokenAndFilePermissionsEndToEnd(t *testing.T) {
	_, url, _ := stack(t, config{mode: "static", tokenFile: secretFile(t, staticToken)})
	cmd := exec.Command("../target/debug/examples/relay_probe", url, secretFile(t, staticToken), "7")
	cmd.Env = append(os.Environ(), "UC_PROBE_QUERY_TOKEN=1")
	// EOF closes the accepted connection after the result has been printed.
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "connected" {
		t.Fatalf("browser token failed: %v %s", err, out)
	}
	path := secretFile(t, staticToken)
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	// Exercise the actual executable startup, including the credential loader.
	build := exec.Command("go", "build", "-o", filepath.Join(t.TempDir(), "gateway"), ".")
	if err = build.Run(); err != nil {
		t.Fatal(err)
	}
	binary := build.Args[3]
	command := exec.Command(binary)
	command.Env = append(os.Environ(), "UC_GATEWAY_MODE=static", "UC_RELAY_UPSTREAM=http://127.0.0.1:1", "UC_RELAY_TOKEN_FILE="+path)
	out, err = command.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "readable only by its owner") {
		t.Fatalf("insecure file was not rejected: %v %s", err, out)
	}
	if strings.Contains(string(out), staticToken) {
		t.Fatal("startup error leaked a credential")
	}
}

func TestReceiveRateEndToEnd(t *testing.T) {
	c, srv := cloud(t)
	c.policy.ReceiveRate = 32768
	g, url, _ := stack(t, config{mode: "cloud", nodeID: "node-1", managementFile: secretFile(t, "management-secret"), cloudURL: srv.URL})
	if err := g.syncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	senderToken := c.token(t, endpoint(t, 7), nil)
	receiverToken := c.token(t, endpoint(t, 8), nil)
	cmd := exec.Command("../target/debug/examples/relay_probe", url, secretFile(t, senderToken), "forward")
	cmd.Env = append(os.Environ(), "UC_PROBE_PEER_TOKEN_FILE="+secretFile(t, receiverToken), "UC_PROBE_PACKETS=6", "UC_PROBE_PACKET_SIZE=16384")
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)
	if err != nil || strings.TrimSpace(string(out)) != "forwarded" {
		t.Fatalf("limited forwarding failed: %v %s", err, out)
	}
	if elapsed < 1500*time.Millisecond {
		t.Fatalf("96 KiB exceeded a 32 KiB/s limit with a 32 KiB burst: %v", elapsed)
	}
	t.Logf("96 KiB forwarded with a 32 KiB/s receive limit in %v", elapsed)
}

func TestScheduledCloudPollingAndIdleHeartbeatEndToEnd(t *testing.T) {
	c, srv := cloud(t)
	g, _, _ := stack(t, config{mode: "cloud", nodeID: "node-1", managementFile: secretFile(t, "management-secret"), cloudURL: srv.URL})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.runCloud(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		g.mu.Lock()
		ready := g.policy != nil
		g.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial synchronization did not complete")
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.mu.Lock()
	c.policy.Revision = 2
	c.mu.Unlock()
	deadline = time.Now().Add(36 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		revision := g.policy.Revision
		g.mu.Unlock()
		c.mu.Lock()
		count := len(c.windows)
		c.mu.Unlock()
		if revision == 2 && count > 0 {
			c.mu.Lock()
			defer c.mu.Unlock()
			for _, raw := range c.windows {
				var v struct {
					WindowStart time.Time `json:"window_start"`
					WindowEnd   time.Time `json:"window_end"`
					Active      int       `json:"active_connections"`
				}
				if json.Unmarshal([]byte(raw), &v) != nil || v.WindowEnd.Sub(v.WindowStart) != 30*time.Second || v.Active != 0 {
					t.Fatal("invalid idle telemetry window")
				}
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("30-second policy poll or idle heartbeat did not occur")
}

func TestGatewayAndRelayExecutablesEndToEnd(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "gateway")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("gateway build: %v %s", err, out)
	}
	for _, mode := range []string{"static", "cloud"} {
		t.Run(mode, func(t *testing.T) {
			backend, public, private := freeAddress(t), freeAddress(t), freeAddress(t)
			c, srv := cloud(t)
			gatewayCommand := exec.Command(binary)
			gatewayCommand.Env = append(os.Environ(), "UC_GATEWAY_MODE="+mode, "UC_GATEWAY_BIND="+public, "UC_GATEWAY_INTERNAL_BIND="+private, "UC_RELAY_UPSTREAM=http://"+backend, "UC_RELAY_TOKEN_FILE=", "UC_RELAY_TOKEN=", "UC_RELAY_NODE_ID=", "UC_RELAY_MANAGEMENT_FILE=")
			credential := staticToken
			if mode == "static" {
				gatewayCommand.Env = append(gatewayCommand.Env, "UC_RELAY_TOKEN="+staticToken)
			} else {
				gatewayCommand.Env = append(gatewayCommand.Env, "UC_CLOUD_URL="+srv.URL, "UC_RELAY_NODE_ID=node-1", "UC_RELAY_MANAGEMENT_FILE="+secretFile(t, "management-secret"))
				credential = c.token(t, endpoint(t, 7), nil)
			}
			relayCommand := exec.Command("../target/debug/uniclipboard-relay", "--bind", backend, "--gateway-url", "http://"+private)
			relayCommand.Env = append(os.Environ(), "RUST_LOG=trace")
			relayLog := filepath.Join(t.TempDir(), "relay.log")
			logFile, err := os.Create(relayLog)
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			relayCommand.Stdout = logFile
			relayCommand.Stderr = logFile
			for _, cmd := range []*exec.Cmd{gatewayCommand, relayCommand} {
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
			}
			deadline := time.Now().Add(10 * time.Second)
			for _, address := range []string{backend, public} {
				ready := false
				for time.Now().Before(deadline) {
					resp, err := http.Get("http://" + address + "/healthz")
					if err == nil {
						resp.Body.Close()
						if resp.StatusCode == 200 {
							ready = true
							break
						}
					}
					time.Sleep(20 * time.Millisecond)
				}
				if !ready {
					t.Fatal("executable did not become healthy")
				}
			}
			connectProbe(t, "http://"+public, "incorrect", 7, "denied")
			p := connectProbe(t, "http://"+public, credential, 7, "connected")
			p.ping(t)
			p.close()
			queryClient := exec.Command("../target/debug/examples/relay_probe", "http://"+public, secretFile(t, credential), "7")
			queryClient.Env = append(os.Environ(), "UC_PROBE_QUERY_TOKEN=1")
			if out, err := queryClient.CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "connected" {
				t.Fatalf("process query client failed: %v %s", err, out)
			}
			relayCommand.Process.Kill()
			relayCommand.Wait()
			logs, err := os.ReadFile(relayLog)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(logs), credential) || strings.Contains(string(logs), "Bearer ") {
				t.Fatal("relay logs exposed a credential with RUST_LOG=trace")
			}
		})
	}
}

func TestInvalidPolicyDoesNotRefreshFreshnessEndToEnd(t *testing.T) {
	c, srv := cloud(t)
	g, url, _ := stack(t, config{mode: "cloud", nodeID: "node-1", managementFile: secretFile(t, "management-secret"), cloudURL: srv.URL})
	if err := g.syncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	valid := c.token(t, endpoint(t, 7), nil)
	c.mu.Lock()
	raw, _ := json.Marshal(c.policy)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	fields["revision"] = json.RawMessage(`2`)
	fields["blocked_endpoint_ids"] = json.RawMessage(`[]`)
	delete(fields, "client_rx_bytes_per_second")
	c.policyBody, _ = json.Marshal(fields)
	c.mu.Unlock()
	g.mu.Lock()
	before := g.lastPolicy
	g.mu.Unlock()
	if g.syncCloud(context.Background()) == nil {
		t.Fatal("incomplete policy was accepted")
	}
	g.mu.Lock()
	same := g.lastPolicy.Equal(before) && g.policy.Revision == 1
	g.mu.Unlock()
	if !same {
		t.Fatal("invalid policy refreshed freshness or advanced the applied revision")
	}
	p := connectProbe(t, url, valid, 7, "connected")
	p.ping(t)
	p.close()
	g.mu.Lock()
	g.lastPolicy = time.Now().Add(-6 * time.Minute)
	g.mu.Unlock()
	connectProbe(t, url, valid, 7, "denied")
	c.mu.Lock()
	c.policyBody = nil
	c.mu.Unlock()
	if err := g.syncCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	p = connectProbe(t, url, valid, 7, "connected")
	p.close()
}

func TestLocalUnauthenticatedRelayEndToEnd(t *testing.T) {
	_, url, _ := stack(t, config{mode: "static", allowLocal: true, bind: "127.0.0.1:3340"})
	p := connectProbe(t, url, "", 7, "connected")
	p.ping(t)
	p.close()
	binary := filepath.Join(t.TempDir(), "gateway")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("gateway build: %v %s", err, out)
	}
	command := exec.Command(binary)
	command.Env = append(os.Environ(), "UC_GATEWAY_MODE=static", "UC_RELAY_UPSTREAM=http://127.0.0.1:1", "UC_RELAY_TOKEN_FILE=", "UC_RELAY_TOKEN=", "UC_RELAY_ALLOW_UNAUTHENTICATED_LOCAL=true", "UC_GATEWAY_BIND=0.0.0.0:3340")
	out, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "loopback") {
		t.Fatalf("public unauthenticated mode was not rejected: %v %s", err, out)
	}
}
