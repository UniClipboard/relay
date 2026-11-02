// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const tunnelHeader = "X-UC-Relay-Tunnel"

type tunnel struct {
	endpoint string
	admitted bool
	limiter  *rate.Limiter
	cancel   context.CancelFunc
	body     io.Closer
}

type gateway struct {
	cfg         config
	digest      [32]byte
	client      *http.Client
	proxy       *httputil.ReverseProxy
	mu          sync.Mutex
	tunnels     map[string]*tunnel
	endpoints   map[string]int
	policy      *policy
	keys        map[string][]byte
	lastPolicy  time.Time
	etag        string
	accepted    uint64
	denied      uint64
	windowStart time.Time
	pending     []telemetry
	syncMu      sync.Mutex
	telemetryMu sync.Mutex
}

func newGateway(cfg config) (*gateway, error) {
	backend, err := parseURL(cfg.relayURL)
	if err != nil {
		return nil, err
	}
	g := &gateway{cfg: cfg, tunnels: map[string]*tunnel{}, endpoints: map[string]int{}, keys: map[string][]byte{}, windowStart: time.Now().UTC()}
	switch cfg.mode {
	case "static":
		if cfg.nodeID != "" || cfg.managementFile != "" {
			return nil, errors.New("static mode cannot use Cloud node credentials")
		}
		if cfg.allowLocal {
			host, _, e := net.SplitHostPort(cfg.bind)
			if e != nil || !net.ParseIP(host).IsLoopback() {
				return nil, errors.New("unauthenticated mode requires a loopback gateway bind address")
			}
			os.Unsetenv("UC_RELAY_TOKEN")
		} else {
			g.digest, err = loadStatic(cfg.tokenFile)
			if err != nil {
				return nil, err
			}
		}
	case "cloud":
		if cfg.allowLocal {
			return nil, errors.New("Cloud mode cannot allow unauthenticated clients")
		}
		if cfg.tokenFile != "" || osTokenConfigured() {
			return nil, errors.New("Cloud mode cannot use a static token")
		}
		if cfg.nodeID == "" || cfg.managementFile == "" {
			return nil, errors.New("Cloud mode requires a node ID and management credential file")
		}
		cloudOrigin, e := parseURL(cfg.cloudURL)
		if e != nil {
			return nil, e
		}
		if cloudOrigin.Scheme != "https" && cloudOrigin.Hostname() != "localhost" && !net.ParseIP(cloudOrigin.Hostname()).IsLoopback() {
			return nil, errors.New("Cloud URL requires HTTPS outside loopback")
		}
		cfg.cloudURL = cloudOrigin.String()
		g.cfg = cfg
		secret, e := readSecret(cfg.managementFile)
		clear(secret)
		if e != nil {
			return nil, e
		}
	default:
		return nil, errors.New("mode must be static or cloud")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 10 * time.Second
	g.client = &http.Client{Timeout: 10 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are disabled") }}
	g.proxy = &httputil.ReverseProxy{
		Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(backend); r.Out.Host = backend.Host },
		Transport: transport,
		ErrorLog:  log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "relay unavailable", http.StatusBadGateway)
		},
		ModifyResponse: func(r *http.Response) error {
			if r.StatusCode != http.StatusSwitchingProtocols {
				return nil
			}
			body, ok := r.Body.(io.ReadWriteCloser)
			if !ok {
				return errors.New("upgraded relay is not writable")
			}
			id := r.Request.Header.Get(tunnelHeader)
			g.mu.Lock()
			s := g.tunnels[id]
			if s != nil {
				s.body = body
			}
			g.mu.Unlock()
			if s == nil {
				return errors.New("tunnel no longer exists")
			}
			r.Body = &limitedTunnel{ReadWriteCloser: body, g: g, session: s, ctx: r.Request.Context()}
			return nil
		},
	}
	return g, nil
}

func (g *gateway) publicHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			g.mu.Lock()
			ready := g.cfg.mode == "static" || (g.policy != nil && time.Since(g.lastPolicy) <= 5*time.Minute)
			g.mu.Unlock()
			if !ready {
				http.Error(w, "policy unavailable", 503)
				return
			}
			w.WriteHeader(200)
			return
		}
		if r.URL.Path != "/relay" && r.URL.Path != "/" && r.URL.Path != "/generate_204" {
			http.NotFound(w, r)
			return
		}
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		id := hex.EncodeToString(random[:])
		ctx, cancel := context.WithCancel(r.Context())
		s := &tunnel{cancel: cancel}
		g.mu.Lock()
		g.tunnels[id] = s
		g.mu.Unlock()
		defer func() {
			cancel()
			g.mu.Lock()
			delete(g.tunnels, id)
			if s.admitted {
				g.endpoints[s.endpoint]--
				if g.endpoints[s.endpoint] == 0 {
					delete(g.endpoints, s.endpoint)
				}
			}
			g.mu.Unlock()
		}()
		// Always replace untrusted tunnel correlation headers.
		r.Header.Set(tunnelHeader, id)
		g.proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}

type admission struct {
	TunnelID   string `json:"tunnel_id"`
	EndpointID string `json:"endpoint_id"`
	Token      string `json:"token"`
}

func (g *gateway) privateHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/admit", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var a admission
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 24576))
		if decoder.Decode(&a) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		s := g.tunnels[a.TunnelID]
		allowed := s != nil && !s.admitted && canonicalEndpoint(a.EndpointID)
		receiveRate := int64(0)
		if allowed {
			if g.cfg.mode == "static" {
				b := []byte(a.Token)
				digest := sha256.Sum256(b)
				allowed = g.cfg.allowLocal || (validStatic(b) && subtle.ConstantTimeCompare(g.digest[:], digest[:]) == 1)
				clear(b)
			} else {
				p := g.policy
				allowed = p != nil && time.Since(g.lastPolicy) <= 5*time.Minute && p.Admit
				if allowed {
					allowed = !p.blocked[a.EndpointID] && g.endpoints[a.EndpointID] < p.MaxConnections && g.verifyJWT(a.Token, a.EndpointID, p.RelayID)
					receiveRate = p.ReceiveRate
				}
			}
		}
		a.Token = ""
		if !allowed {
			g.denied++
			w.WriteHeader(http.StatusForbidden)
			return
		}
		s.endpoint = a.EndpointID
		s.admitted = true
		if receiveRate > 0 {
			s.limiter = rate.NewLimiter(rate.Limit(receiveRate), 32768)
		}
		g.endpoints[s.endpoint]++
		g.accepted++
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	return mux
}

func canonicalEndpoint(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type limitedTunnel struct {
	io.ReadWriteCloser
	g       *gateway
	session *tunnel
	ctx     context.Context
}

func (t *limitedTunnel) Write(p []byte) (int, error) {
	t.g.mu.Lock()
	limiter := t.session.limiter
	t.g.mu.Unlock()
	written := 0
	for len(p) > 0 {
		n := min(len(p), 32768)
		if limiter != nil {
			if err := limiter.WaitN(t.ctx, n); err != nil {
				return written, err
			}
		}
		count, err := t.ReadWriteCloser.Write(p[:n])
		written += count
		if err != nil {
			return written, err
		}
		if count != n {
			return written, io.ErrShortWrite
		}
		p = p[n:]
	}
	return written, nil
}
func (g *gateway) close() {
	g.mu.Lock()
	for _, s := range g.tunnels {
		s.cancel()
	}
	bodies := make([]io.Closer, 0, len(g.tunnels))
	for _, s := range g.tunnels {
		if s.body != nil {
			bodies = append(bodies, s.body)
		}
	}
	g.mu.Unlock()
	for _, body := range bodies {
		body.Close()
	}
	g.client.CloseIdleConnections()
}
