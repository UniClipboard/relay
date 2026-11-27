// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultCloudVerifyCacheTTL is the positive verification cache TTL.
	DefaultCloudVerifyCacheTTL = 60 * time.Second
	// DefaultCloudVerifyNegativeCacheTTL is the negative verification cache TTL.
	DefaultCloudVerifyNegativeCacheTTL = 10 * time.Second
	// DefaultCloudVerifyTimeout bounds each outbound verification call to uc-cloud.
	DefaultCloudVerifyTimeout = 5 * time.Second
	// DefaultCloudVerifyMaxCacheEntries bounds in-memory key_hash cache size.
	DefaultCloudVerifyMaxCacheEntries = 4096

	maxCloudVerifyResponseBytes = 16 * 1024
)

// ErrInvalidCloudVerifyURL indicates a malformed CLOUD_VERIFY_URL configuration.
var ErrInvalidCloudVerifyURL = errors.New("auth: invalid CLOUD_VERIFY_URL")

// CloudConfig configures CloudAuthorizer for official uc-cloud per-user API key
// verification with optional StaticAuthorizer fallback and bounded key_hash caching.
type CloudConfig struct {
	VerifyURL        string
	VerifySecret     string
	CacheTTL         time.Duration
	NegativeCacheTTL time.Duration
	MaxCacheEntries  int
	RequestTimeout   time.Duration
	HTTPClient       *http.Client
	Static           *StaticAuthorizer
	Now              func() time.Time
}

type cloudCacheEntry struct {
	decision  Decision
	expiresAt time.Time
}

type cloudVerifyRequest struct {
	KeyHash string `json:"key_hash"`
}

type cloudVerifyResponse struct {
	Allowed          bool   `json:"allowed"`
	Subject          string `json:"subject,omitempty"`
	KeyID            string `json:"key_id,omitempty"`
	MaxTransferBytes int64  `json:"max_transfer_bytes,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

// CloudAuthorizer verifies X-Unic-Relay-Key hashes against uc-cloud while
// supporting optional static access-key fallback and Ed25519 pubkey allowlisting.
// Raw presented API keys are hashed with SHA-256 locally and are never logged,
// cached, or transmitted to the cloud verification endpoint.
type CloudAuthorizer struct {
	verifyURL        string
	verifySecret     string
	cacheTTL         time.Duration
	negativeCacheTTL time.Duration
	maxCacheEntries  int
	requestTimeout   time.Duration
	httpClient       *http.Client
	static           *StaticAuthorizer
	now              func() time.Time

	mu    sync.Mutex
	cache map[string]cloudCacheEntry
}

// NewCloud validates cfg and constructs a CloudAuthorizer.
// If VerifyURL is set without VerifySecret, construction succeeds and
// AuthorizeAccessKey fails closed with HTTP 503 (auth_unavailable).
func NewCloud(cfg CloudConfig) (*CloudAuthorizer, error) {
	verifyURL := strings.TrimSpace(cfg.VerifyURL)
	if verifyURL != "" {
		u, err := url.Parse(verifyURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("%w: must be an http or https URL", ErrInvalidCloudVerifyURL)
		}
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = DefaultCloudVerifyCacheTTL
	}
	negTTL := cfg.NegativeCacheTTL
	if negTTL <= 0 {
		negTTL = DefaultCloudVerifyNegativeCacheTTL
	}
	maxEntries := cfg.MaxCacheEntries
	if maxEntries <= 0 {
		maxEntries = DefaultCloudVerifyMaxCacheEntries
	}
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultCloudVerifyTimeout
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	return &CloudAuthorizer{
		verifyURL:        verifyURL,
		verifySecret:     strings.TrimSpace(cfg.VerifySecret),
		cacheTTL:         cacheTTL,
		negativeCacheTTL: negTTL,
		maxCacheEntries:  maxEntries,
		requestTimeout:   timeout,
		httpClient:       client,
		static:           cfg.Static,
		now:              nowFn,
		cache:            make(map[string]cloudCacheEntry),
	}, nil
}

// LoadFromEnv loads either a StaticAuthorizer (when CLOUD_VERIFY_URL is empty)
// or a CloudAuthorizer wrapping the static configuration (when CLOUD_VERIFY_URL is set).
func LoadFromEnv(getenv func(string) string) (Authorizer, ConfigSummary, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	staticAuth, err := LoadStaticFromEnv(getenv)
	if err != nil {
		return nil, ConfigSummary{}, err
	}

	verifyURL := strings.TrimSpace(getenv("CLOUD_VERIFY_URL"))
	if verifyURL == "" {
		return staticAuth, staticAuth.Summary(), nil
	}

	var verifySecret string
	if secretFile := strings.TrimSpace(getenv("CLOUD_VERIFY_SECRET_FILE")); secretFile != "" {
		b, err := readOwnerOnlySecretFile(secretFile)
		if err != nil {
			return nil, ConfigSummary{}, err
		}
		verifySecret = string(b)
		wipeBytes(b)
	} else {
		verifySecret = strings.TrimSpace(getenv("CLOUD_VERIFY_SECRET"))
	}

	cacheTTL := DefaultCloudVerifyCacheTTL
	if raw := strings.TrimSpace(getenv("CLOUD_VERIFY_CACHE_TTL_SEC")); raw != "" {
		if sec, err := strconv.Atoi(raw); err == nil && sec > 0 {
			cacheTTL = time.Duration(sec) * time.Second
		}
	}

	cloudAuth, err := NewCloud(CloudConfig{
		VerifyURL:    verifyURL,
		VerifySecret: verifySecret,
		CacheTTL:     cacheTTL,
		Static:       staticAuth,
	})
	if err != nil {
		return nil, ConfigSummary{}, err
	}
	return cloudAuth, cloudAuth.Summary(), nil
}

// Summary returns non-secret configuration metadata safe for structured logs.
func (c *CloudAuthorizer) Summary() ConfigSummary {
	if c == nil {
		return ConfigSummary{}
	}
	var sum ConfigSummary
	if c.static != nil {
		sum = c.static.Summary()
	}
	sum.HasCloudVerify = c.verifyURL != ""
	return sum
}

// AuthorizeDevicePubKey delegates to the underlying StaticAuthorizer allowlist if configured.
func (c *CloudAuthorizer) AuthorizeDevicePubKey(ctx context.Context, req Request) Decision {
	if c == nil || c.static == nil {
		return Decision{Allowed: true, StatusCode: http.StatusOK}
	}
	return c.static.AuthorizeDevicePubKey(ctx, req)
}

// AuthorizeAccessKey enforces static key fallback + uc-cloud SHA-256 key_hash verification.
func (c *CloudAuthorizer) AuthorizeAccessKey(ctx context.Context, req Request) Decision {
	if c == nil {
		return Decision{Allowed: true, StatusCode: http.StatusOK}
	}
	if c.verifyURL == "" {
		if c.static != nil {
			return c.static.AuthorizeAccessKey(ctx, req)
		}
		return Decision{Allowed: true, StatusCode: http.StatusOK}
	}

	// Fail closed whenever CLOUD_VERIFY_URL is configured without its Bearer secret.
	if c.verifySecret == "" {
		return Decision{
			Allowed:    false,
			StatusCode: http.StatusServiceUnavailable,
			Reason:     "auth_unavailable",
		}
	}

	if req.AccessKey == "" {
		return Decision{
			Allowed:    false,
			StatusCode: http.StatusUnauthorized,
			Reason:     "unauthorized",
		}
	}

	// Optional static RELAY_ACCESS_KEY fast-path in constant time.
	if c.static != nil && c.static.Summary().HasAccessKey {
		if dec := c.static.AuthorizeAccessKey(ctx, req); dec.Allowed {
			return dec
		}
	}

	digest := sha256.Sum256([]byte(req.AccessKey))
	keyHash := hex.EncodeToString(digest[:])

	now := c.now()
	if dec, ok := c.lookupCache(keyHash, now); ok {
		return dec
	}

	dec, cacheTTL := c.verifyRemote(ctx, keyHash)
	if cacheTTL > 0 {
		c.storeCache(keyHash, dec, c.now().Add(cacheTTL))
	}
	return dec
}

func (c *CloudAuthorizer) lookupCache(keyHash string, now time.Time) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[keyHash]
	if !ok {
		return Decision{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(c.cache, keyHash)
		return Decision{}, false
	}
	return entry.decision, true
}

func (c *CloudAuthorizer) storeCache(keyHash string, dec Decision, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.cache) >= c.maxCacheEntries {
		for k, v := range c.cache {
			if !now.Before(v.expiresAt) {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= c.maxCacheEntries {
			var oldestKey string
			var oldestExp time.Time
			for k, v := range c.cache {
				if oldestKey == "" || v.expiresAt.Before(oldestExp) {
					oldestKey = k
					oldestExp = v.expiresAt
				}
			}
			if oldestKey != "" {
				delete(c.cache, oldestKey)
			}
		}
	}
	c.cache[keyHash] = cloudCacheEntry{
		decision:  dec,
		expiresAt: expiresAt,
	}
}

func (c *CloudAuthorizer) verifyRemote(ctx context.Context, keyHash string) (Decision, time.Duration) {
	reqCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	payload, err := json.Marshal(cloudVerifyRequest{KeyHash: keyHash})
	if err != nil {
		return Decision{
			Allowed:    false,
			StatusCode: http.StatusServiceUnavailable,
			Reason:     "auth_unavailable",
		}, 0
	}

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.verifyURL, bytes.NewReader(payload))
	if err != nil {
		return Decision{
			Allowed:    false,
			StatusCode: http.StatusServiceUnavailable,
			Reason:     "auth_unavailable",
		}, 0
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.verifySecret)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return Decision{
			Allowed:    false,
			StatusCode: http.StatusServiceUnavailable,
			Reason:     "auth_unavailable",
		}, 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCloudVerifyResponseBytes))
	if err != nil || resp.StatusCode != http.StatusOK {
		return Decision{
			Allowed:    false,
			StatusCode: http.StatusServiceUnavailable,
			Reason:     "auth_unavailable",
		}, 0
	}

	var parsed cloudVerifyResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Decision{
			Allowed:    false,
			StatusCode: http.StatusServiceUnavailable,
			Reason:     "auth_unavailable",
		}, 0
	}

	if !parsed.Allowed {
		return Decision{
			Allowed:    false,
			StatusCode: http.StatusUnauthorized,
			Reason:     "unauthorized",
		}, c.negativeCacheTTL
	}

	var maxBytes int64
	if parsed.MaxTransferBytes > 0 {
		maxBytes = parsed.MaxTransferBytes
	}
	return Decision{
		Allowed:       true,
		StatusCode:    http.StatusOK,
		Subject:       parsed.Subject,
		KeyID:         parsed.KeyID,
		MaxBytesLimit: maxBytes,
	}, c.cacheTTL
}
