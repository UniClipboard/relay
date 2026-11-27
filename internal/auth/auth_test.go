// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testPubKey(seedByte byte) string {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func TestStaticAuthorizerAccessKeyAndWipe(t *testing.T) {
	rawKey := []byte("super-secret-relay-access-key-2026")
	a, err := NewStatic(StaticConfig{AccessKeyBytes: rawKey})
	if err != nil {
		t.Fatalf("NewStatic failed: %v", err)
	}
	// Verify input buffer was wiped after digest calculation.
	for i, b := range rawKey {
		if b != 0 {
			t.Fatalf("expected rawKey[%d] to be wiped to 0, got %d", i, b)
		}
	}

	ctx := context.Background()
	if dec := a.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: "super-secret-relay-access-key-2026"}); !dec.Allowed {
		t.Fatalf("expected valid access key to be allowed, got %+v", dec)
	}
	if dec := a.AuthorizeAccessKey(ctx, Request{Service: ServiceP2P, AccessKey: "super-secret-relay-access-key-2026"}); !dec.Allowed {
		t.Fatalf("expected valid access key for p2p service to be allowed, got %+v", dec)
	}
	if dec := a.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: "wrong-key"}); dec.Allowed || dec.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected wrong access key to fail with 401, got %+v", dec)
	}
	if dec := a.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper}); dec.Allowed || dec.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected missing access key to fail with 401, got %+v", dec)
	}
}

func TestStaticAuthorizerPubKeyAllowlist(t *testing.T) {
	pk1 := testPubKey(1)
	pk2 := testPubKey(2)

	a, err := NewStatic(StaticConfig{AllowedPubKeys: []string{" " + pk1 + " "}})
	if err != nil {
		t.Fatalf("NewStatic failed: %v", err)
	}
	ctx := context.Background()
	if dec := a.AuthorizeDevicePubKey(ctx, Request{Service: ServiceHyper, PubKey: pk1}); !dec.Allowed {
		t.Fatalf("expected pk1 allowed, got %+v", dec)
	}
	if dec := a.AuthorizeDevicePubKey(ctx, Request{Service: ServiceHyper, PubKey: pk2}); dec.Allowed || dec.StatusCode != http.StatusForbidden {
		t.Fatalf("expected pk2 forbidden, got %+v", dec)
	}

	if _, err := NewStatic(StaticConfig{AllowedPubKeys: []string{"not-valid-base64!!!"}}); !errors.Is(err, ErrInvalidPubKey) {
		t.Fatalf("expected ErrInvalidPubKey, got %v", err)
	}
}

func TestLoadStaticFromEnvAndFilePermissions(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "relay.key")
	if err := os.WriteFile(keyPath, []byte("file-secret-value\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	pk := testPubKey(7)

	env := map[string]string{
		"RELAY_ACCESS_KEY_FILE": keyPath,
		"RELAY_ACCESS_KEY":      "inline-ignored-when-file-set",
		"RELAY_ALLOWED_PUBKEYS": pk,
	}
	a, err := LoadStaticFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("LoadStaticFromEnv failed: %v", err)
	}
	if sum := a.Summary(); !sum.HasAccessKey || sum.AllowedPubKeyCount != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	ctx := context.Background()
	if !a.AuthorizeAccessKey(ctx, Request{AccessKey: "file-secret-value"}).Allowed {
		t.Fatal("expected file secret to take precedence")
	}
	if a.AuthorizeAccessKey(ctx, Request{AccessKey: "inline-ignored-when-file-set"}).Allowed {
		t.Fatal("inline secret should not be active when file is configured")
	}

	// Verify legacy fallback env names.
	legacyEnv := map[string]string{
		"UNIC_RELAY_ACCESS_KEY":      "legacy-key",
		"UNIC_RELAY_ALLOWED_PUBKEYS": pk,
	}
	legacyAuth, err := LoadStaticFromEnv(func(k string) string { return legacyEnv[k] })
	if err != nil {
		t.Fatalf("legacy LoadStaticFromEnv failed: %v", err)
	}
	if !legacyAuth.AuthorizeAccessKey(ctx, Request{AccessKey: "legacy-key"}).Allowed {
		t.Fatal("expected legacy access key to work")
	}

	if runtime.GOOS != "windows" {
		badPath := filepath.Join(dir, "insecure.key")
		if err := os.WriteFile(badPath, []byte("secret"), 0o644); err != nil {
			t.Fatalf("write insecure key: %v", err)
		}
		if _, err := LoadStaticFromEnv(func(k string) string {
			if k == "RELAY_ACCESS_KEY_FILE" {
				return badPath
			}
			return ""
		}); !errors.Is(err, ErrInsecureKeyFile) {
			t.Fatalf("expected ErrInsecureKeyFile for mode 0644, got %v", err)
		}
	}
}

func TestCloudAuthorizerAllowDenyCacheFailClosedAndNoRawKeyLeakage(t *testing.T) {
	const (
		verifySecret = "cloud-verify-bearer-secret"
		rawValidKey  = "uc_live_super_secret_user_api_key_12345"
		rawDeniedKey = "uc_live_revoked_user_api_key_67890"
		staticKey    = "self-hosted-static-fallback-key"
	)

	validSum := sha256.Sum256([]byte(rawValidKey))
	validHash := hex.EncodeToString(validSum[:])
	deniedSum := sha256.Sum256([]byte(rawDeniedKey))
	deniedHash := hex.EncodeToString(deniedSum[:])

	var calls atomic.Int32
	var forceStatus atomic.Int32
	forceStatus.Store(http.StatusOK)

	var seenMu sync.Mutex
	var seenBodies []string
	var seenAuthHeaders []string

	cloudSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		bodyBytes, _ := io.ReadAll(r.Body)
		seenMu.Lock()
		seenBodies = append(seenBodies, string(bodyBytes))
		seenAuthHeaders = append(seenAuthHeaders, r.Header.Get("Authorization"))
		seenMu.Unlock()

		if r.Header.Get("Authorization") != "Bearer "+verifySecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if st := int(forceStatus.Load()); st != http.StatusOK {
			w.WriteHeader(st)
			return
		}
		var req struct {
			KeyHash string `json:"key_hash"`
		}
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.KeyHash {
		case validHash:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"allowed":            true,
				"subject":            "user-42",
				"key_id":             "key-99",
				"max_transfer_bytes": 5242880,
			})
		case deniedHash:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"allowed": false,
				"reason":  "revoked",
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"allowed": false,
				"reason":  "not_found",
			})
		}
	}))
	defer cloudSrv.Close()

	staticAuth, err := NewStatic(StaticConfig{
		AccessKeyBytes: []byte(staticKey),
		AllowedPubKeys: []string{testPubKey(3)},
	})
	if err != nil {
		t.Fatalf("NewStatic: %v", err)
	}

	var nowMu sync.Mutex
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	getNow := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		nowMu.Lock()
		now = now.Add(d)
		nowMu.Unlock()
	}

	ca, err := NewCloud(CloudConfig{
		VerifyURL:        cloudSrv.URL,
		VerifySecret:     verifySecret,
		CacheTTL:         60 * time.Second,
		NegativeCacheTTL: 10 * time.Second,
		HTTPClient:       cloudSrv.Client(),
		Static:           staticAuth,
		Now:              getNow,
	})
	if err != nil {
		t.Fatalf("NewCloud: %v", err)
	}

	ctx := context.Background()

	// 1. Missing key -> 401 without calling Cloud.
	if dec := ca.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper}); dec.Allowed || dec.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on missing key, got %+v", dec)
	}
	if calls.Load() != 0 {
		t.Fatalf("expected 0 cloud calls on missing key, got %d", calls.Load())
	}

	// 2. Static fallback key -> allowed immediately without calling Cloud.
	if dec := ca.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: staticKey}); !dec.Allowed {
		t.Fatalf("expected static key fast-path allow, got %+v", dec)
	}
	if calls.Load() != 0 {
		t.Fatalf("expected 0 cloud calls on static key fast-path, got %d", calls.Load())
	}

	// 3. Valid cloud key -> allowed with subject, key_id, max_transfer_bytes, and cached for 60s.
	dec := ca.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: rawValidKey})
	if !dec.Allowed || dec.Subject != "user-42" || dec.KeyID != "key-99" || dec.MaxBytesLimit != 5242880 {
		t.Fatalf("unexpected allow decision: %+v", dec)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 cloud call, got %d", calls.Load())
	}

	advance(30 * time.Second)
	dec2 := ca.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: rawValidKey})
	if !dec2.Allowed || dec2.Subject != "user-42" || dec2.MaxBytesLimit != 5242880 {
		t.Fatalf("unexpected cached decision: %+v", dec2)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected cached hit with 1 total cloud call, got %d", calls.Load())
	}

	// Advance past 60s TTL -> refreshes from Cloud.
	advance(31 * time.Second)
	if dec3 := ca.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: rawValidKey}); !dec3.Allowed {
		t.Fatalf("expected refreshed allow, got %+v", dec3)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 cloud calls after TTL expiry, got %d", calls.Load())
	}

	// 4. Denied cloud key -> 401 and negative-cached for 10s.
	deniedDec := ca.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: rawDeniedKey})
	if deniedDec.Allowed || deniedDec.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on denied key, got %+v", deniedDec)
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 cloud calls, got %d", calls.Load())
	}
	advance(5 * time.Second)
	deniedDec2 := ca.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: rawDeniedKey})
	if deniedDec2.Allowed || deniedDec2.StatusCode != http.StatusUnauthorized || calls.Load() != 3 {
		t.Fatalf("expected negative cache hit, got dec=%+v calls=%d", deniedDec2, calls.Load())
	}
	advance(6 * time.Second)
	_ = ca.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: rawDeniedKey})
	if calls.Load() != 4 {
		t.Fatalf("expected negative cache expiry at 10s, got calls=%d", calls.Load())
	}

	// 5. Cloud 5xx -> fail closed 503 (auth_unavailable) and NOT cached.
	forceStatus.Store(http.StatusInternalServerError)
	errDec := ca.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: "uc_live_uncached_500"})
	if errDec.Allowed || errDec.StatusCode != http.StatusServiceUnavailable || errDec.Reason != "auth_unavailable" {
		t.Fatalf("expected 503 auth_unavailable on cloud 500, got %+v", errDec)
	}
	errDec2 := ca.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: "uc_live_uncached_500"})
	if errDec2.Allowed || errDec2.StatusCode != http.StatusServiceUnavailable || calls.Load() != 6 {
		t.Fatalf("expected 503 not cached, got dec=%+v calls=%d", errDec2, calls.Load())
	}

	// 6. Verify no raw API key was ever transmitted to Cloud.
	seenMu.Lock()
	for _, b := range seenBodies {
		if strings.Contains(b, rawValidKey) || strings.Contains(b, rawDeniedKey) || strings.Contains(b, "uc_live_") {
			t.Fatalf("raw API key leaked in cloud verify request body: %s", b)
		}
	}
	for _, h := range seenAuthHeaders {
		if h != "Bearer "+verifySecret {
			t.Fatalf("unexpected Authorization header sent to cloud: %q", h)
		}
	}
	seenMu.Unlock()

	// 7. Missing CLOUD_VERIFY_SECRET fails closed with 503 (auth_unavailable).
	misconfigured, err := NewCloud(CloudConfig{VerifyURL: cloudSrv.URL})
	if err != nil {
		t.Fatalf("NewCloud without secret: %v", err)
	}
	if dec := misconfigured.AuthorizeAccessKey(ctx, Request{Service: ServiceHyper, AccessKey: rawValidKey}); dec.Allowed || dec.StatusCode != http.StatusServiceUnavailable || dec.Reason != "auth_unavailable" {
		t.Fatalf("expected 503 auth_unavailable when secret missing, got %+v", dec)
	}

	// 8. PubKey allowlist still delegates to underlying StaticAuthorizer.
	if !ca.AuthorizeDevicePubKey(ctx, Request{PubKey: testPubKey(3)}).Allowed {
		t.Fatal("expected allowed pubkey to pass")
	}
	if ca.AuthorizeDevicePubKey(ctx, Request{PubKey: testPubKey(4)}).Allowed {
		t.Fatal("expected disallowed pubkey to be rejected")
	}
}

func TestLoadFromEnvCloudAndStaticModes(t *testing.T) {
	// Static-only mode when CLOUD_VERIFY_URL is empty.
	staticAuth, sum, err := LoadFromEnv(func(k string) string {
		if k == "RELAY_ACCESS_KEY" {
			return "only-static"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("LoadFromEnv static: %v", err)
	}
	if !sum.HasAccessKey || sum.HasCloudVerify {
		t.Fatalf("unexpected static summary: %+v", sum)
	}
	if !staticAuth.AuthorizeAccessKey(context.Background(), Request{AccessKey: "only-static"}).Allowed {
		t.Fatal("expected static key allowed")
	}

	// Cloud mode when CLOUD_VERIFY_URL is set without secret -> fails closed 503.
	cloudAuth, sum2, err := LoadFromEnv(func(k string) string {
		if k == "CLOUD_VERIFY_URL" {
			return "https://cloud.uniclipboard.app/api/relay/v2/keys/verify"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("LoadFromEnv cloud: %v", err)
	}
	if !sum2.HasCloudVerify {
		t.Fatalf("expected HasCloudVerify=true, got %+v", sum2)
	}
	if dec := cloudAuth.AuthorizeAccessKey(context.Background(), Request{AccessKey: "any"}); dec.Allowed || dec.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when CLOUD_VERIFY_SECRET missing, got %+v", dec)
	}
}
