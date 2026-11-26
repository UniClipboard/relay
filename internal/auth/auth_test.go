// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
