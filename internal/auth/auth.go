// SPDX-License-Identifier: AGPL-3.0-only

// Package auth provides the shared credential and admission abstraction used
// across UniClipboard relay microservices (Hyper HTTP relay and future P2P/DERP
// relay). It supports self-hosted static credentials and defines an extensible
// Authorizer interface for future official Cloud control-plane policies.
package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
)

// Service identifies which relay microservice is requesting an admission check.
type Service string

const (
	ServiceHyper Service = "hyper"
	ServiceP2P   Service = "p2p"
)

// AccessKeyHeader is the shared HTTP header carrying an optional instance access key.
const AccessKeyHeader = "X-Unic-Relay-Key"

var (
	// ErrInvalidPubKey indicates a malformed base64url Ed25519 public key in configuration.
	ErrInvalidPubKey = errors.New("auth: invalid Ed25519 public key")
	// ErrInsecureKeyFile indicates a credential file has group or world permissions on Unix.
	ErrInsecureKeyFile = errors.New("auth: credential file must be readable only by owner (0600 or stricter)")
	// ErrEmptyKeyFile indicates a configured credential file contains no non-whitespace secret.
	ErrEmptyKeyFile = errors.New("auth: credential file is empty")
)

// Request captures the credential material presented by a client to a relay service.
// Implementations must never log or persist raw AccessKey values.
type Request struct {
	Service   Service
	AccessKey string
	PubKey    string
	Subject   string
	ClientIP  string
}

// Decision represents an admission check result.
type Decision struct {
	Allowed       bool
	StatusCode    int
	Reason        string
	MaxBytesLimit int64
}

// Authorizer is the shared admission interface across Hyper and future P2P/DERP relays.
// Official Cloud deployments can plug in a control-plane or JWT-backed Authorizer
// without changing relay protocol handlers.
type Authorizer interface {
	AuthorizeAccessKey(ctx context.Context, req Request) Decision
	AuthorizeDevicePubKey(ctx context.Context, req Request) Decision
}

// ConfigSummary provides safe, non-secret metadata suitable for structured startup logs.
type ConfigSummary struct {
	HasAccessKey       bool
	AllowedPubKeyCount int
}

// StaticConfig configures a StaticAuthorizer for self-hosted deployments.
// AccessKeyBytes is wiped immediately after its SHA-256 digest is computed.
type StaticConfig struct {
	AccessKeyBytes []byte
	AllowedPubKeys []string
}

// StaticAuthorizer enforces optional shared access-key digest matching and
// optional Ed25519 device public key allowlisting. It never retains the raw
// access key after construction.
type StaticAuthorizer struct {
	hasAccessKey    bool
	accessKeyDigest [32]byte
	allowedPubKeys  map[string]struct{}
}

// NewStatic validates cfg, hashes any configured access key into a SHA-256 digest,
// wipes cfg.AccessKeyBytes in place, and returns a StaticAuthorizer.
func NewStatic(cfg StaticConfig) (*StaticAuthorizer, error) {
	defer wipeBytes(cfg.AccessKeyBytes)

	a := &StaticAuthorizer{}
	if len(cfg.AccessKeyBytes) > 0 {
		a.accessKeyDigest = sha256.Sum256(cfg.AccessKeyBytes)
		a.hasAccessKey = true
	}

	if len(cfg.AllowedPubKeys) > 0 {
		a.allowedPubKeys = make(map[string]struct{}, len(cfg.AllowedPubKeys))
		for _, raw := range cfg.AllowedPubKeys {
			pk := strings.TrimSpace(raw)
			if pk == "" {
				continue
			}
			decoded, err := base64.RawURLEncoding.DecodeString(pk)
			if err != nil || len(decoded) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("%w: must be 32-byte raw base64url", ErrInvalidPubKey)
			}
			canonical := base64.RawURLEncoding.EncodeToString(decoded)
			a.allowedPubKeys[canonical] = struct{}{}
		}
		if len(a.allowedPubKeys) == 0 {
			a.allowedPubKeys = nil
		}
	}

	return a, nil
}

// LoadStaticFromEnv loads shared relay credentials from environment variables or
// owner-only secret files. File variables take precedence over inline env variables.
//
// Supported variables (canonical shared names first, legacy UNIC_RELAY_* fallback):
//   - RELAY_ACCESS_KEY_FILE / UNIC_RELAY_ACCESS_KEY_FILE
//   - RELAY_ACCESS_KEY / UNIC_RELAY_ACCESS_KEY
//   - RELAY_ALLOWED_PUBKEYS / UNIC_RELAY_ALLOWED_PUBKEYS (comma-separated base64url Ed25519 keys)
func LoadStaticFromEnv(getenv func(string) string) (*StaticAuthorizer, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	var keyBytes []byte
	keyFile := firstNonEmpty(getenv("RELAY_ACCESS_KEY_FILE"), getenv("UNIC_RELAY_ACCESS_KEY_FILE"))
	if keyFile != "" {
		b, err := readOwnerOnlySecretFile(keyFile)
		if err != nil {
			return nil, err
		}
		keyBytes = b
	} else if raw := firstNonEmpty(getenv("RELAY_ACCESS_KEY"), getenv("UNIC_RELAY_ACCESS_KEY")); raw != "" {
		keyBytes = []byte(raw)
	}

	var allowed []string
	if raw := firstNonEmpty(getenv("RELAY_ALLOWED_PUBKEYS"), getenv("UNIC_RELAY_ALLOWED_PUBKEYS")); raw != "" {
		allowed = strings.Split(raw, ",")
	}

	return NewStatic(StaticConfig{
		AccessKeyBytes: keyBytes,
		AllowedPubKeys: allowed,
	})
}

// Summary returns non-secret configuration counts safe for logging.
func (a *StaticAuthorizer) Summary() ConfigSummary {
	if a == nil {
		return ConfigSummary{}
	}
	return ConfigSummary{
		HasAccessKey:       a.hasAccessKey,
		AllowedPubKeyCount: len(a.allowedPubKeys),
	}
}

// AuthorizeAccessKey verifies the presented X-Unic-Relay-Key against the stored
// SHA-256 digest using constant-time comparison.
func (a *StaticAuthorizer) AuthorizeAccessKey(_ context.Context, req Request) Decision {
	if a == nil || !a.hasAccessKey {
		return Decision{Allowed: true, StatusCode: http.StatusOK}
	}
	if req.AccessKey == "" {
		return Decision{Allowed: false, StatusCode: http.StatusUnauthorized, Reason: "unauthorized"}
	}
	gotDigest := sha256.Sum256([]byte(req.AccessKey))
	if subtle.ConstantTimeCompare(gotDigest[:], a.accessKeyDigest[:]) != 1 {
		return Decision{Allowed: false, StatusCode: http.StatusUnauthorized, Reason: "unauthorized"}
	}
	return Decision{Allowed: true, StatusCode: http.StatusOK}
}

// AuthorizeDevicePubKey verifies whether the presented Ed25519 public key is permitted
// when an allowlist is configured.
func (a *StaticAuthorizer) AuthorizeDevicePubKey(_ context.Context, req Request) Decision {
	if a == nil || len(a.allowedPubKeys) == 0 {
		return Decision{Allowed: true, StatusCode: http.StatusOK}
	}
	if _, ok := a.allowedPubKeys[req.PubKey]; !ok {
		return Decision{Allowed: false, StatusCode: http.StatusForbidden, Reason: "pubkey_not_allowed"}
	}
	return Decision{Allowed: true, StatusCode: http.StatusOK}
}

func readOwnerOnlySecretFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("auth: stat credential file: %w", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, ErrInsecureKeyFile
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("auth: read credential file: %w", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	wipeBytes(raw)
	if trimmed == "" {
		return nil, ErrEmptyKeyFile
	}
	return []byte(trimmed), nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
