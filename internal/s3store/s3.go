// SPDX-License-Identifier: AGPL-3.0-only

// Package s3store implements a lightweight, zero-dependency S3-compatible
// object storage client using AWS Signature Version 4 (SigV4).
//
// It supports any S3-compatible provider including Tencent Cloud COS,
// Cloudflare R2, AWS S3, Aliyun OSS, MinIO, and Backblaze B2 for:
//   - Generating short-lived Presigned PUT / GET URLs (direct client transfer)
//   - Server-side HeadObject verification (existence & exact Content-Length)
//   - Server-side DeleteObject cleanup on ACK, DELETE, and TTL expiry
package s3store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	unsignedPayload    = "UNSIGNED-PAYLOAD"
	defaultKeyPrefix   = "mailboxes"
	defaultRegion      = "auto"
	defaultPresignTTL  = 5 * time.Minute
	maxPresignTTL      = 30 * time.Minute
)

var (
	// ErrObjectNotFound is returned by HeadObject when the object does not exist.
	ErrObjectNotFound = errors.New("s3store: object not found")
	// ErrInvalidConfig indicates missing or malformed S3 configuration.
	ErrInvalidConfig = errors.New("s3store: invalid configuration")
	// ErrInsecureSecretFile indicates a secret file has group/world permissions on Unix.
	ErrInsecureSecretFile = errors.New("s3store: secret file must be readable only by owner (0600 or stricter)")
)

// ObjectMeta holds object metadata returned by HeadObject.
type ObjectMeta struct {
	Size int64
	ETag string
}

// PresignedURL describes a short-lived direct upload or download URL.
// Callers must never log URL because it carries temporary bearer signatures.
type PresignedURL struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	ExpiresAtMs int64             `json:"expires_at_ms"`
}

// Store is the minimal object storage interface required by Hyper relay.
type Store interface {
	ObjectKey(mailboxID, transferID string, index int) string
	PresignPut(key string, ttl time.Duration, now time.Time) (PresignedURL, error)
	PresignGet(key string, ttl time.Duration, now time.Time) (PresignedURL, error)
	HeadObject(ctx context.Context, key string) (ObjectMeta, error)
	DeleteObject(ctx context.Context, key string) error
	DeleteTransfer(ctx context.Context, mailboxID, transferID string, indices []int) error
}

// Config configures an S3-compatible Store.
type Config struct {
	// Endpoint is the S3 API endpoint used for server-side HEAD/DELETE requests
	// (e.g. https://cos.ap-guangzhou.myqcloud.com, https://<acct>.r2.cloudflarestorage.com).
	Endpoint string
	// PublicEndpoint optionally overrides Endpoint when generating client-facing
	// Presigned URLs (useful when the relay talks over an internal VPC/Docker endpoint).
	PublicEndpoint string
	// Region is the signing region (e.g. ap-guangzhou, us-east-1, auto for R2).
	Region string
	// Bucket is the target bucket name (for Tencent COS: <name>-<appid>).
	Bucket string
	// AccessKeyID and SecretAccessKey are S3 credentials.
	AccessKeyID     string
	SecretAccessKey string
	// ForcePathStyle forces https://endpoint/bucket/key addressing (needed for MinIO/IP endpoints).
	ForcePathStyle bool
	// KeyPrefix namespaces objects inside a shared bucket (default "mailboxes").
	KeyPrefix string
	// PresignTTL sets default expiry for presigned URLs (default 5m, max 30m).
	PresignTTL time.Duration
	// HTTPClient overrides the HTTP client for server-side HEAD/DELETE requests.
	HTTPClient *http.Client
	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
}

// Client is an S3-compatible SigV4 Store implementation.
type Client struct {
	endpoint       *url.URL
	publicEndpoint *url.URL
	region         string
	bucket         string
	accessKeyID    string
	secretKey      string
	forcePathStyle bool
	keyPrefix      string
	presignTTL     time.Duration
	httpClient     *http.Client
	now            func() time.Time
}

// New validates cfg and constructs a SigV4 S3 Client.
func New(cfg Config) (*Client, error) {
	ep, err := parseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: S3_ENDPOINT: %v", ErrInvalidConfig, err)
	}
	pubEP := ep
	if strings.TrimSpace(cfg.PublicEndpoint) != "" {
		pubEP, err = parseEndpoint(cfg.PublicEndpoint)
		if err != nil {
			return nil, fmt.Errorf("%w: S3_PUBLIC_ENDPOINT: %v", ErrInvalidConfig, err)
		}
	}
	bucket := strings.TrimSpace(cfg.Bucket)
	if bucket == "" || strings.ContainsAny(bucket, "/\\ \t\r\n") {
		return nil, fmt.Errorf("%w: S3_BUCKET is required", ErrInvalidConfig)
	}
	ak := strings.TrimSpace(cfg.AccessKeyID)
	sk := strings.TrimSpace(cfg.SecretAccessKey)
	if ak == "" || sk == "" {
		return nil, fmt.Errorf("%w: S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY are required", ErrInvalidConfig)
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = defaultRegion
	}
	prefix := strings.Trim(strings.TrimSpace(cfg.KeyPrefix), "/")
	if prefix == "" {
		prefix = defaultKeyPrefix
	}
	presignTTL := cfg.PresignTTL
	if presignTTL <= 0 {
		presignTTL = defaultPresignTTL
	}
	if presignTTL > maxPresignTTL {
		presignTTL = maxPresignTTL
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	return &Client{
		endpoint:       ep,
		publicEndpoint: pubEP,
		region:         region,
		bucket:         bucket,
		accessKeyID:    ak,
		secretKey:      sk,
		forcePathStyle: cfg.ForcePathStyle,
		keyPrefix:      prefix,
		presignTTL:     presignTTL,
		httpClient:     httpClient,
		now:            nowFn,
	}, nil
}

// LoadFromEnv constructs an S3 Client from environment variables (supporting
// owner-only S3_SECRET_ACCESS_KEY_FILE on Unix).
func LoadFromEnv(getenv func(string) string) (*Client, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	secret := strings.TrimSpace(getenv("S3_SECRET_ACCESS_KEY"))
	if secretFile := strings.TrimSpace(getenv("S3_SECRET_ACCESS_KEY_FILE")); secretFile != "" {
		val, err := readOwnerOnlyFile(secretFile)
		if err != nil {
			return nil, err
		}
		secret = val
	}

	var presignTTL time.Duration
	if raw := strings.TrimSpace(getenv("S3_PRESIGN_TTL")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			presignTTL = d
		}
	}

	forcePathStyle := parseBoolEnv(getenv("S3_FORCE_PATH_STYLE"))

	return New(Config{
		Endpoint:        getenv("S3_ENDPOINT"),
		PublicEndpoint:  getenv("S3_PUBLIC_ENDPOINT"),
		Region:          getenv("S3_REGION"),
		Bucket:          getenv("S3_BUCKET"),
		AccessKeyID:     getenv("S3_ACCESS_KEY_ID"),
		SecretAccessKey: secret,
		ForcePathStyle:  forcePathStyle,
		KeyPrefix:       getenv("S3_KEY_PREFIX"),
		PresignTTL:      presignTTL,
	})
}

// ObjectKey returns the opaque object key for a ciphertext chunk.
func (c *Client) ObjectKey(mailboxID, transferID string, index int) string {
	return fmt.Sprintf("%s/%s/transfers/%s/chunks/%d", c.keyPrefix, mailboxID, transferID, index)
}

// PresignPut returns a short-lived SigV4 presigned PUT URL for direct client upload.
func (c *Client) PresignPut(key string, ttl time.Duration, now time.Time) (PresignedURL, error) {
	return c.presign(http.MethodPut, key, ttl, now)
}

// PresignGet returns a short-lived SigV4 presigned GET URL for direct client download.
func (c *Client) PresignGet(key string, ttl time.Duration, now time.Time) (PresignedURL, error) {
	return c.presign(http.MethodGet, key, ttl, now)
}

func (c *Client) presign(method, key string, ttl time.Duration, now time.Time) (PresignedURL, error) {
	if ttl <= 0 || ttl > c.presignTTL {
		ttl = c.presignTTL
	}
	expSec := int64(ttl.Seconds())
	if expSec < 1 {
		expSec = 1
	}
	if expSec > int64(maxPresignTTL.Seconds()) {
		expSec = int64(maxPresignTTL.Seconds())
	}

	utcNow := now.UTC()
	amzDate := utcNow.Format("20060102T150405Z")
	dateStamp := utcNow.Format("20060102")
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.region)

	host, canonicalURI, scheme := c.objectAddress(c.publicEndpoint, key)

	query := [][2]string{
		{"X-Amz-Algorithm", "AWS4-HMAC-SHA256"},
		{"X-Amz-Credential", c.accessKeyID + "/" + scope},
		{"X-Amz-Date", amzDate},
		{"X-Amz-Expires", strconv.FormatInt(expSec, 10)},
		{"X-Amz-SignedHeaders", "host"},
	}
	canonicalQuery := buildCanonicalQuery(query)
	canonicalHeaders := "host:" + host + "\n"
	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		"host",
		unsignedPayload,
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	sig := hex.EncodeToString(hmacSHA256(signingKey(c.secretKey, dateStamp, c.region, "s3"), []byte(stringToSign)))
	finalURL := fmt.Sprintf("%s://%s%s?%s&X-Amz-Signature=%s", scheme, host, canonicalURI, canonicalQuery, sig)

	return PresignedURL{
		Method:      method,
		URL:         finalURL,
		ExpiresAtMs: utcNow.Add(time.Duration(expSec) * time.Second).UnixMilli(),
	}, nil
}

// HeadObject verifies an uploaded chunk exists in S3/COS/R2 and returns its size and ETag.
func (c *Client) HeadObject(ctx context.Context, key string) (ObjectMeta, error) {
	req, err := c.newSignedRequest(ctx, http.MethodHead, key)
	if err != nil {
		return ObjectMeta{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ObjectMeta{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode == http.StatusNotFound {
		return ObjectMeta{}, ErrObjectNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ObjectMeta{}, fmt.Errorf("s3store: head object failed with status %d", resp.StatusCode)
	}
	size := resp.ContentLength
	if size < 0 {
		if raw := strings.TrimSpace(resp.Header.Get("Content-Length")); raw != "" {
			if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
				size = parsed
			}
		}
	}
	return ObjectMeta{
		Size: size,
		ETag: strings.Trim(resp.Header.Get("ETag"), `"`),
	}, nil
}

// DeleteObject deletes a single chunk object from S3/COS/R2 (idempotent on 404).
func (c *Client) DeleteObject(ctx context.Context, key string) error {
	req, err := c.newSignedRequest(ctx, http.MethodDelete, key)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode == http.StatusNotFound || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
		return nil
	}
	return fmt.Errorf("s3store: delete object failed with status %d", resp.StatusCode)
}

// DeleteTransfer deletes all given chunk indices for a transfer (best-effort across all indices).
func (c *Client) DeleteTransfer(ctx context.Context, mailboxID, transferID string, indices []int) error {
	var firstErr error
	for _, idx := range indices {
		if err := c.DeleteObject(ctx, c.ObjectKey(mailboxID, transferID, idx)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *Client) newSignedRequest(ctx context.Context, method, key string) (*http.Request, error) {
	utcNow := c.now().UTC()
	amzDate := utcNow.Format("20060102T150405Z")
	dateStamp := utcNow.Format("20060102")
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.region)

	host, canonicalURI, scheme := c.objectAddress(c.endpoint, key)
	targetURL := fmt.Sprintf("%s://%s%s", scheme, host, canonicalURI)

	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", emptyPayloadSHA256)

	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", host, emptyPayloadSHA256, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI,
		"",
		canonicalHeaders,
		signedHeaders,
		emptyPayloadSHA256,
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	sig := hex.EncodeToString(hmacSHA256(signingKey(c.secretKey, dateStamp, c.region, "s3"), []byte(stringToSign)))
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKeyID, scope, signedHeaders, sig)
	req.Header.Set("Authorization", authHeader)
	return req, nil
}

func (c *Client) objectAddress(ep *url.URL, key string) (host, canonicalURI, scheme string) {
	scheme = ep.Scheme
	basePath := strings.TrimRight(ep.Path, "/")
	cleanKey := strings.TrimLeft(key, "/")

	hostname := ep.Hostname()
	usePathStyle := c.forcePathStyle || isIPOrLocalhost(hostname)
	// Avoid double-prefixing if endpoint already contains "<bucket>." as its host prefix.
	alreadyVirtualHost := strings.HasPrefix(strings.ToLower(hostname), strings.ToLower(c.bucket)+".")

	if usePathStyle || alreadyVirtualHost {
		host = ep.Host
		if alreadyVirtualHost {
			canonicalURI = encodeURIPath(basePath + "/" + cleanKey)
		} else {
			canonicalURI = encodeURIPath(basePath + "/" + c.bucket + "/" + cleanKey)
		}
		return host, canonicalURI, scheme
	}

	host = c.bucket + "." + ep.Host
	canonicalURI = encodeURIPath(basePath + "/" + cleanKey)
	return host, canonicalURI, scheme
}

func parseEndpoint(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty endpoint")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return nil, errors.New("scheme must be http or https")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("endpoint must not include userinfo, query, or fragment")
	}
	u.Scheme = scheme
	return u, nil
}

func isIPOrLocalhost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	return net.ParseIP(host) != nil
}

func encodeURIPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = awsPercentEncode(s)
	}
	return strings.Join(segs, "/")
}

func buildCanonicalQuery(pairs [][2]string) string {
	encoded := make([][2]string, len(pairs))
	for i, kv := range pairs {
		encoded[i] = [2]string{awsPercentEncode(kv[0]), awsPercentEncode(kv[1])}
	}
	sort.Slice(encoded, func(i, j int) bool {
		if encoded[i][0] == encoded[j][0] {
			return encoded[i][1] < encoded[j][1]
		}
		return encoded[i][0] < encoded[j][0]
	})
	var b strings.Builder
	for i, kv := range encoded {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(kv[0])
		b.WriteByte('=')
		b.WriteString(kv[1])
	}
	return b.String()
}

func awsPercentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func signingKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func parseBoolEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func readOwnerOnlyFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("s3store: stat secret file: %w", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return "", ErrInsecureSecretFile
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("s3store: read secret file: %w", err)
	}
	val := strings.TrimSpace(string(raw))
	for i := range raw {
		raw[i] = 0
	}
	if val == "" {
		return "", fmt.Errorf("%w: secret file is empty", ErrInvalidConfig)
	}
	return val, nil
}
