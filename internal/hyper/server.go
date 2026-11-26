// SPDX-License-Identifier: AGPL-3.0-only

// Package hyper implements the zero-knowledge Relay HTTP API v2 control plane.
// Clients upload and download AES-256-GCM ciphertext chunks directly against
// configured S3-compatible object storage (Tencent COS, Cloudflare R2, AWS S3,
// Aliyun OSS, MinIO) via short-lived SigV4 presigned URLs. The relay server
// handles only authentication, metadata, SSE notifications, HeadObject commit
// verification, and immediate DeleteObject cleanup.
package hyper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uniclipboard/relay/internal/auth"
	"github.com/uniclipboard/relay/internal/relaycrypto"
	"github.com/uniclipboard/relay/internal/s3store"
)

const (
	DefaultMaxTransferBytes = 25 << 20 // 25 MiB
	DefaultMaxSenders       = 64
	DefaultMaxTransfers     = 32
	DefaultEventBuffer      = 128
	DefaultPresignTTL       = 5 * time.Minute
	MaxInlineUploadURLs     = 16
	nonceReplayWindow       = 120 * time.Second
)

// Config configures a Hyper Relay server instance backed by direct S3 storage.
type Config struct {
	// Origin is the canonical origin used for Owner Auth and mailbox verification.
	// If empty, the server derives it from the incoming request.
	Origin string
	// Authorizer enforces shared credential policies (access key + Ed25519 allowlist).
	Authorizer auth.Authorizer
	// ObjectStore is the S3-compatible store used to sign presigned URLs, verify
	// uploaded chunks via HeadObject, and delete expired/ACKed objects. Required.
	ObjectStore s3store.Store
	// MaxTransferBytes bounds total ciphertext bytes per transfer (default 25 MiB).
	MaxTransferBytes int64
	// DefaultTTL and MaxTTL bound transfer lifetime (default 10m / 30m).
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	// PresignTTL bounds presigned PUT/GET URL lifetime (default 5m).
	PresignTTL time.Duration
	// MaxSendersPerMailbox caps registered delivery token hashes per mailbox (default 64).
	MaxSendersPerMailbox int
	// MaxTransfersPerMailbox caps concurrent active transfers per mailbox (default 32).
	MaxTransfersPerMailbox int
	// KeepaliveInterval sets SSE comment heartbeat cadence (default 25s).
	KeepaliveInterval time.Duration
	// Now overrides time.Now for tests.
	Now func() time.Time
}

// TransferSummary is returned by GET /v1/relay/mailboxes/{mailbox_id}/transfers.
type TransferSummary struct {
	TransferID      string               `json:"transfer_id"`
	Envelope        relaycrypto.Envelope `json:"envelope"`
	AvailableBitmap string               `json:"available_bitmap"`
	ExpiresAtMs     int64                `json:"expires_at_ms"`
}

// ChunkUploadGrant is one presigned PUT grant returned on transfer creation.
type ChunkUploadGrant struct {
	Index       int               `json:"index"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	ExpiresAtMs int64             `json:"expires_at_ms"`
}

// SSEEvent is one server-sent event delivered on GET .../events.
type SSEEvent struct {
	ID              string                `json:"id"`
	Event           string                `json:"event"`
	TransferID      string                `json:"transfer_id"`
	Envelope        *relaycrypto.Envelope `json:"envelope,omitempty"`
	ChunkIndex      *int                  `json:"chunk_index,omitempty"`
	AvailableBitmap string                `json:"available_bitmap,omitempty"`
	ExpiresAtMs     int64                 `json:"expires_at_ms,omitempty"`
}

type senderRecord struct {
	tokenHash string
	maxBytes  int64
}

type storedTransfer struct {
	id         string
	senderHash string
	envelope   relaycrypto.Envelope
	chunkSizes map[int]int64
	available  []byte
	expiresAt  time.Time
}

type cleanupTarget struct {
	mailboxID  string
	transferID string
	indices    []int
}

type sseSubscriber struct {
	ch   chan SSEEvent
	done chan struct{}
}

type mailboxState struct {
	senders   map[string]*senderRecord
	transfers map[string]*storedTransfer
	nextEvtID uint64
	history   []SSEEvent
	subs      map[*sseSubscriber]struct{}
}

// Server implements the Direct-to-S3 Hyper Relay HTTP API microservice.
type Server struct {
	cfg   Config
	store s3store.Store

	mu        sync.Mutex
	mailboxes map[string]*mailboxState
	nonces    map[string]time.Time
	reqCount  int64
	closed    bool
}

// New creates a new Hyper relay server with validated defaults.
func New(cfg Config) (*Server, error) {
	if cfg.ObjectStore == nil {
		return nil, errors.New("hyper: ObjectStore (S3-compatible storage) is required")
	}
	if cfg.MaxTransferBytes <= 0 {
		cfg.MaxTransferBytes = DefaultMaxTransferBytes
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = relaycrypto.DefaultTTL
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = relaycrypto.MaxTTL
	}
	if cfg.DefaultTTL > cfg.MaxTTL {
		cfg.DefaultTTL = cfg.MaxTTL
	}
	if cfg.PresignTTL <= 0 {
		cfg.PresignTTL = DefaultPresignTTL
	}
	if cfg.MaxSendersPerMailbox <= 0 {
		cfg.MaxSendersPerMailbox = DefaultMaxSenders
	}
	if cfg.MaxTransfersPerMailbox <= 0 {
		cfg.MaxTransfersPerMailbox = DefaultMaxTransfers
	}
	if cfg.KeepaliveInterval <= 0 {
		cfg.KeepaliveInterval = 25 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Origin != "" {
		if norm, err := relaycrypto.NormalizeRelayOrigin(cfg.Origin); err == nil {
			cfg.Origin = norm
		}
	}
	return &Server{
		cfg:       cfg,
		store:     cfg.ObjectStore,
		mailboxes: map[string]*mailboxState{},
		nonces:    map[string]time.Time{},
	}, nil
}

// RequestCount returns the total number of HTTP requests handled.
func (s *Server) RequestCount() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqCount
}

// ActiveTransferCount returns the number of currently stored non-expired transfers.
func (s *Server) ActiveTransferCount() int {
	var expired []cleanupTarget

	s.mu.Lock()
	now := s.cfg.Now()
	total := 0
	for mbID, mb := range s.mailboxes {
		expired = append(expired, s.sweepMailboxLocked(mbID, mb, now)...)
		total += len(mb.transfers)
	}
	s.mu.Unlock()

	s.deleteObjects(context.Background(), expired)
	return total
}

// Close stops active SSE streams.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for _, mb := range s.mailboxes {
		for sub := range mb.subs {
			close(sub.done)
			delete(mb.subs, sub)
		}
	}
	s.mu.Unlock()
	return nil
}

// Sweep removes expired transfers (and deletes their S3 objects) as well as expired nonces.
func (s *Server) Sweep(ctx context.Context) {
	var expired []cleanupTarget

	s.mu.Lock()
	now := s.cfg.Now()
	for k, exp := range s.nonces {
		if !now.Before(exp) {
			delete(s.nonces, k)
		}
	}
	for id, mb := range s.mailboxes {
		expired = append(expired, s.sweepMailboxLocked(id, mb, now)...)
		if len(mb.senders) == 0 && len(mb.transfers) == 0 && len(mb.subs) == 0 {
			delete(s.mailboxes, id)
		}
	}
	s.mu.Unlock()

	s.deleteObjects(ctx, expired)
}

func transferIndices(tr *storedTransfer) []int {
	out := make([]int, 0, tr.envelope.TotalChunks)
	for i := 0; i < tr.envelope.TotalChunks; i++ {
		out = append(out, i)
	}
	return out
}

func (s *Server) sweepMailboxLocked(mailboxID string, mb *mailboxState, now time.Time) []cleanupTarget {
	var expired []cleanupTarget
	for tid, tr := range mb.transfers {
		if !now.Before(tr.expiresAt) {
			delete(mb.transfers, tid)
			expired = append(expired, cleanupTarget{
				mailboxID:  mailboxID,
				transferID: tid,
				indices:    transferIndices(tr),
			})
		}
	}
	return expired
}

func (s *Server) deleteObjects(ctx context.Context, targets []cleanupTarget) {
	for _, t := range targets {
		_ = s.store.DeleteTransfer(ctx, t.mailboxID, t.transferID, t.indices)
	}
}

func (s *Server) originFor(r *http.Request) string {
	if s.cfg.Origin != "" {
		return s.cfg.Origin
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	norm, err := relaycrypto.NormalizeRelayOrigin(scheme + "://" + r.Host)
	if err != nil {
		return scheme + "://" + r.Host
	}
	return norm
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.reqCount++
	s.mu.Unlock()

	if r.URL.Path == "/healthz" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": "hyper-relay",
			"storage": "s3-direct",
		})
		return
	}

	if s.cfg.Authorizer != nil {
		dec := s.cfg.Authorizer.AuthorizeAccessKey(r.Context(), auth.Request{
			Service:   auth.ServiceHyper,
			AccessKey: r.Header.Get(auth.AccessKeyHeader),
			ClientIP:  clientIP(r),
		})
		if !dec.Allowed {
			code := dec.StatusCode
			if code == 0 {
				code = http.StatusUnauthorized
			}
			reason := dec.Reason
			if reason == "" {
				reason = "unauthorized"
			}
			writeErr(w, code, reason)
			return
		}
	}

	const prefix = "/v1/relay/mailboxes/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || !validMailboxID(parts[0]) {
		writeErr(w, http.StatusBadRequest, "invalid_path")
		return
	}
	mailboxID := parts[0]

	switch {
	case len(parts) == 3 && parts[1] == "senders":
		tokenHash := parts[2]
		switch r.Method {
		case http.MethodPut:
			s.handlePutSender(w, r, mailboxID, tokenHash)
		case http.MethodDelete:
			s.handleDeleteSender(w, r, mailboxID, tokenHash)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed")
		}
	case len(parts) == 2 && parts[1] == "events":
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		s.handleEvents(w, r, mailboxID)
	case len(parts) == 2 && parts[1] == "transfers":
		switch r.Method {
		case http.MethodGet:
			s.handleListTransfers(w, r, mailboxID)
		case http.MethodPost:
			s.handleCreateTransfer(w, r, mailboxID)
		default:
			writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed")
		}
	case len(parts) == 6 && parts[1] == "transfers" && parts[3] == "chunks" && parts[5] == "upload-url":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if !relaycrypto.ValidTransferID(parts[2]) {
			writeErr(w, http.StatusBadRequest, "invalid_transfer_id")
			return
		}
		idx, ok := parseChunkIndex(parts[4])
		if !ok {
			writeErr(w, http.StatusBadRequest, "invalid_chunk_index")
			return
		}
		s.handleChunkUploadURL(w, r, mailboxID, parts[2], idx)
	case len(parts) == 6 && parts[1] == "transfers" && parts[3] == "chunks" && parts[5] == "commit":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if !relaycrypto.ValidTransferID(parts[2]) {
			writeErr(w, http.StatusBadRequest, "invalid_transfer_id")
			return
		}
		idx, ok := parseChunkIndex(parts[4])
		if !ok {
			writeErr(w, http.StatusBadRequest, "invalid_chunk_index")
			return
		}
		s.handleCommitChunk(w, r, mailboxID, parts[2], idx)
	case len(parts) == 5 && parts[1] == "transfers" && parts[3] == "chunks":
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if !relaycrypto.ValidTransferID(parts[2]) {
			writeErr(w, http.StatusBadRequest, "invalid_transfer_id")
			return
		}
		idx, ok := parseChunkIndex(parts[4])
		if !ok {
			writeErr(w, http.StatusBadRequest, "invalid_chunk_index")
			return
		}
		s.handleChunkDownloadURL(w, r, mailboxID, parts[2], idx)
	case len(parts) == 4 && parts[1] == "transfers" && parts[3] == "ack":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if !relaycrypto.ValidTransferID(parts[2]) {
			writeErr(w, http.StatusBadRequest, "invalid_transfer_id")
			return
		}
		s.handleAckTransfer(w, r, mailboxID, parts[2])
	case len(parts) == 3 && parts[1] == "transfers":
		if r.Method != http.MethodDelete {
			writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if !relaycrypto.ValidTransferID(parts[2]) {
			writeErr(w, http.StatusBadRequest, "invalid_transfer_id")
			return
		}
		s.handleDeleteTransfer(w, r, mailboxID, parts[2])
	default:
		writeErr(w, http.StatusNotFound, "not_found")
	}
}

func parseChunkIndex(raw string) (int, bool) {
	idx, err := strconv.Atoi(raw)
	if err != nil || idx < 0 || idx >= relaycrypto.MaxChunks {
		return 0, false
	}
	return idx, true
}

func ownerTimestampHeader(r *http.Request) string {
	if ts := r.Header.Get("X-Unic-Timestamp"); ts != "" {
		return ts
	}
	return r.Header.Get("X-Unic-TS")
}

func (s *Server) verifyOwner(r *http.Request, mailboxID string, body []byte) (int, error) {
	hdr := relaycrypto.OwnerAuthHeaders{
		PubKey:    r.Header.Get("X-Unic-PubKey"),
		Timestamp: ownerTimestampHeader(r),
		Nonce:     r.Header.Get("X-Unic-Nonce"),
		Sig:       r.Header.Get("X-Unic-Sig"),
	}
	if s.cfg.Authorizer != nil {
		dec := s.cfg.Authorizer.AuthorizeDevicePubKey(r.Context(), auth.Request{
			Service:  auth.ServiceHyper,
			PubKey:   hdr.PubKey,
			Subject:  mailboxID,
			ClientIP: clientIP(r),
		})
		if !dec.Allowed {
			code := dec.StatusCode
			if code == 0 {
				code = http.StatusForbidden
			}
			return code, errors.New("pubkey not allowed")
		}
	}
	now := s.cfg.Now()
	if _, err := relaycrypto.VerifyOwnerAuth(s.originFor(r), mailboxID, r.Method, r.URL.RequestURI(), body, hdr, now); err != nil {
		return http.StatusUnauthorized, err
	}
	nonceKey := mailboxID + ":" + hdr.Nonce
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.nonces {
		if !now.Before(exp) {
			delete(s.nonces, k)
		}
	}
	if _, dup := s.nonces[nonceKey]; dup {
		return http.StatusUnauthorized, errors.New("replayed nonce")
	}
	s.nonces[nonceKey] = now.Add(nonceReplayWindow)
	return http.StatusOK, nil
}

func bearerToken(r *http.Request) (string, bool) {
	authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authHdr, "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(authHdr, "Bearer "))
	if len(tok) < 16 || len(tok) > 256 {
		return "", false
	}
	return tok, true
}

func (s *Server) mailboxLocked(id string, create bool) *mailboxState {
	mb := s.mailboxes[id]
	if mb == nil && create {
		mb = &mailboxState{
			senders:   map[string]*senderRecord{},
			transfers: map[string]*storedTransfer{},
			subs:      map[*sseSubscriber]struct{}{},
		}
		s.mailboxes[id] = mb
	}
	return mb
}

func (s *Server) authorizeSenderLocked(mailboxID, token string) (*mailboxState, *senderRecord, bool) {
	mb := s.mailboxes[mailboxID]
	if mb == nil {
		return nil, nil, false
	}
	th := relaycrypto.TokenHash(token)
	rec := mb.senders[th]
	if rec == nil {
		return nil, nil, false
	}
	return mb, rec, true
}

func (s *Server) publishLocked(mb *mailboxState, evt SSEEvent) {
	mb.nextEvtID++
	evt.ID = strconv.FormatUint(mb.nextEvtID, 10)
	mb.history = append(mb.history, evt)
	if len(mb.history) > DefaultEventBuffer {
		mb.history = mb.history[len(mb.history)-DefaultEventBuffer:]
	}
	for sub := range mb.subs {
		select {
		case sub.ch <- evt:
		default:
			// Slow consumer: receiver can resync via ListTransfers.
		}
	}
}

func (s *Server) presignTTLFor(now, transferExpires time.Time) time.Duration {
	remaining := transferExpires.Sub(now)
	if remaining <= 0 {
		return time.Second
	}
	if remaining < s.cfg.PresignTTL {
		return remaining
	}
	return s.cfg.PresignTTL
}

func (s *Server) handlePutSender(w http.ResponseWriter, r *http.Request, mailboxID, tokenHash string) {
	if !validHex64(tokenHash) {
		writeErr(w, http.StatusBadRequest, "invalid_token_hash")
		return
	}
	body, err := readLimited(r.Body, 4096)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	if code, err := s.verifyOwner(r, mailboxID, body); err != nil {
		writeErr(w, code, "unauthorized")
		return
	}
	var req struct {
		MaxBytes int64 `json:"max_bytes,omitempty"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil || req.MaxBytes < 0 {
			writeErr(w, http.StatusBadRequest, "invalid_json")
			return
		}
	}
	limit := s.cfg.MaxTransferBytes
	if req.MaxBytes > 0 && req.MaxBytes < limit {
		limit = req.MaxBytes
	}

	s.mu.Lock()
	mb := s.mailboxLocked(mailboxID, true)
	if _, exists := mb.senders[tokenHash]; !exists && len(mb.senders) >= s.cfg.MaxSendersPerMailbox {
		s.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "too_many_senders")
		return
	}
	mb.senders[tokenHash] = &senderRecord{tokenHash: tokenHash, maxBytes: limit}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteSender(w http.ResponseWriter, r *http.Request, mailboxID, tokenHash string) {
	if !validHex64(tokenHash) {
		writeErr(w, http.StatusBadRequest, "invalid_token_hash")
		return
	}
	body, err := readLimited(r.Body, 1024)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	if code, err := s.verifyOwner(r, mailboxID, body); err != nil {
		writeErr(w, code, "unauthorized")
		return
	}
	s.mu.Lock()
	if mb := s.mailboxes[mailboxID]; mb != nil {
		delete(mb.senders, tokenHash)
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validateEnvelope(env relaycrypto.Envelope, maxBytes int64, now time.Time) (time.Time, int, string) {
	if env.V != relaycrypto.Version || !relaycrypto.ValidTransferID(env.TransferID) {
		return time.Time{}, http.StatusBadRequest, "invalid_envelope"
	}
	if env.TotalChunks <= 0 || env.TotalChunks > relaycrypto.MaxChunks || len(env.ChunkHashes) != env.TotalChunks {
		return time.Time{}, http.StatusBadRequest, "invalid_chunk_count"
	}
	if env.TotalCiphertextBytes <= 0 || env.TotalCiphertextBytes > maxBytes {
		return time.Time{}, http.StatusRequestEntityTooLarge, "payload_too_large"
	}
	if env.TotalChunks == 1 {
		if env.ChunkSize <= 0 || env.ChunkSize > relaycrypto.SingleChunkThreshold {
			return time.Time{}, http.StatusBadRequest, "invalid_chunk_size"
		}
	} else {
		if env.ChunkSize < relaycrypto.MinChunkSize || env.ChunkSize > relaycrypto.MaxChunkSize {
			return time.Time{}, http.StatusBadRequest, "invalid_chunk_size"
		}
	}
	for _, hs := range env.ChunkHashes {
		hb, err := base64.RawURLEncoding.DecodeString(hs)
		if err != nil || len(hb) != 32 {
			return time.Time{}, http.StatusBadRequest, "invalid_chunk_hash"
		}
	}
	exp := now.Add(s.cfg.DefaultTTL)
	if env.ExpiresMs > 0 {
		envExp := time.UnixMilli(env.ExpiresMs)
		if !now.Before(envExp) {
			return time.Time{}, http.StatusBadRequest, "expired"
		}
		if maxExp := now.Add(s.cfg.MaxTTL); envExp.After(maxExp) {
			exp = maxExp
		} else {
			exp = envExp
		}
	}
	return exp, http.StatusOK, ""
}

func (s *Server) handleCreateTransfer(w http.ResponseWriter, r *http.Request, mailboxID string) {
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	s.mu.Lock()
	_, sender, ok := s.authorizeSenderLocked(mailboxID, tok)
	if !ok {
		s.mu.Unlock()
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	maxBytes := sender.maxBytes
	senderHash := sender.tokenHash
	s.mu.Unlock()

	body, err := readLimited(r.Body, relaycrypto.MaxEnvelopeJSONBytes)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "envelope_too_large")
		return
	}
	var env relaycrypto.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_json")
		return
	}
	now := s.cfg.Now()
	exp, status, reason := s.validateEnvelope(env, maxBytes, now)
	if status != http.StatusOK {
		writeErr(w, status, reason)
		return
	}
	bm, err := relaycrypto.NewBitmap(env.TotalChunks)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_chunks")
		return
	}

	inlineCount := min(env.TotalChunks, MaxInlineUploadURLs)
	presignTTL := s.presignTTLFor(now, exp)
	grants := make([]ChunkUploadGrant, 0, inlineCount)
	for i := 0; i < inlineCount; i++ {
		key := s.store.ObjectKey(mailboxID, env.TransferID, i)
		signed, err := s.store.PresignPut(key, presignTTL, now)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "presign_error")
			return
		}
		grants = append(grants, ChunkUploadGrant{
			Index:       i,
			Method:      signed.Method,
			URL:         signed.URL,
			Headers:     signed.Headers,
			ExpiresAtMs: signed.ExpiresAtMs,
		})
	}

	s.mu.Lock()
	mb := s.mailboxes[mailboxID]
	if mb == nil || mb.senders[senderHash] == nil {
		s.mu.Unlock()
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	expired := s.sweepMailboxLocked(mailboxID, mb, now)
	if _, dup := mb.transfers[env.TransferID]; dup {
		s.mu.Unlock()
		s.deleteObjects(r.Context(), expired)
		writeErr(w, http.StatusConflict, "already_exists")
		return
	}
	if len(mb.transfers) >= s.cfg.MaxTransfersPerMailbox {
		s.mu.Unlock()
		s.deleteObjects(r.Context(), expired)
		writeErr(w, http.StatusTooManyRequests, "mailbox_full")
		return
	}
	mb.transfers[env.TransferID] = &storedTransfer{
		id:         env.TransferID,
		senderHash: senderHash,
		envelope:   env,
		chunkSizes: map[int]int64{},
		available:  bm,
		expiresAt:  exp,
	}
	envCopy := env
	s.publishLocked(mb, SSEEvent{
		Event:           "transfer_announced",
		TransferID:      env.TransferID,
		Envelope:        &envCopy,
		AvailableBitmap: relaycrypto.EncodeBitmap(bm),
		ExpiresAtMs:     exp.UnixMilli(),
	})
	s.mu.Unlock()
	s.deleteObjects(r.Context(), expired)

	writeJSON(w, http.StatusOK, map[string]any{
		"transfer_id":     env.TransferID,
		"expires_at_ms":   exp.UnixMilli(),
		"max_chunk_bytes": relaycrypto.MaxChunkSize + relaycrypto.GCMTagSize,
		"upload_mode":     "presigned",
		"upload_urls":     grants,
	})
}

func (s *Server) handleChunkUploadURL(w http.ResponseWriter, r *http.Request, mailboxID, transferID string, idx int) {
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	now := s.cfg.Now()
	s.mu.Lock()
	mb, sender, ok := s.authorizeSenderLocked(mailboxID, tok)
	if !ok {
		s.mu.Unlock()
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	expired := s.sweepMailboxLocked(mailboxID, mb, now)
	tr := mb.transfers[transferID]
	if tr == nil {
		s.mu.Unlock()
		s.deleteObjects(r.Context(), expired)
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	if tr.senderHash != sender.tokenHash {
		s.mu.Unlock()
		s.deleteObjects(r.Context(), expired)
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if idx < 0 || idx >= tr.envelope.TotalChunks {
		s.mu.Unlock()
		s.deleteObjects(r.Context(), expired)
		writeErr(w, http.StatusBadRequest, "invalid_chunk_index")
		return
	}
	expiresAt := tr.expiresAt
	s.mu.Unlock()
	s.deleteObjects(r.Context(), expired)

	key := s.store.ObjectKey(mailboxID, transferID, idx)
	signed, err := s.store.PresignPut(key, s.presignTTLFor(now, expiresAt), now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "presign_error")
		return
	}
	writeJSON(w, http.StatusOK, signed)
}

func (s *Server) handleCommitChunk(w http.ResponseWriter, r *http.Request, mailboxID, transferID string, idx int) {
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	now := s.cfg.Now()
	s.mu.Lock()
	mb, sender, ok := s.authorizeSenderLocked(mailboxID, tok)
	if !ok {
		s.mu.Unlock()
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	senderHash := sender.tokenHash
	expired := s.sweepMailboxLocked(mailboxID, mb, now)
	tr := mb.transfers[transferID]
	if tr == nil {
		s.mu.Unlock()
		s.deleteObjects(r.Context(), expired)
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	if tr.senderHash != senderHash {
		s.mu.Unlock()
		s.deleteObjects(r.Context(), expired)
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if idx < 0 || idx >= tr.envelope.TotalChunks {
		s.mu.Unlock()
		s.deleteObjects(r.Context(), expired)
		writeErr(w, http.StatusBadRequest, "invalid_chunk_index")
		return
	}
	maxChunk := int64(tr.envelope.ChunkSize) + relaycrypto.GCMTagSize
	totalChunks := tr.envelope.TotalChunks
	totalCipherBytes := tr.envelope.TotalCiphertextBytes
	s.mu.Unlock()
	s.deleteObjects(r.Context(), expired)

	key := s.store.ObjectKey(mailboxID, transferID, idx)
	meta, err := s.store.HeadObject(r.Context(), key)
	if err != nil {
		if errors.Is(err, s3store.ErrObjectNotFound) {
			writeErr(w, http.StatusNotFound, "chunk_not_uploaded")
			return
		}
		writeErr(w, http.StatusBadGateway, "storage_error")
		return
	}
	if meta.Size <= 0 || meta.Size > maxChunk || (totalChunks == 1 && meta.Size != totalCipherBytes) {
		_ = s.store.DeleteObject(r.Context(), key)
		if meta.Size > maxChunk {
			writeErr(w, http.StatusRequestEntityTooLarge, "chunk_too_large")
		} else {
			writeErr(w, http.StatusBadRequest, "size_mismatch")
		}
		return
	}

	s.mu.Lock()
	mb = s.mailboxes[mailboxID]
	if mb == nil || mb.senders[senderHash] == nil {
		s.mu.Unlock()
		_ = s.store.DeleteObject(r.Context(), key)
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	expired2 := s.sweepMailboxLocked(mailboxID, mb, s.cfg.Now())
	tr = mb.transfers[transferID]
	if tr == nil {
		s.mu.Unlock()
		s.deleteObjects(r.Context(), expired2)
		_ = s.store.DeleteObject(r.Context(), key)
		writeErr(w, http.StatusGone, "gone")
		return
	}
	tr.chunkSizes[idx] = meta.Size
	relaycrypto.SetBit(tr.available, idx)
	ci := idx
	s.publishLocked(mb, SSEEvent{
		Event:           "chunk_ready",
		TransferID:      transferID,
		ChunkIndex:      &ci,
		AvailableBitmap: relaycrypto.EncodeBitmap(tr.available),
		ExpiresAtMs:     tr.expiresAt.UnixMilli(),
	})
	s.mu.Unlock()
	s.deleteObjects(r.Context(), expired2)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListTransfers(w http.ResponseWriter, r *http.Request, mailboxID string) {
	if code, err := s.verifyOwner(r, mailboxID, nil); err != nil {
		writeErr(w, code, "unauthorized")
		return
	}
	now := s.cfg.Now()
	var expired []cleanupTarget

	s.mu.Lock()
	mb := s.mailboxes[mailboxID]
	out := []TransferSummary{}
	if mb != nil {
		expired = s.sweepMailboxLocked(mailboxID, mb, now)
		for _, tr := range mb.transfers {
			out = append(out, TransferSummary{
				TransferID:      tr.id,
				Envelope:        tr.envelope,
				AvailableBitmap: relaycrypto.EncodeBitmap(tr.available),
				ExpiresAtMs:     tr.expiresAt.UnixMilli(),
			})
		}
	}
	s.mu.Unlock()
	s.deleteObjects(r.Context(), expired)

	writeJSON(w, http.StatusOK, map[string]any{"transfers": out})
}

func (s *Server) handleChunkDownloadURL(w http.ResponseWriter, r *http.Request, mailboxID, transferID string, idx int) {
	if code, err := s.verifyOwner(r, mailboxID, nil); err != nil {
		writeErr(w, code, "unauthorized")
		return
	}
	now := s.cfg.Now()
	var expired []cleanupTarget

	s.mu.Lock()
	mb := s.mailboxes[mailboxID]
	if mb == nil {
		s.mu.Unlock()
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	expired = s.sweepMailboxLocked(mailboxID, mb, now)
	tr := mb.transfers[transferID]
	if tr == nil || idx < 0 || idx >= tr.envelope.TotalChunks || !relaycrypto.HasBit(tr.available, idx) {
		s.mu.Unlock()
		s.deleteObjects(r.Context(), expired)
		writeErr(w, http.StatusNotFound, "not_found")
		return
	}
	size := tr.chunkSizes[idx]
	expiresAt := tr.expiresAt
	s.mu.Unlock()
	s.deleteObjects(r.Context(), expired)

	key := s.store.ObjectKey(mailboxID, transferID, idx)
	signed, err := s.store.PresignGet(key, s.presignTTLFor(now, expiresAt), now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "presign_error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"method":        signed.Method,
		"url":           signed.URL,
		"expires_at_ms": signed.ExpiresAtMs,
		"size":          size,
	})
}

func (s *Server) handleAckTransfer(w http.ResponseWriter, r *http.Request, mailboxID, transferID string) {
	body, err := readLimited(r.Body, 1024)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	if code, err := s.verifyOwner(r, mailboxID, body); err != nil {
		writeErr(w, code, "unauthorized")
		return
	}
	var target *cleanupTarget
	s.mu.Lock()
	if mb := s.mailboxes[mailboxID]; mb != nil {
		if tr := mb.transfers[transferID]; tr != nil {
			target = &cleanupTarget{
				mailboxID:  mailboxID,
				transferID: transferID,
				indices:    transferIndices(tr),
			}
			delete(mb.transfers, transferID)
		}
	}
	s.mu.Unlock()
	if target != nil {
		s.deleteObjects(r.Context(), []cleanupTarget{*target})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteTransfer(w http.ResponseWriter, r *http.Request, mailboxID, transferID string) {
	if tok, ok := bearerToken(r); ok {
		var target *cleanupTarget
		s.mu.Lock()
		mb, sender, authOK := s.authorizeSenderLocked(mailboxID, tok)
		if !authOK {
			s.mu.Unlock()
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if tr := mb.transfers[transferID]; tr != nil {
			if tr.senderHash != sender.tokenHash {
				s.mu.Unlock()
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
			target = &cleanupTarget{
				mailboxID:  mailboxID,
				transferID: transferID,
				indices:    transferIndices(tr),
			}
			delete(mb.transfers, transferID)
		}
		s.mu.Unlock()
		if target != nil {
			s.deleteObjects(r.Context(), []cleanupTarget{*target})
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if code, err := s.verifyOwner(r, mailboxID, nil); err != nil {
		writeErr(w, code, "unauthorized")
		return
	}
	var target *cleanupTarget
	s.mu.Lock()
	if mb := s.mailboxes[mailboxID]; mb != nil {
		if tr := mb.transfers[transferID]; tr != nil {
			target = &cleanupTarget{
				mailboxID:  mailboxID,
				transferID: transferID,
				indices:    transferIndices(tr),
			}
			delete(mb.transfers, transferID)
		}
	}
	s.mu.Unlock()
	if target != nil {
		s.deleteObjects(r.Context(), []cleanupTarget{*target})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, mailboxID string) {
	if code, err := s.verifyOwner(r, mailboxID, nil); err != nil {
		writeErr(w, code, "unauthorized")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming_unsupported")
		return
	}
	var afterID uint64
	if raw := strings.TrimSpace(r.Header.Get("Last-Event-ID")); raw != "" {
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			afterID = parsed
		}
	}

	sub := &sseSubscriber{ch: make(chan SSEEvent, 64), done: make(chan struct{})}
	var backlog []SSEEvent

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		writeErr(w, http.StatusServiceUnavailable, "closing")
		return
	}
	mb := s.mailboxLocked(mailboxID, true)
	if afterID > 0 {
		for _, ev := range mb.history {
			if id, err := strconv.ParseUint(ev.ID, 10, 64); err == nil && id > afterID {
				backlog = append(backlog, ev)
			}
		}
	}
	mb.subs[sub] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if mb := s.mailboxes[mailboxID]; mb != nil {
			delete(mb.subs, sub)
		}
		s.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, ": connected\n\n")
	flusher.Flush()

	writeEvt := func(ev SSEEvent) bool {
		b, err := json.Marshal(ev)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", ev.ID, ev.Event, b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	for _, ev := range backlog {
		if !writeEvt(ev) {
			return
		}
	}

	ticker := time.NewTicker(s.cfg.KeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.done:
			return
		case ev := <-sub.ch:
			if !writeEvt(ev) {
				return
			}
		case <-ticker.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	lr := io.LimitReader(r, limit+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("body exceeds limit")
	}
	return b, nil
}

func validMailboxID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			return false
		}
	}
	return true
}

func validHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
