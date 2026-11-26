// SPDX-License-Identifier: AGPL-3.0-only

package hyper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uniclipboard/relay/internal/auth"
	"github.com/uniclipboard/relay/internal/relaycrypto"
	"github.com/uniclipboard/relay/internal/s3store"
)

type vecSigner struct {
	seed []byte
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func signerFromSeedHex(t *testing.T, seedHex string) *vecSigner {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &vecSigner{
		seed: seed,
		priv: priv,
		pub:  priv.Public().(ed25519.PublicKey),
	}
}

func (s *vecSigner) DeviceID() string { return relaycrypto.DeviceID(s.pub) }
func (s *vecSigner) Public() []byte   { return s.pub }
func (s *vecSigner) RelayX25519Key() (*ecdh.PrivateKey, error) {
	return relaycrypto.Ed25519SeedToX25519(s.seed)
}
func (s *vecSigner) SignRelayEnvelope(b []byte) []byte {
	msg := append([]byte("unic/relay-envelope-sig/v1\x00"), b...)
	return ed25519.Sign(s.priv, msg)
}
func (s *vecSigner) SignRelayAuth(b []byte) []byte {
	msg := append([]byte("unic/relay-auth/v1\x00"), b...)
	return ed25519.Sign(s.priv, msg)
}

type vectorDoc struct {
	RelayOrigin string `json:"relay_origin"`
	Keys        struct {
		Sender struct {
			Seed string `json:"seed"`
		} `json:"sender"`
		Recipient struct {
			Seed      string `json:"seed"`
			MailboxID string `json:"mailbox_id"`
		} `json:"recipient"`
	} `json:"keys"`
	Transfer struct {
		TransferID     string               `json:"transfer_id"`
		CreatedMs      int64                `json:"created_ms"`
		ExpiresMs      int64                `json:"expires_ms"`
		CiphertextsHex []string             `json:"ciphertexts_hex"`
		Envelope       relaycrypto.Envelope `json:"envelope"`
	} `json:"transfer"`
	OwnerAuth struct {
		Method       string                       `json:"method"`
		PathAndQuery string                       `json:"path_and_query"`
		NowUnix      int64                        `json:"now_unix"`
		Headers      relaycrypto.OwnerAuthHeaders `json:"headers"`
	} `json:"owner_auth"`
}

func loadVectorDoc(t *testing.T) vectorDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "vectors", "hybrid-relay-v1.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var doc vectorDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return doc
}

func applyOwnerHeaders(t *testing.T, req *http.Request, owner relaycrypto.Signer, origin string, body []byte, now time.Time, nonce string) {
	t.Helper()
	hdrs, err := relaycrypto.SignOwnerAuth(owner, origin, req.Method, req.URL.RequestURI(), body, now, nonce)
	if err != nil {
		t.Fatalf("SignOwnerAuth: %v", err)
	}
	req.Header.Set("X-Unic-PubKey", hdrs.PubKey)
	req.Header.Set("X-Unic-Timestamp", hdrs.Timestamp)
	req.Header.Set("X-Unic-Nonce", hdrs.Nonce)
	req.Header.Set("X-Unic-Sig", hdrs.Sig)
}

type mockS3Harness struct {
	srv     *httptest.Server
	store   *s3store.Client
	mu      sync.Mutex
	objects map[string][]byte
}

func newMockS3(t *testing.T) *mockS3Harness {
	t.Helper()
	h := &mockS3Harness{objects: map[string][]byte{}}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			if r.URL.Query().Get("X-Amz-Signature") == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			body, _ := io.ReadAll(r.Body)
			h.mu.Lock()
			h.objects[r.URL.Path] = body
			h.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case http.MethodHead:
			if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			h.mu.Lock()
			b, ok := h.objects[r.URL.Path]
			h.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			if r.URL.Query().Get("X-Amz-Signature") == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			h.mu.Lock()
			b, ok := h.objects[r.URL.Path]
			h.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
		case http.MethodDelete:
			if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			h.mu.Lock()
			delete(h.objects, r.URL.Path)
			h.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(h.srv.Close)

	store, err := s3store.New(s3store.Config{
		Endpoint:        h.srv.URL,
		Region:          "ap-guangzhou",
		Bucket:          "unic-test-bucket",
		AccessKeyID:     "AKTEST",
		SecretAccessKey: "SKTEST",
		ForcePathStyle:  true,
		HTTPClient:      h.srv.Client(),
	})
	if err != nil {
		t.Fatalf("s3store.New: %v", err)
	}
	h.store = store
	return h
}

func (h *mockS3Harness) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.objects)
}

func TestVectorOwnerAuthAndReplayProtection(t *testing.T) {
	doc := loadVectorDoc(t)
	now := time.Unix(doc.OwnerAuth.NowUnix, 0)
	s3 := newMockS3(t)

	srv, err := New(Config{
		Origin:      doc.RelayOrigin,
		ObjectStore: s3.store,
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	req := httptest.NewRequest(doc.OwnerAuth.Method, doc.OwnerAuth.PathAndQuery, nil)
	req.Header.Set("X-Unic-PubKey", doc.OwnerAuth.Headers.PubKey)
	req.Header.Set("X-Unic-Timestamp", doc.OwnerAuth.Headers.Timestamp)
	req.Header.Set("X-Unic-Nonce", doc.OwnerAuth.Headers.Nonce)
	req.Header.Set("X-Unic-Sig", doc.OwnerAuth.Headers.Sig)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("vector owner auth failed: status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req.Clone(req.Context()))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected replay rejection 401, got %d", rec2.Code)
	}
}

func TestHealthzAndSharedAccessControl(t *testing.T) {
	doc := loadVectorDoc(t)
	recipient := signerFromSeedHex(t, doc.Keys.Recipient.Seed)
	other := signerFromSeedHex(t, doc.Keys.Sender.Seed)
	now := time.Unix(doc.OwnerAuth.NowUnix, 0)
	s3 := newMockS3(t)

	allowedPK := base64.RawURLEncoding.EncodeToString(recipient.Public())
	authorizer, err := auth.NewStatic(auth.StaticConfig{
		AccessKeyBytes: []byte("shared-secret-key"),
		AllowedPubKeys: []string{allowedPK},
	})
	if err != nil {
		t.Fatalf("NewStatic: %v", err)
	}

	srv, err := New(Config{
		Origin:      doc.RelayOrigin,
		Authorizer:  authorizer,
		ObjectStore: s3.store,
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	hRec := httptest.NewRecorder()
	srv.ServeHTTP(hRec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if hRec.Code != http.StatusOK || !strings.Contains(hRec.Body.String(), `"s3-direct"`) {
		t.Fatalf("unexpected /healthz response: %d %s", hRec.Code, hRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/relay/mailboxes/"+doc.Keys.Recipient.MailboxID+"/transfers", nil)
	applyOwnerHeaders(t, req, recipient, doc.RelayOrigin, nil, now, "nonce-access-check-1")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without access key, got %d", rec.Code)
	}

	req.Header.Set(auth.AccessKeyHeader, "shared-secret-key")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid access key, got %d body=%s", rec.Code, rec.Body.String())
	}

	otherMailbox, _ := relaycrypto.DeriveMailboxID(doc.RelayOrigin, other.Public())
	otherReq := httptest.NewRequest(http.MethodGet, "/v1/relay/mailboxes/"+otherMailbox+"/transfers", nil)
	otherReq.Header.Set(auth.AccessKeyHeader, "shared-secret-key")
	applyOwnerHeaders(t, otherReq, other, doc.RelayOrigin, nil, now, "nonce-access-check-2")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, otherReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed pubkey, got %d", rec.Code)
	}
}

func TestDirectS3TransferLifecycleAndTTLSweep(t *testing.T) {
	doc := loadVectorDoc(t)
	recipient := signerFromSeedHex(t, doc.Keys.Recipient.Seed)
	mailboxID := doc.Keys.Recipient.MailboxID
	origin := doc.RelayOrigin
	var nowUnix atomic.Int64
	nowUnix.Store(doc.Transfer.CreatedMs/1000 + 1)

	s3 := newMockS3(t)
	srv, err := New(Config{
		Origin:            origin,
		ObjectStore:       s3.store,
		KeepaliveInterval: 50 * time.Millisecond,
		Now:               func() time.Time { return time.Unix(nowUnix.Load(), 0) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	ts := httptest.NewServer(srv)
	defer ts.Close()
	client := ts.Client()

	token, err := relaycrypto.NewDeliveryToken()
	if err != nil {
		t.Fatalf("NewDeliveryToken: %v", err)
	}
	tokenHash := relaycrypto.TokenHash(token)

	// 1. Register sender token hash.
	putSenderPath := "/v1/relay/mailboxes/" + mailboxID + "/senders/" + tokenHash
	putBody := []byte(`{"max_bytes":10485760}`)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+putSenderPath, bytes.NewReader(putBody))
	applyOwnerHeaders(t, req, recipient, origin, putBody, time.Unix(nowUnix.Load(), 0), "nonce-put-sender")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT sender failed: err=%v status=%v", err, resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 2. Open SSE stream.
	ssePath := "/v1/relay/mailboxes/" + mailboxID + "/events"
	sseReq, _ := http.NewRequest(http.MethodGet, ts.URL+ssePath, nil)
	applyOwnerHeaders(t, sseReq, recipient, origin, nil, time.Unix(nowUnix.Load(), 0), "nonce-sse-1")
	sseResp, err := client.Do(sseReq)
	if err != nil || sseResp.StatusCode != http.StatusOK {
		t.Fatalf("SSE open failed: err=%v status=%v", err, sseResp.StatusCode)
	}
	defer sseResp.Body.Close()
	sseReader := bufio.NewReader(sseResp.Body)
	if line, _ := sseReader.ReadString('\n'); !strings.HasPrefix(line, ": connected") {
		t.Fatalf("expected : connected, got %q", line)
	}

	// 3. Create transfer -> relay returns inline presigned PUT URLs.
	envJSON, _ := json.Marshal(doc.Transfer.Envelope)
	createReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers", bytes.NewReader(envJSON))
	createReq.Header.Set("Authorization", "Bearer "+token)
	createResp, err := client.Do(createReq)
	if err != nil || createResp.StatusCode != http.StatusOK {
		t.Fatalf("POST transfer failed: err=%v status=%v", err, createResp.StatusCode)
	}
	var created struct {
		TransferID string             `json:"transfer_id"`
		UploadMode string             `json:"upload_mode"`
		UploadURLs []ChunkUploadGrant `json:"upload_urls"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)
	_ = createResp.Body.Close()
	if created.UploadMode != "presigned" || len(created.UploadURLs) != 2 {
		t.Fatalf("unexpected create response: %+v", created)
	}

	// 4. Upload chunk 0 directly to mock S3 using inline URL, and chunk 1 using refreshed upload-url endpoint.
	for i, ctHex := range doc.Transfer.CiphertextsHex {
		ct, _ := hex.DecodeString(ctHex)
		uploadURL := created.UploadURLs[i].URL
		if i == 1 {
			urlReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers/"+doc.Transfer.TransferID+"/chunks/1/upload-url", nil)
			urlReq.Header.Set("Authorization", "Bearer "+token)
			urlResp, err := client.Do(urlReq)
			if err != nil || urlResp.StatusCode != http.StatusOK {
				t.Fatalf("POST upload-url failed: err=%v", err)
			}
			var grant s3store.PresignedURL
			_ = json.NewDecoder(urlResp.Body).Decode(&grant)
			_ = urlResp.Body.Close()
			uploadURL = grant.URL
		}

		// Direct PUT to S3 (no relay auth headers!).
		s3PutReq, _ := http.NewRequest(http.MethodPut, uploadURL, bytes.NewReader(ct))
		s3PutResp, err := s3.srv.Client().Do(s3PutReq)
		if err != nil || s3PutResp.StatusCode != http.StatusOK {
			t.Fatalf("direct S3 PUT chunk %d failed: err=%v status=%v", i, err, s3PutResp)
		}
		_ = s3PutResp.Body.Close()

		// Commit chunk to relay.
		commitReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers/"+doc.Transfer.TransferID+"/chunks/"+strconv.Itoa(i)+"/commit", nil)
		commitReq.Header.Set("Authorization", "Bearer "+token)
		commitResp, err := client.Do(commitReq)
		if err != nil || commitResp.StatusCode != http.StatusNoContent {
			t.Fatalf("POST commit chunk %d failed: err=%v status=%v", i, err, commitResp.StatusCode)
		}
		_ = commitResp.Body.Close()
	}

	if s3.count() != 2 {
		t.Fatalf("expected 2 objects in S3, got %d", s3.count())
	}

	// Read 3 SSE events (transfer_announced + 2 chunk_ready).
	var events []SSEEvent
	for len(events) < 3 {
		l, err := sseReader.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE: %v", err)
		}
		if strings.HasPrefix(l, "data: ") {
			var ev SSEEvent
			_ = json.Unmarshal([]byte(strings.TrimPrefix(l, "data: ")), &ev)
			events = append(events, ev)
		}
	}
	if events[0].Event != "transfer_announced" || events[1].Event != "chunk_ready" || events[2].Event != "chunk_ready" {
		t.Fatalf("unexpected SSE sequence: %+v", events)
	}

	// 5. Receiver obtains presigned GET URLs and downloads directly from S3.
	for i, ctHex := range doc.Transfer.CiphertextsHex {
		wantCT, _ := hex.DecodeString(ctHex)
		dlReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers/"+doc.Transfer.TransferID+"/chunks/"+strconv.Itoa(i), nil)
		applyOwnerHeaders(t, dlReq, recipient, origin, nil, time.Unix(nowUnix.Load(), 0), "nonce-dl-"+strconv.Itoa(i))
		dlResp, err := client.Do(dlReq)
		if err != nil || dlResp.StatusCode != http.StatusOK {
			t.Fatalf("GET chunk download URL %d failed: err=%v status=%v", i, err, dlResp.StatusCode)
		}
		var grant struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Size   int64  `json:"size"`
		}
		_ = json.NewDecoder(dlResp.Body).Decode(&grant)
		_ = dlResp.Body.Close()
		if grant.Method != http.MethodGet || grant.Size != int64(len(wantCT)) {
			t.Fatalf("unexpected download grant: %+v", grant)
		}

		s3GetResp, err := s3.srv.Client().Get(grant.URL)
		if err != nil || s3GetResp.StatusCode != http.StatusOK {
			t.Fatalf("direct S3 GET %d failed: err=%v", i, err)
		}
		gotCT, _ := io.ReadAll(s3GetResp.Body)
		_ = s3GetResp.Body.Close()
		if !bytes.Equal(gotCT, wantCT) {
			t.Fatalf("chunk %d content mismatch", i)
		}
	}

	// 6. ACK deletes metadata and purges both S3 objects immediately.
	ackReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers/"+doc.Transfer.TransferID+"/ack", nil)
	applyOwnerHeaders(t, ackReq, recipient, origin, nil, time.Unix(nowUnix.Load(), 0), "nonce-ack")
	ackResp, err := client.Do(ackReq)
	if err != nil || ackResp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST ack failed: err=%v status=%v", err, ackResp.StatusCode)
	}
	_ = ackResp.Body.Close()
	if srv.ActiveTransferCount() != 0 || s3.count() != 0 {
		t.Fatalf("expected 0 transfers and 0 S3 objects after ACK, got transfers=%d objects=%d", srv.ActiveTransferCount(), s3.count())
	}

	// 7. Create another transfer, upload to S3, then expire via TTL Sweep and verify S3 cleanup.
	expEnv := doc.Transfer.Envelope
	expEnv.TransferID = "fedcba9876543210fedcba9876543210"
	expEnv.TotalChunks = 1
	ct0, _ := hex.DecodeString(doc.Transfer.CiphertextsHex[0])
	expEnv.ChunkSize = len(ct0)
	expEnv.TotalCiphertextBytes = int64(len(ct0))
	expEnv.ChunkHashes = expEnv.ChunkHashes[:1]
	expJSON, _ := json.Marshal(expEnv)

	c2Req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers", bytes.NewReader(expJSON))
	c2Req.Header.Set("Authorization", "Bearer "+token)
	c2Resp, err := client.Do(c2Req)
	if err != nil || c2Resp.StatusCode != http.StatusOK {
		t.Fatalf("POST second transfer failed: err=%v", err)
	}
	var c2 struct {
		UploadURLs []ChunkUploadGrant `json:"upload_urls"`
	}
	_ = json.NewDecoder(c2Resp.Body).Decode(&c2)
	_ = c2Resp.Body.Close()

	s3Put, _ := http.NewRequest(http.MethodPut, c2.UploadURLs[0].URL, bytes.NewReader(ct0))
	rPut, _ := s3.srv.Client().Do(s3Put)
	_ = rPut.Body.Close()
	if s3.count() != 1 {
		t.Fatalf("expected 1 S3 object before sweep")
	}

	nowUnix.Store(doc.Transfer.ExpiresMs/1000 + 10)
	srv.Sweep(context.Background())
	if srv.ActiveTransferCount() != 0 || s3.count() != 0 {
		t.Fatalf("expected 0 transfers and 0 S3 objects after TTL sweep, got transfers=%d objects=%d", srv.ActiveTransferCount(), s3.count())
	}
}
