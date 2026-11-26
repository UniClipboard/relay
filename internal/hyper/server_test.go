// SPDX-License-Identifier: AGPL-3.0-only

package hyper

import (
	"bufio"
	"bytes"
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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uniclipboard/relay/internal/auth"
	"github.com/uniclipboard/relay/internal/relaycrypto"
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

func TestVectorOwnerAuthAndReplayProtection(t *testing.T) {
	doc := loadVectorDoc(t)
	now := time.Unix(doc.OwnerAuth.NowUnix, 0)

	srv := New(Config{
		Origin: doc.RelayOrigin,
		Now:    func() time.Time { return now },
	})
	defer srv.Close()

	// Exact vector request must pass once.
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

	// Replaying the exact same nonce within 120s must fail with 401.
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

	allowedPK := base64.RawURLEncoding.EncodeToString(recipient.Public())
	authorizer, err := auth.NewStatic(auth.StaticConfig{
		AccessKeyBytes: []byte("shared-secret-key"),
		AllowedPubKeys: []string{allowedPK},
	})
	if err != nil {
		t.Fatalf("NewStatic: %v", err)
	}

	srv := New(Config{
		Origin:     doc.RelayOrigin,
		Authorizer: authorizer,
		Now:        func() time.Time { return now },
	})
	defer srv.Close()

	// /healthz must work without credentials.
	hRec := httptest.NewRecorder()
	srv.ServeHTTP(hRec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if hRec.Code != http.StatusOK || !strings.Contains(hRec.Body.String(), `"ok"`) {
		t.Fatalf("unexpected /healthz response: %d %s", hRec.Code, hRec.Body.String())
	}

	// API without X-Unic-Relay-Key fails with 401.
	req := httptest.NewRequest(http.MethodGet, "/v1/relay/mailboxes/"+doc.Keys.Recipient.MailboxID+"/transfers", nil)
	applyOwnerHeaders(t, req, recipient, doc.RelayOrigin, nil, now, "nonce-access-check-1")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without access key, got %d", rec.Code)
	}

	// API with valid access key and allowed pubkey succeeds.
	req.Header.Set(auth.AccessKeyHeader, "shared-secret-key")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid access key, got %d body=%s", rec.Code, rec.Body.String())
	}

	// API with valid access key but disallowed pubkey fails with 403.
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

func TestFullTransferLifecycleMemoryAndDisk(t *testing.T) {
	for _, mode := range []string{"memory", "disk"} {
		t.Run(mode, func(t *testing.T) {
			doc := loadVectorDoc(t)
			recipient := signerFromSeedHex(t, doc.Keys.Recipient.Seed)
			mailboxID := doc.Keys.Recipient.MailboxID
			origin := doc.RelayOrigin
			var nowUnix atomic.Int64
			nowUnix.Store(doc.Transfer.CreatedMs/1000 + 1)

			var store ChunkStore
			var storageDir string
			if mode == "disk" {
				storageDir = t.TempDir()
				ds, err := NewDiskChunkStore(storageDir)
				if err != nil {
					t.Fatalf("NewDiskChunkStore: %v", err)
				}
				store = ds
			} else {
				store = NewMemoryChunkStore()
			}

			srv := New(Config{
				Origin:            origin,
				Store:             store,
				KeepaliveInterval: 50 * time.Millisecond,
				Now:               func() time.Time { return time.Unix(nowUnix.Load(), 0) },
			})
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
			line, _ := sseReader.ReadString('\n')
			if !strings.HasPrefix(line, ": connected") {
				t.Fatalf("expected : connected, got %q", line)
			}

			// 3. Multi-chunk create + upload chunks from deterministic vector.
			envJSON, _ := json.Marshal(doc.Transfer.Envelope)
			createReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers", bytes.NewReader(envJSON))
			createReq.Header.Set("Authorization", "Bearer "+token)
			createResp, err := client.Do(createReq)
			if err != nil || createResp.StatusCode != http.StatusOK {
				t.Fatalf("POST transfer failed: err=%v status=%v", err, createResp.StatusCode)
			}
			_ = createResp.Body.Close()

			for i, ctHex := range doc.Transfer.CiphertextsHex {
				ct, _ := hex.DecodeString(ctHex)
				upReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers/"+doc.Transfer.TransferID+"/chunks/"+string(rune('0'+i)), bytes.NewReader(ct))
				upReq.Header.Set("Authorization", "Bearer "+token)
				upResp, err := client.Do(upReq)
				if err != nil || upResp.StatusCode != http.StatusNoContent {
					t.Fatalf("PUT chunk %d failed: err=%v status=%v", i, err, upResp.StatusCode)
				}
				_ = upResp.Body.Close()
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
					if err := json.Unmarshal([]byte(strings.TrimPrefix(l, "data: ")), &ev); err != nil {
						t.Fatalf("unmarshal SSE: %v", err)
					}
					events = append(events, ev)
				}
			}
			if events[0].Event != "transfer_announced" || events[1].Event != "chunk_ready" || events[2].Event != "chunk_ready" {
				t.Fatalf("unexpected SSE event sequence: %+v", events)
			}

			// 4. Test Last-Event-ID replay.
			replayReq, _ := http.NewRequest(http.MethodGet, ts.URL+ssePath, nil)
			replayReq.Header.Set("Last-Event-ID", events[0].ID)
			applyOwnerHeaders(t, replayReq, recipient, origin, nil, time.Unix(nowUnix.Load(), 0), "nonce-sse-replay")
			replayResp, err := client.Do(replayReq)
			if err != nil || replayResp.StatusCode != http.StatusOK {
				t.Fatalf("SSE replay failed: err=%v status=%v", err, replayResp.StatusCode)
			}
			repReader := bufio.NewReader(replayResp.Body)
			var replayed []SSEEvent
			for len(replayed) < 2 {
				l, err := repReader.ReadString('\n')
				if err != nil {
					t.Fatalf("read replay SSE: %v", err)
				}
				if strings.HasPrefix(l, "data: ") {
					var ev SSEEvent
					_ = json.Unmarshal([]byte(strings.TrimPrefix(l, "data: ")), &ev)
					replayed = append(replayed, ev)
				}
			}
			_ = replayResp.Body.Close()
			if replayed[0].ID != events[1].ID || replayed[1].ID != events[2].ID {
				t.Fatalf("unexpected replayed IDs: %+v", replayed)
			}

			// 5. List transfers and download chunks.
			listReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers", nil)
			applyOwnerHeaders(t, listReq, recipient, origin, nil, time.Unix(nowUnix.Load(), 0), "nonce-list")
			listResp, err := client.Do(listReq)
			if err != nil || listResp.StatusCode != http.StatusOK {
				t.Fatalf("GET transfers failed: err=%v", err)
			}
			var listed struct {
				Transfers []TransferSummary `json:"transfers"`
			}
			_ = json.NewDecoder(listResp.Body).Decode(&listed)
			_ = listResp.Body.Close()
			if len(listed.Transfers) != 1 || listed.Transfers[0].TransferID != doc.Transfer.TransferID {
				t.Fatalf("unexpected listed transfers: %+v", listed.Transfers)
			}

			for i, ctHex := range doc.Transfer.CiphertextsHex {
				wantCT, _ := hex.DecodeString(ctHex)
				dlReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers/"+doc.Transfer.TransferID+"/chunks/"+string(rune('0'+i)), nil)
				applyOwnerHeaders(t, dlReq, recipient, origin, nil, time.Unix(nowUnix.Load(), 0), "nonce-dl-"+string(rune('0'+i)))
				dlResp, err := client.Do(dlReq)
				if err != nil || dlResp.StatusCode != http.StatusOK {
					t.Fatalf("GET chunk %d failed: err=%v status=%v", i, err, dlResp.StatusCode)
				}
				gotCT, _ := io.ReadAll(dlResp.Body)
				_ = dlResp.Body.Close()
				if !bytes.Equal(gotCT, wantCT) {
					t.Fatalf("chunk %d content mismatch", i)
				}
			}

			// 6. ACK deletes metadata and chunks immediately (including disk files).
			ackReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers/"+doc.Transfer.TransferID+"/ack", nil)
			applyOwnerHeaders(t, ackReq, recipient, origin, nil, time.Unix(nowUnix.Load(), 0), "nonce-ack")
			ackResp, err := client.Do(ackReq)
			if err != nil || ackResp.StatusCode != http.StatusNoContent {
				t.Fatalf("POST ack failed: err=%v status=%v", err, ackResp.StatusCode)
			}
			_ = ackResp.Body.Close()
			if srv.ActiveTransferCount() != 0 {
				t.Fatalf("expected 0 active transfers after ack")
			}
			if mode == "disk" {
				transferDir := filepath.Join(storageDir, "chunks", mailboxID, doc.Transfer.TransferID)
				if _, err := os.Stat(transferDir); !os.IsNotExist(err) {
					t.Fatalf("expected disk transfer dir to be deleted after ack")
				}
			}

			// 7. Single-chunk fast path + TTL sweep cleanup.
			ct0, _ := hex.DecodeString(doc.Transfer.CiphertextsHex[0])
			singleEnv := doc.Transfer.Envelope
			singleEnv.TransferID = "fedcba9876543210fedcba9876543210"
			singleEnv.TotalChunks = 1
			singleEnv.ChunkSize = len(ct0)
			singleEnv.TotalCiphertextBytes = int64(len(ct0))
			singleEnv.ChunkHashes = singleEnv.ChunkHashes[:1]
			frame, err := relaycrypto.EncodeSingleFrame(singleEnv, ct0)
			if err != nil {
				t.Fatalf("EncodeSingleFrame: %v", err)
			}
			sReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/relay/mailboxes/"+mailboxID+"/transfers/"+singleEnv.TransferID+"/single", bytes.NewReader(frame))
			sReq.Header.Set("Authorization", "Bearer "+token)
			sResp, err := client.Do(sReq)
			if err != nil || sResp.StatusCode != http.StatusOK {
				t.Fatalf("PUT single failed: err=%v status=%v", err, sResp.StatusCode)
			}
			_ = sResp.Body.Close()
			if srv.ActiveTransferCount() != 1 {
				t.Fatalf("expected 1 active transfer after single PUT")
			}

			// Advance clock beyond expires_ms and sweep.
			nowUnix.Store(doc.Transfer.ExpiresMs/1000 + 5)
			srv.Sweep()
			if srv.ActiveTransferCount() != 0 {
				t.Fatalf("expected 0 active transfers after TTL sweep")
			}
		})
	}
}
