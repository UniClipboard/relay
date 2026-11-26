// SPDX-License-Identifier: AGPL-3.0-only

package relaycrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testSigner struct {
	seed []byte
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newTestSigner(t *testing.T, seedHex string) *testSigner {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &testSigner{
		seed: seed,
		priv: priv,
		pub:  priv.Public().(ed25519.PublicKey),
	}
}

func (s *testSigner) DeviceID() string { return DeviceID(s.pub) }
func (s *testSigner) Public() []byte   { return s.pub }
func (s *testSigner) RelayX25519Key() (*ecdh.PrivateKey, error) {
	return Ed25519SeedToX25519(s.seed)
}
func (s *testSigner) SignRelayEnvelope(bodyAndWrappedCEK []byte) []byte {
	return ed25519.Sign(s.priv, cat([]byte("unic/relay-envelope-sig/v1\x00"), bodyAndWrappedCEK))
}
func (s *testSigner) SignRelayAuth(authPayload []byte) []byte {
	return ed25519.Sign(s.priv, cat([]byte("unic/relay-auth/v1\x00"), authPayload))
}

type hybridVector struct {
	Version     int    `json:"version"`
	RelayOrigin string `json:"relay_origin"`
	Keys        struct {
		Sender struct {
			Seed         string `json:"seed"`
			Public       string `json:"public"`
			X25519Public string `json:"x25519_public"`
			DeviceID     string `json:"device_id"`
		} `json:"sender"`
		Recipient struct {
			Seed         string `json:"seed"`
			Public       string `json:"public"`
			X25519Public string `json:"x25519_public"`
			DeviceID     string `json:"device_id"`
			MailboxID    string `json:"mailbox_id"`
		} `json:"recipient"`
	} `json:"keys"`
	Transfer struct {
		TransferID     string   `json:"transfer_id"`
		CreatedMs      int64    `json:"created_ms"`
		ExpiresMs      int64    `json:"expires_ms"`
		CEK            string   `json:"cek"`
		EphPriv        string   `json:"eph_priv"`
		EphPub         string   `json:"eph_pub"`
		PlaintextsHex  []string `json:"plaintexts_hex"`
		CiphertextsHex []string `json:"ciphertexts_hex"`
		Envelope       Envelope `json:"envelope"`
	} `json:"transfer"`
	OwnerAuth struct {
		Method       string           `json:"method"`
		PathAndQuery string           `json:"path_and_query"`
		BodyHex      string           `json:"body_hex"`
		NowUnix      int64            `json:"now_unix"`
		Nonce        string           `json:"nonce"`
		Headers      OwnerAuthHeaders `json:"headers"`
	} `json:"owner_auth"`
}

func loadVector(t *testing.T) hybridVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "vectors", "hybrid-relay-v1.json"))
	if err != nil {
		t.Fatalf("read vector file: %v", err)
	}
	var v hybridVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal vector: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func TestDeterministicVectors(t *testing.T) {
	v := loadVector(t)
	sender := newTestSigner(t, v.Keys.Sender.Seed)
	recipient := newTestSigner(t, v.Keys.Recipient.Seed)

	if hex.EncodeToString(sender.Public()) != v.Keys.Sender.Public {
		t.Fatalf("sender pubkey mismatch")
	}
	if hex.EncodeToString(recipient.Public()) != v.Keys.Recipient.Public {
		t.Fatalf("recipient pubkey mismatch")
	}
	if sender.DeviceID() != v.Keys.Sender.DeviceID {
		t.Fatalf("sender device_id mismatch: got %s want %s", sender.DeviceID(), v.Keys.Sender.DeviceID)
	}
	if recipient.DeviceID() != v.Keys.Recipient.DeviceID {
		t.Fatalf("recipient device_id mismatch: got %s want %s", recipient.DeviceID(), v.Keys.Recipient.DeviceID)
	}

	sx, err := Ed25519PublicToX25519(sender.Public())
	if err != nil || hex.EncodeToString(sx.Bytes()) != v.Keys.Sender.X25519Public {
		t.Fatalf("sender x25519 mismatch: err=%v", err)
	}
	rx, err := Ed25519PublicToX25519(recipient.Public())
	if err != nil || hex.EncodeToString(rx.Bytes()) != v.Keys.Recipient.X25519Public {
		t.Fatalf("recipient x25519 mismatch: err=%v", err)
	}

	mailboxID, err := DeriveMailboxID(v.RelayOrigin, recipient.Public())
	if err != nil || mailboxID != v.Keys.Recipient.MailboxID {
		t.Fatalf("mailbox_id mismatch: got %s want %s err=%v", mailboxID, v.Keys.Recipient.MailboxID, err)
	}

	// Verify chunk AEAD encryption and decryption against exact vector ciphertexts.
	cek := mustHex(t, v.Transfer.CEK)
	cc, err := NewChunkCipher(cek, v.Transfer.TransferID, sender.DeviceID(), recipient.DeviceID(), len(v.Transfer.PlaintextsHex))
	if err != nil {
		t.Fatalf("NewChunkCipher: %v", err)
	}
	hashes := make([][32]byte, len(v.Transfer.PlaintextsHex))
	var totalCT int64
	for i, ptHex := range v.Transfer.PlaintextsHex {
		pt := mustHex(t, ptHex)
		ct, h, err := cc.SealChunk(i, pt)
		if err != nil {
			t.Fatalf("SealChunk(%d): %v", i, err)
		}
		if hex.EncodeToString(ct) != v.Transfer.CiphertextsHex[i] {
			t.Fatalf("chunk %d ciphertext mismatch:\ngot:  %x\nwant: %s", i, ct, v.Transfer.CiphertextsHex[i])
		}
		hashes[i] = h
		totalCT += int64(len(ct))

		opened, err := cc.OpenChunk(i, ct, h)
		if err != nil || !bytes.Equal(opened, pt) {
			t.Fatalf("OpenChunk(%d) failed: err=%v", i, err)
		}
	}

	// Verify envelope sealing matches vector byte-for-byte.
	ephPriv, err := ecdh.X25519().NewPrivateKey(mustHex(t, v.Transfer.EphPriv))
	if err != nil {
		t.Fatalf("eph priv: %v", err)
	}
	if hex.EncodeToString(ephPriv.PublicKey().Bytes()) != v.Transfer.EphPub {
		t.Fatalf("eph pub mismatch")
	}
	env, err := SealEnvelope(sender, SealEnvelopeInput{
		RelayOrigin:          v.RelayOrigin,
		TransferID:           v.Transfer.TransferID,
		RecipientPK:          recipient.Public(),
		CreatedMs:            v.Transfer.CreatedMs,
		ExpiresMs:            v.Transfer.ExpiresMs,
		ChunkSize:            v.Transfer.Envelope.ChunkSize,
		TotalChunks:          len(hashes),
		TotalCiphertextBytes: totalCT,
		ChunkHashes:          hashes,
		CEK:                  cek,
		EphemeralPriv:        ephPriv,
	})
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	if env.WrappedCEK != v.Transfer.Envelope.WrappedCEK {
		t.Fatalf("wrapped_cek mismatch:\ngot:  %s\nwant: %s", env.WrappedCEK, v.Transfer.Envelope.WrappedCEK)
	}
	if env.Sig != v.Transfer.Envelope.Sig {
		t.Fatalf("envelope sig mismatch:\ngot:  %s\nwant: %s", env.Sig, v.Transfer.Envelope.Sig)
	}
	for i := range hashes {
		if env.ChunkHashes[i] != v.Transfer.Envelope.ChunkHashes[i] {
			t.Fatalf("chunk_hash[%d] mismatch", i)
		}
	}

	// Verify envelope verification + CEK unwrapping.
	now := time.UnixMilli(v.Transfer.CreatedMs + 1000)
	ve, err := VerifyEnvelope(v.RelayOrigin, v.Transfer.Envelope, recipient.DeviceID(), sender.Public(), now)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	gotCEK, err := OpenCEK(recipient, v.RelayOrigin, ve)
	if err != nil || !bytes.Equal(gotCEK, cek) {
		t.Fatalf("OpenCEK failed: err=%v", err)
	}

	// Tampered origin must fail envelope signature verification.
	if _, err := VerifyEnvelope("https://evil.example", v.Transfer.Envelope, recipient.DeviceID(), sender.Public(), now); err == nil {
		t.Fatal("expected VerifyEnvelope to reject mismatched relay origin")
	}

	// Verify Owner Auth signing and verification against vector.
	ownerNow := time.Unix(v.OwnerAuth.NowUnix, 0)
	body := mustHex(t, v.OwnerAuth.BodyHex)
	hdrs, err := SignOwnerAuth(recipient, v.RelayOrigin, v.OwnerAuth.Method, v.OwnerAuth.PathAndQuery, body, ownerNow, v.OwnerAuth.Nonce)
	if err != nil {
		t.Fatalf("SignOwnerAuth: %v", err)
	}
	if hdrs != v.OwnerAuth.Headers {
		t.Fatalf("owner_auth headers mismatch:\ngot:  %+v\nwant: %+v", hdrs, v.OwnerAuth.Headers)
	}
	pk, err := VerifyOwnerAuth(v.RelayOrigin, mailboxID, v.OwnerAuth.Method, v.OwnerAuth.PathAndQuery, body, v.OwnerAuth.Headers, ownerNow)
	if err != nil || !bytes.Equal(pk, recipient.Public()) {
		t.Fatalf("VerifyOwnerAuth failed: err=%v", err)
	}
	if _, err := VerifyOwnerAuth(v.RelayOrigin, mailboxID, v.OwnerAuth.Method, v.OwnerAuth.PathAndQuery, []byte("tampered"), v.OwnerAuth.Headers, ownerNow); err == nil {
		t.Fatal("expected VerifyOwnerAuth to reject tampered body")
	}
}

func TestBitmapAndSingleFrame(t *testing.T) {
	bm, err := NewBitmap(10)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	SetBit(bm, 0)
	SetBit(bm, 9)
	if !HasBit(bm, 0) || HasBit(bm, 1) || !HasBit(bm, 9) {
		t.Fatal("unexpected bit state")
	}
	enc := EncodeBitmap(bm)
	dec, err := DecodeBitmap(enc, 10)
	if err != nil || !bytes.Equal(dec, bm) {
		t.Fatalf("DecodeBitmap mismatch: err=%v", err)
	}

	v := loadVector(t)
	env := v.Transfer.Envelope
	env.TotalChunks = 1
	env.ChunkHashes = env.ChunkHashes[:1]
	ct0 := mustHex(t, v.Transfer.CiphertextsHex[0])
	frame, err := EncodeSingleFrame(env, ct0)
	if err != nil {
		t.Fatalf("EncodeSingleFrame: %v", err)
	}
	gotEnv, gotCT, err := DecodeSingleFrame(frame)
	if err != nil {
		t.Fatalf("DecodeSingleFrame: %v", err)
	}
	if gotEnv.TransferID != env.TransferID || !bytes.Equal(gotCT, ct0) {
		t.Fatal("DecodeSingleFrame content mismatch")
	}
}
