// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from "vitest";
import vector from "../../../vectors/hybrid-relay-v1.json";
import {
  base64UrlDecode,
  base64UrlEncode,
  bytesToHex,
  concatBytes,
  decodeBitmap,
  decodeSingleFrame,
  deriveDeviceId,
  deriveMailboxId,
  encodeBitmap,
  encodeSingleFrame,
  hexToBytes,
  lengthPrefixedField,
  newBitmap,
  normalizeRelayOrigin,
  ownerAuthPayload,
  setBit,
  hasBit,
  sha256,
  utf8Bytes,
  verifyOwnerAuth,
} from "../src/crypto";

describe("Hybrid Relay v1 Deterministic Vectors (cross-language parity with Go)", () => {
  it("derives exact device IDs and mailbox_id from vector Ed25519 keys", async () => {
    const senderPk = hexToBytes(vector.keys.sender.public);
    const recipientPk = hexToBytes(vector.keys.recipient.public);

    expect(await deriveDeviceId(senderPk)).toBe(vector.keys.sender.device_id);
    expect(await deriveDeviceId(recipientPk)).toBe(vector.keys.recipient.device_id);

    const mailboxId = await deriveMailboxId(vector.relay_origin, recipientPk);
    expect(mailboxId).toBe(vector.keys.recipient.mailbox_id);
    expect(normalizeRelayOrigin("HTTPS://RELAY.UNICLIPBOARD.APP:443/")).toBe(vector.relay_origin);
  });

  it("verifies deterministic chunk hashes, AES-GCM chunk decryption, and Ed25519 envelope signature", async () => {
    const senderPk = hexToBytes(vector.keys.sender.public);
    const cek = hexToBytes(vector.transfer.cek);

    // Verify chunk_hashes match SHA-256(ciphertext)
    const rawChunkHashes: Uint8Array[] = [];
    for (let i = 0; i < vector.transfer.ciphertexts_hex.length; i++) {
      const ct = hexToBytes(vector.transfer.ciphertexts_hex[i]);
      const digest = await sha256(ct);
      expect(base64UrlEncode(digest)).toBe(vector.transfer.envelope.chunk_hashes[i]);
      rawChunkHashes.push(digest);
    }

    // Verify HKDF + AES-256-GCM decryption of every vector chunk matches exact plaintexts
    const salt = await sha256(
      concatBytes(utf8Bytes("unic/relay-chunk-salt/v1\0"), lengthPrefixedField(utf8Bytes(vector.transfer.transfer_id)))
    );
    const ikm = await crypto.subtle.importKey("raw", cek, "HKDF", false, ["deriveBits"]);
    const chunkKeyBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: utf8Bytes("unic/relay-chunk-key/v1\0") },
      ikm,
      256
    );
    const noncePrefixBits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: utf8Bytes("unic/relay-chunk-nonce/v1\0") },
      ikm,
      64
    );
    const aesKey = await crypto.subtle.importKey("raw", chunkKeyBits, "AES-GCM", false, ["decrypt"]);
    const noncePrefix = new Uint8Array(noncePrefixBits);

    for (let i = 0; i < vector.transfer.ciphertexts_hex.length; i++) {
      const ct = hexToBytes(vector.transfer.ciphertexts_hex[i]);
      const nonce = new Uint8Array(12);
      nonce.set(noncePrefix, 0);
      new DataView(nonce.buffer).setUint32(8, i, false);

      const idxBuf = new Uint8Array(9);
      const idxView = new DataView(idxBuf.buffer);
      idxView.setUint32(0, i, false);
      idxView.setUint32(4, vector.transfer.ciphertexts_hex.length, false);
      idxBuf[8] = i === vector.transfer.ciphertexts_hex.length - 1 ? 1 : 0;

      const aad = concatBytes(
        utf8Bytes("unic/relay-chunk-aad/v1\0"),
        lengthPrefixedField(utf8Bytes(vector.transfer.transfer_id)),
        lengthPrefixedField(utf8Bytes(vector.keys.sender.device_id)),
        lengthPrefixedField(utf8Bytes(vector.keys.recipient.device_id)),
        idxBuf
      );

      const pt = new Uint8Array(
        await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, aesKey, ct)
      );
      expect(bytesToHex(pt)).toBe(vector.transfer.plaintexts_hex[i]);
    }

    // Verify canonical outer envelope Ed25519 signature
    const env = vector.transfer.envelope;
    const hashesRoot = await sha256(concatBytes(...rawChunkHashes));
    const nums = new Uint8Array(32);
    const nv = new DataView(nums.buffer);
    nv.setBigUint64(0, BigInt(env.created_ms), false);
    nv.setBigUint64(8, BigInt(env.expires_ms), false);
    nv.setUint32(16, env.chunk_size, false);
    nv.setUint32(20, env.total_chunks, false);
    nv.setBigUint64(24, BigInt(env.total_ciphertext_bytes), false);

    const ephPub = base64UrlDecode(env.eph_pub)!;
    const wrappedCek = base64UrlDecode(env.wrapped_cek)!;
    const sig = base64UrlDecode(env.sig)!;

    const body = concatBytes(
      utf8Bytes("unic/relay-envelope/v1\0"),
      lengthPrefixedField(utf8Bytes(vector.relay_origin)),
      new Uint8Array([env.v]),
      lengthPrefixedField(utf8Bytes(env.transfer_id)),
      lengthPrefixedField(utf8Bytes(env.sender_id)),
      lengthPrefixedField(utf8Bytes(env.recipient_id)),
      nums,
      ephPub,
      hashesRoot
    );
    const signedMsg = concatBytes(utf8Bytes("unic/relay-envelope-sig/v1\0"), body, wrappedCek);
    const edKey = await crypto.subtle.importKey("raw", senderPk, { name: "Ed25519" }, false, ["verify"]);
    expect(await crypto.subtle.verify("Ed25519", edKey, sig, signedMsg)).toBe(true);
  });

  it("verifies deterministic Owner Auth headers and rejects tampered body/origin/timestamp", async () => {
    const body = hexToBytes(vector.owner_auth.body_hex);
    const hdr = {
      pubKey: vector.owner_auth.headers.PubKey,
      timestamp: vector.owner_auth.headers.Timestamp,
      nonce: vector.owner_auth.headers.Nonce,
      sig: vector.owner_auth.headers.Sig,
    };

    const pk = await verifyOwnerAuth(
      vector.relay_origin,
      vector.keys.recipient.mailbox_id,
      vector.owner_auth.method,
      vector.owner_auth.path_and_query,
      body,
      hdr,
      vector.owner_auth.now_unix * 1000
    );
    expect(pk).not.toBeNull();
    expect(bytesToHex(pk!)).toBe(vector.keys.recipient.public);

    // Tampered body must fail.
    expect(
      await verifyOwnerAuth(
        vector.relay_origin,
        vector.keys.recipient.mailbox_id,
        vector.owner_auth.method,
        vector.owner_auth.path_and_query,
        utf8Bytes("tampered"),
        hdr,
        vector.owner_auth.now_unix * 1000
      )
    ).toBeNull();

    // Tampered origin must fail.
    expect(
      await verifyOwnerAuth(
        "https://evil.example",
        vector.keys.recipient.mailbox_id,
        vector.owner_auth.method,
        vector.owner_auth.path_and_query,
        body,
        hdr,
        vector.owner_auth.now_unix * 1000
      )
    ).toBeNull();

    // Timestamp skew > 60s must fail.
    expect(
      await verifyOwnerAuth(
        vector.relay_origin,
        vector.keys.recipient.mailbox_id,
        vector.owner_auth.method,
        vector.owner_auth.path_and_query,
        body,
        hdr,
        (vector.owner_auth.now_unix + 61) * 1000
      )
    ).toBeNull();

    // Payload builder sanity check.
    const payload = ownerAuthPayload(
      vector.relay_origin,
      vector.owner_auth.method,
      vector.owner_auth.path_and_query,
      hdr.timestamp,
      hdr.nonce,
      await sha256(body)
    );
    expect(payload).not.toBeNull();
  });

  it("round-trips LSB-first bitmaps and single-chunk binary frames", () => {
    const bm = newBitmap(10);
    setBit(bm, 0);
    setBit(bm, 9);
    expect(hasBit(bm, 0)).toBe(true);
    expect(hasBit(bm, 1)).toBe(false);
    expect(hasBit(bm, 9)).toBe(true);

    const decoded = decodeBitmap(encodeBitmap(bm), 10);
    expect(decoded).toEqual(bm);

    const ct0 = hexToBytes(vector.transfer.ciphertexts_hex[0]);
    const singleEnv = {
      ...vector.transfer.envelope,
      total_chunks: 1,
      chunk_hashes: [vector.transfer.envelope.chunk_hashes[0]],
    };
    const frame = encodeSingleFrame(singleEnv, ct0);
    const unpacked = decodeSingleFrame(frame);
    expect(unpacked).not.toBeNull();
    expect(unpacked!.envelope.transfer_id).toBe(singleEnv.transfer_id);
    expect(unpacked!.ciphertext).toEqual(ct0);
  });
});
