// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Zero-knowledge Relay HTTP API v1 cryptographic primitives for Cloudflare Workers.
 * Wire-compatible with Go `internal/relaycrypto` and `vectors/hybrid-relay-v1.json`.
 */

export const VERSION = 1;
export const SINGLE_CHUNK_THRESHOLD = 2 * 1024 * 1024; // 2 MiB
export const DEFAULT_CHUNK_SIZE = 1 * 1024 * 1024; // 1 MiB
export const MIN_CHUNK_SIZE = 256 * 1024; // 256 KiB
export const MAX_CHUNK_SIZE = 4 * 1024 * 1024; // 4 MiB
export const MAX_CHUNKS = 4096;
export const MAX_ENVELOPE_JSON_BYTES = 256 * 1024; // 256 KiB
export const GCM_TAG_SIZE = 16;
export const OWNER_AUTH_MAX_SKEW_SEC = 60;
export const NONCE_REPLAY_WINDOW_MS = 120_000;

export interface Envelope {
  v: number;
  transfer_id: string;
  sender_id: string;
  recipient_id: string;
  created_ms: number;
  expires_ms: number;
  chunk_size: number;
  total_chunks: number;
  total_ciphertext_bytes: number;
  eph_pub: string;
  wrapped_cek: string;
  chunk_hashes: string[];
  sig: string;
}

export interface OwnerAuthHeaders {
  pubKey: string;
  timestamp: string;
  nonce: string;
  sig: string;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

export function utf8Bytes(s: string): Uint8Array {
  return textEncoder.encode(s);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function lengthPrefixedField(data: Uint8Array): Uint8Array {
  if (data.length > 0xffff) {
    throw new Error("field exceeds uint16 length");
  }
  const out = new Uint8Array(2 + data.length);
  out[0] = (data.length >>> 8) & 0xff;
  out[1] = data.length & 0xff;
  out.set(data, 2);
  return out;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecode(input: string): Uint8Array | null {
  if (input.length === 0 || !/^[A-Za-z0-9_-]+$/.test(input)) {
    return null;
  }
  const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (input.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    // Reject non-canonical unpadded inputs.
    if (base64UrlEncode(out) !== input) {
      return null;
    }
    return out;
  } catch {
    return null;
  }
}

export function base32EncodeLowerNoPad(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < bytes.length; i++) {
    buffer = (buffer << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(buffer >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f];
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("invalid hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  // Cloudflare Workers provides crypto.subtle.timingSafeEqual; fall back cleanly if absent.
  const subtleAny = crypto.subtle as SubtleCrypto & {
    timingSafeEqual?: (a: BufferSource, b: BufferSource) => boolean;
  };
  if (typeof subtleAny.timingSafeEqual === "function") {
    return subtleAny.timingSafeEqual(a, b);
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function normalizeRelayOrigin(raw: string): string | null {
  const s = raw.trim();
  if (!s) return null;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  const scheme = u.protocol.replace(/:$/, "").toLowerCase();
  if (scheme !== "https" && scheme !== "http") return null;
  if (!u.host || u.username || u.password || u.search || u.hash) return null;
  const hostname = u.hostname.toLowerCase();
  if (!hostname) return null;
  let port = u.port;
  if ((scheme === "https" && port === "443") || (scheme === "http" && port === "80")) {
    port = "";
  }
  const hostPort = port ? `${hostname}:${port}` : hostname;
  const path = u.pathname.replace(/\/+$/, "");
  return `${scheme}://${hostPort}${path}`;
}

export async function deriveDeviceId(publicKey: Uint8Array): Promise<string> {
  if (publicKey.length !== 32) {
    throw new Error("invalid ed25519 public key length");
  }
  const digest = await sha256(concatBytes(utf8Bytes("unic/device-id/v1\0"), publicKey));
  return base32EncodeLowerNoPad(digest.subarray(0, 16));
}

export async function deriveMailboxId(relayOrigin: string, recipientPk: Uint8Array): Promise<string | null> {
  const origin = normalizeRelayOrigin(relayOrigin);
  if (!origin || recipientPk.length !== 32) return null;
  const digest = await sha256(
    concatBytes(utf8Bytes("unic/relay-mailbox/v1\0"), lengthPrefixedField(utf8Bytes(origin)), recipientPk)
  );
  return base32EncodeLowerNoPad(digest.subarray(0, 20));
}

export async function tokenHashHex(deliveryToken: string): Promise<string> {
  const digest = await sha256(utf8Bytes(deliveryToken));
  return bytesToHex(digest);
}

export function validMailboxId(id: string): boolean {
  return /^[a-z2-7]{32}$/.test(id);
}

export function validTransferId(id: string): boolean {
  return /^[0-9a-f]{16,64}$/.test(id);
}

export function validHex64(s: string): boolean {
  return /^[0-9a-f]{64}$/.test(s);
}

export function ownerAuthPayload(
  relayOrigin: string,
  method: string,
  pathAndQuery: string,
  timestamp: string,
  nonce: string,
  bodySha256: Uint8Array
): Uint8Array | null {
  const origin = normalizeRelayOrigin(relayOrigin);
  const m = method.trim().toUpperCase();
  if (!origin || !m || !pathAndQuery || !timestamp || !nonce || bodySha256.length !== 32) {
    return null;
  }
  return concatBytes(
    lengthPrefixedField(utf8Bytes(origin)),
    lengthPrefixedField(utf8Bytes(m)),
    lengthPrefixedField(utf8Bytes(pathAndQuery)),
    lengthPrefixedField(utf8Bytes(timestamp)),
    lengthPrefixedField(utf8Bytes(nonce)),
    bodySha256
  );
}

export async function verifyOwnerAuth(
  relayOrigin: string,
  expectedMailboxId: string,
  method: string,
  pathAndQuery: string,
  body: Uint8Array,
  hdr: OwnerAuthHeaders,
  nowMs: number
): Promise<Uint8Array | null> {
  const pk = base64UrlDecode(hdr.pubKey);
  if (!pk || pk.length !== 32) return null;

  const sig = base64UrlDecode(hdr.sig);
  if (!sig || sig.length !== 64) return null;

  if (!/^-?\d+$/.test(hdr.timestamp)) return null;
  const ts = Number.parseInt(hdr.timestamp, 10);
  if (!Number.isSafeInteger(ts)) return null;

  const nowSec = Math.floor(nowMs / 1000);
  if (Math.abs(nowSec - ts) > OWNER_AUTH_MAX_SKEW_SEC) {
    return null;
  }

  if (hdr.nonce.length < 8 || hdr.nonce.length > 128) {
    return null;
  }

  const derivedMailbox = await deriveMailboxId(relayOrigin, pk);
  if (!derivedMailbox || !timingSafeEqualBytes(utf8Bytes(derivedMailbox), utf8Bytes(expectedMailboxId))) {
    return null;
  }

  const bodyDigest = await sha256(body);
  const payload = ownerAuthPayload(relayOrigin, method, pathAndQuery, hdr.timestamp, hdr.nonce, bodyDigest);
  if (!payload) return null;

  const fullMessage = concatBytes(utf8Bytes("unic/relay-auth/v1\0"), payload);
  try {
    const key = await crypto.subtle.importKey("raw", pk, { name: "Ed25519" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("Ed25519", key, sig, fullMessage);
    return valid ? pk : null;
  } catch {
    return null;
  }
}

export function encodeSingleFrame(env: Envelope, ciphertext0: Uint8Array): Uint8Array {
  const envBytes = utf8Bytes(JSON.stringify(env));
  if (envBytes.length === 0 || envBytes.length > MAX_ENVELOPE_JSON_BYTES) {
    throw new Error("invalid envelope size");
  }
  const out = new Uint8Array(4 + envBytes.length + ciphertext0.length);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(0, envBytes.length, false);
  out.set(envBytes, 4);
  out.set(ciphertext0, 4 + envBytes.length);
  return out;
}

export function decodeSingleFrame(frame: Uint8Array): { envelope: Envelope; ciphertext: Uint8Array } | null {
  if (frame.length < 4) return null;
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const envLen = view.getUint32(0, false);
  if (envLen === 0 || envLen > MAX_ENVELOPE_JSON_BYTES || frame.length < 4 + envLen) {
    return null;
  }
  try {
    const envJson = textDecoder.decode(frame.subarray(4, 4 + envLen));
    const envelope = JSON.parse(envJson) as Envelope;
    const ciphertext = frame.subarray(4 + envLen);
    return { envelope, ciphertext };
  } catch {
    return null;
  }
}

export function newBitmap(totalChunks: number): Uint8Array {
  if (totalChunks <= 0 || totalChunks > MAX_CHUNKS) {
    throw new Error("invalid chunk count");
  }
  return new Uint8Array(Math.ceil(totalChunks / 8));
}

export function setBit(bm: Uint8Array, index: number): void {
  const byteIdx = index >>> 3;
  if (index < 0 || byteIdx >= bm.length) return;
  bm[byteIdx] |= 1 << (index & 7);
}

export function hasBit(bm: Uint8Array, index: number): boolean {
  const byteIdx = index >>> 3;
  if (index < 0 || byteIdx >= bm.length) return false;
  return (bm[byteIdx] & (1 << (index & 7))) !== 0;
}

export function encodeBitmap(bm: Uint8Array): string {
  return base64UrlEncode(bm);
}

export function decodeBitmap(encoded: string, totalChunks: number): Uint8Array | null {
  if (totalChunks <= 0 || totalChunks > MAX_CHUNKS) return null;
  const raw = base64UrlDecode(encoded);
  if (!raw || raw.length !== Math.ceil(totalChunks / 8)) return null;
  return raw;
}
