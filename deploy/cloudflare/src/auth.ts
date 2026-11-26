// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Shared credential & admission helpers for Cloudflare Workers.
 * Mirrors the Go `internal/auth` policy semantics:
 * - Constant-time SHA-256 digest comparison for X-Unic-Relay-Key
 * - Ed25519 device public key allowlist (RELAY_ALLOWED_PUBKEYS)
 * - Zero logging or persistence of raw secrets
 */

import { base64UrlDecode, base64UrlEncode, sha256, timingSafeEqualBytes, utf8Bytes } from "./crypto";

export const ACCESS_KEY_HEADER = "X-Unic-Relay-Key";

export interface AuthEnv {
  RELAY_ACCESS_KEY?: string;
  RELAY_ALLOWED_PUBKEYS?: string;
}

export async function verifyAccessKey(presented: string | null, expected: string | undefined): Promise<boolean> {
  if (!expected) {
    return true;
  }
  if (!presented) {
    return false;
  }
  const [gotDigest, wantDigest] = await Promise.all([
    sha256(utf8Bytes(presented)),
    sha256(utf8Bytes(expected)),
  ]);
  return timingSafeEqualBytes(gotDigest, wantDigest);
}

export function parseAllowedPubKeys(csv: string | undefined): Set<string> | null {
  if (!csv || !csv.trim()) {
    return null;
  }
  const out = new Set<string>();
  for (const part of csv.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const raw = base64UrlDecode(trimmed);
    if (raw && raw.length === 32) {
      out.add(base64UrlEncode(raw));
    }
  }
  return out.size > 0 ? out : null;
}

export function isPubKeyAllowed(pubKey: string, allowed: Set<string> | null): boolean {
  if (!allowed || allowed.size === 0) {
    return true;
  }
  return allowed.has(pubKey);
}
