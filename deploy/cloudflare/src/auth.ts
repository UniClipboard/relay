// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Shared credential & admission helpers for Cloudflare Workers.
 * Mirrors the Go `internal/auth` policy semantics:
 * - Constant-time SHA-256 digest comparison for static X-Unic-Relay-Key
 * - Official uc-cloud SHA-256 key_hash verification with bounded short-TTL cache
 * - Ed25519 device public key allowlist (RELAY_ALLOWED_PUBKEYS)
 * - Zero logging, transmission, or persistence of raw secrets
 */

import { base64UrlDecode, base64UrlEncode, bytesToHex, sha256, timingSafeEqualBytes, utf8Bytes } from "./crypto";

export const ACCESS_KEY_HEADER = "X-Unic-Relay-Key";

const DEFAULT_CLOUD_VERIFY_CACHE_TTL_SEC = 60;
const NEGATIVE_CLOUD_VERIFY_CACHE_TTL_SEC = 10;
const CLOUD_VERIFY_TIMEOUT_MS = 5_000;
const MAX_CACHE_ENTRIES = 4096;

export interface AuthEnv {
  RELAY_ACCESS_KEY?: string;
  RELAY_ALLOWED_PUBKEYS?: string;
  CLOUD_VERIFY_URL?: string;
  CLOUD_VERIFY_SECRET?: string;
  CLOUD_VERIFY_CACHE_TTL_SEC?: string;
}

export interface AccessKeyResult {
  allowed: boolean;
  status: number;
  error?: string;
  subject?: string;
  keyId?: string;
  maxTransferBytes?: number;
  cloudKeyHash?: string;
}

interface CloudVerifyCacheEntry {
  result: AccessKeyResult;
  expiresAtMs: number;
}

const cloudVerifyCache = new Map<string, CloudVerifyCacheEntry>();

export function clearCloudVerifyCache(): void {
  cloudVerifyCache.clear();
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

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const n = Number.parseInt(raw.trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function getCachedCloudDecision(cacheKey: string, nowMs: number): AccessKeyResult | null {
  const entry = cloudVerifyCache.get(cacheKey);
  if (!entry) return null;
  if (nowMs >= entry.expiresAtMs) {
    cloudVerifyCache.delete(cacheKey);
    return null;
  }
  return entry.result;
}

function setCachedCloudDecision(cacheKey: string, result: AccessKeyResult, expiresAtMs: number, nowMs: number): void {
  if (cloudVerifyCache.size >= MAX_CACHE_ENTRIES) {
    for (const [k, v] of cloudVerifyCache) {
      if (nowMs >= v.expiresAtMs) {
        cloudVerifyCache.delete(k);
      }
    }
    if (cloudVerifyCache.size >= MAX_CACHE_ENTRIES) {
      const oldestKey = cloudVerifyCache.keys().next().value;
      if (oldestKey !== undefined) {
        cloudVerifyCache.delete(oldestKey);
      }
    }
  }
  cloudVerifyCache.set(cacheKey, { result, expiresAtMs });
}

export async function verifyCloudAccessKey(
  presented: string | null,
  env: AuthEnv,
  options?: { nowMs?: number; fetchFn?: typeof fetch }
): Promise<AccessKeyResult> {
  const verifyUrl = (env.CLOUD_VERIFY_URL ?? "").trim();
  if (!verifyUrl) {
    const ok = await verifyAccessKey(presented, env.RELAY_ACCESS_KEY);
    return ok ? { allowed: true, status: 200 } : { allowed: false, status: 401, error: "unauthorized" };
  }

  // Fail closed whenever CLOUD_VERIFY_URL is configured without its Bearer secret.
  const verifySecret = (env.CLOUD_VERIFY_SECRET ?? "").trim();
  if (!verifySecret) {
    return { allowed: false, status: 503, error: "auth_unavailable" };
  }

  if (!presented) {
    return { allowed: false, status: 401, error: "unauthorized" };
  }

  // Optional static RELAY_ACCESS_KEY fast-path in constant time.
  if (env.RELAY_ACCESS_KEY && (await verifyAccessKey(presented, env.RELAY_ACCESS_KEY))) {
    return { allowed: true, status: 200 };
  }

  const keyHash = bytesToHex(await sha256(utf8Bytes(presented)));
  const cacheKey = `${verifyUrl}\0${keyHash}`;
  const nowMs = options?.nowMs ?? Date.now();

  const cached = getCachedCloudDecision(cacheKey, nowMs);
  if (cached) {
    return cached;
  }

  const cacheTtlSec = parsePositiveInt(env.CLOUD_VERIFY_CACHE_TTL_SEC, DEFAULT_CLOUD_VERIFY_CACHE_TTL_SEC);
  const fetchFn = options?.fetchFn ?? fetch;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CLOUD_VERIFY_TIMEOUT_MS);

  let resp: Response;
  try {
    resp = await fetchFn(verifyUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${verifySecret}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ key_hash: keyHash }),
      signal: controller.signal,
    });
  } catch {
    return { allowed: false, status: 503, error: "auth_unavailable" };
  } finally {
    clearTimeout(timer);
  }

  if (resp.status !== 200) {
    return { allowed: false, status: 503, error: "auth_unavailable" };
  }

  let parsed: {
    allowed?: unknown;
    subject?: unknown;
    key_id?: unknown;
    max_transfer_bytes?: unknown;
    reason?: unknown;
  };
  try {
    parsed = (await resp.json()) as typeof parsed;
  } catch {
    return { allowed: false, status: 503, error: "auth_unavailable" };
  }

  if (typeof parsed?.allowed !== "boolean") {
    return { allowed: false, status: 503, error: "auth_unavailable" };
  }

  if (!parsed.allowed) {
    const denied: AccessKeyResult = { allowed: false, status: 401, error: "unauthorized" };
    setCachedCloudDecision(cacheKey, denied, nowMs + NEGATIVE_CLOUD_VERIFY_CACHE_TTL_SEC * 1000, nowMs);
    return denied;
  }

  const subject = typeof parsed.subject === "string" && parsed.subject.trim() ? parsed.subject.trim() : undefined;
  const keyId = typeof parsed.key_id === "string" && parsed.key_id.trim() ? parsed.key_id.trim() : undefined;
  const maxTransferBytes =
    typeof parsed.max_transfer_bytes === "number" &&
    Number.isFinite(parsed.max_transfer_bytes) &&
    parsed.max_transfer_bytes > 0
      ? Math.floor(parsed.max_transfer_bytes)
      : undefined;

  const allowed: AccessKeyResult = {
    allowed: true,
    status: 200,
    subject,
    keyId,
    maxTransferBytes,
    cloudKeyHash: keyHash,
  };
  setCachedCloudDecision(cacheKey, allowed, nowMs + cacheTtlSec * 1000, nowMs);
  return allowed;
}

export async function reserveCloudTransfer(
  env: AuthEnv,
  keyHash: string,
  bytes: number,
): Promise<Response | null> {
  const unavailable = () => Response.json({ error: "quota_unavailable" }, { status: 503 });
  const verifyUrl = env.CLOUD_VERIFY_URL?.trim();
  const verifySecret = env.CLOUD_VERIFY_SECRET?.trim();
  if (!verifyUrl || !verifySecret) return unavailable();

  try {
    const response = await fetch(verifyUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${verifySecret}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        key_hash: keyHash,
        reservation: { id: crypto.randomUUID(), bytes },
      }),
      signal: AbortSignal.timeout(CLOUD_VERIFY_TIMEOUT_MS),
    });
    const result = await response.json() as { reserved?: unknown; error?: unknown };
    if (response.ok && result?.reserved === true) return null;
    if (response.status === 429 && result?.error === "monthly_quota_exceeded") {
      const headers = new Headers();
      const retryAfter = response.headers.get("Retry-After");
      if (retryAfter) headers.set("Retry-After", retryAfter);
      return Response.json({ error: result.error }, { status: 429, headers });
    }
    if (response.status === 401 && result?.error === "invalid_or_revoked") {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    if (response.status === 413 && result?.error === "transfer_too_large") {
      return Response.json({ error: "payload_too_large" }, { status: 413 });
    }
  } catch {
    return unavailable();
  }
  return unavailable();
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
