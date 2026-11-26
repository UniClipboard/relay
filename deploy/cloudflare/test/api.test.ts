// SPDX-License-Identifier: AGPL-3.0-only

import { env, runDurableObjectAlarm, SELF } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import vector from "../../../vectors/hybrid-relay-v1.json";
import { isPubKeyAllowed, parseAllowedPubKeys, verifyAccessKey } from "../src/auth";
import {
  base64UrlEncode,
  concatBytes,
  deriveMailboxId,
  hexToBytes,
  ownerAuthPayload,
  sha256,
  tokenHashHex,
  utf8Bytes,
} from "../src/crypto";
import worker from "../src/index";
import { S3Client } from "../src/s3";

const ORIGIN = "http://example.com";
const MOCK_S3_ORIGIN = "https://mock-s3.example";

function ed25519SeedToPkcs8(seed: Uint8Array): Uint8Array {
  const prefix = hexToBytes("302e020100300506032b657004220420");
  return concatBytes(prefix, seed);
}

async function importSeedKey(seedHex: string): Promise<{ priv: CryptoKey; pub: Uint8Array }> {
  const seed = hexToBytes(seedHex);
  const priv = await crypto.subtle.importKey("pkcs8", ed25519SeedToPkcs8(seed), { name: "Ed25519" }, false, ["sign"]);
  if (seedHex === vector.keys.recipient.seed) {
    return { priv, pub: hexToBytes(vector.keys.recipient.public) };
  }
  if (seedHex === vector.keys.sender.seed) {
    return { priv, pub: hexToBytes(vector.keys.sender.public) };
  }
  throw new Error("unknown test seed");
}

async function signOwnerHeaders(
  owner: { priv: CryptoKey; pub: Uint8Array },
  method: string,
  pathAndQuery: string,
  body: Uint8Array,
  nonce: string,
  origin = ORIGIN
): Promise<Record<string, string>> {
  const ts = String(Math.floor(Date.now() / 1000));
  const bodyDigest = await sha256(body);
  const payload = ownerAuthPayload(origin, method, pathAndQuery, ts, nonce, bodyDigest)!;
  const full = concatBytes(utf8Bytes("unic/relay-auth/v1\0"), payload);
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", owner.priv, full));
  return {
    "X-Unic-PubKey": base64UrlEncode(owner.pub),
    "X-Unic-Timestamp": ts,
    "X-Unic-Nonce": nonce,
    "X-Unic-Sig": base64UrlEncode(sig),
  };
}

describe("Cloudflare Worker + Durable Object Direct-to-S3 Relay API", () => {
  const mockS3Objects = new Map<string, Uint8Array>();

  beforeEach(() => {
    mockS3Objects.clear();
    const origFetch = globalThis.fetch.bind(globalThis);
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      if (url.origin !== MOCK_S3_ORIGIN) {
        return origFetch(input, init);
      }

      if (req.method === "PUT") {
        if (!url.searchParams.get("X-Amz-Signature")) {
          return new Response("forbidden", { status: 403 });
        }
        const buf = new Uint8Array(await req.arrayBuffer());
        mockS3Objects.set(url.pathname, buf);
        return new Response(null, { status: 200, headers: { ETag: '"mock-etag"' } });
      }
      if (req.method === "HEAD") {
        if (!(req.headers.get("Authorization") ?? "").startsWith("AWS4-HMAC-SHA256 ")) {
          return new Response(null, { status: 403 });
        }
        const obj = mockS3Objects.get(url.pathname);
        if (!obj) return new Response(null, { status: 404 });
        return new Response(null, {
          status: 200,
          headers: { "Content-Length": String(obj.byteLength), ETag: '"mock-etag"' },
        });
      }
      if (req.method === "GET") {
        if (!url.searchParams.get("X-Amz-Signature")) {
          return new Response("forbidden", { status: 403 });
        }
        const obj = mockS3Objects.get(url.pathname);
        if (!obj) return new Response(null, { status: 404 });
        return new Response(obj, { status: 200, headers: { "Content-Type": "application/octet-stream" } });
      }
      if (req.method === "DELETE") {
        if (!(req.headers.get("Authorization") ?? "").startsWith("AWS4-HMAC-SHA256 ")) {
          return new Response(null, { status: 403 });
        }
        mockS3Objects.delete(url.pathname);
        return new Response(null, { status: 204 });
      }
      return new Response(null, { status: 405 });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("serves /healthz with storage=s3-direct without authentication", async () => {
    const resp = await SELF.fetch(`${ORIGIN}/healthz`);
    expect(resp.status).toBe(200);
    expect(await resp.json()).toEqual({
      status: "ok",
      service: "hyper-relay",
      runtime: "cloudflare-workers",
      storage: "s3-direct",
    });
  });

  it("generates valid SigV4 presigned URLs for Tencent COS virtual-host addressing", async () => {
    const nowMs = Date.UTC(2026, 10, 26, 8, 0, 0);
    const cos = new S3Client({
      endpoint: "https://cos.ap-guangzhou.myqcloud.com",
      region: "ap-guangzhou",
      bucket: "unic-relay-1250000000",
      accessKeyId: "AKIDTEST",
      secretAccessKey: "SECRETTEST",
      forcePathStyle: false,
      keyPrefix: "mailboxes",
      presignTtlSec: 300,
    });
    const key = cos.objectKey(vector.keys.recipient.mailbox_id, vector.transfer.transfer_id, 0);
    const putGrant = await cos.presignPut(key, 300, nowMs);
    const u = new URL(putGrant.url);
    expect(u.host).toBe("unic-relay-1250000000.cos.ap-guangzhou.myqcloud.com");
    expect(u.pathname).toBe(
      `/mailboxes/${vector.keys.recipient.mailbox_id}/transfers/${vector.transfer.transfer_id}/chunks/0`
    );
    expect(u.searchParams.get("X-Amz-Algorithm")).toBe("AWS4-HMAC-SHA256");
    expect(u.searchParams.get("X-Amz-Credential")).toBe("AKIDTEST/20261126/ap-guangzhou/s3/aws4_request");
    expect(u.searchParams.get("X-Amz-Date")).toBe("20261126T080000Z");
    expect(u.searchParams.get("X-Amz-Expires")).toBe("300");
    expect(u.searchParams.get("X-Amz-SignedHeaders")).toBe("host");
    expect(u.searchParams.get("X-Amz-Signature")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("handles full direct-to-S3 upload, commit, SSE + Last-Event-ID, direct download, ACK S3 delete, and nonce replay rejection", async () => {
    const owner = await importSeedKey(vector.keys.recipient.seed);
    const mailboxId = (await deriveMailboxId(ORIGIN, owner.pub))!;

    const deliveryToken = "delivery-token-0123456789abcdef0123456789";
    const tokHash = await tokenHashHex(deliveryToken);

    // 1. Register sender token hash via Owner Auth.
    const senderPath = `/v1/relay/mailboxes/${mailboxId}/senders/${tokHash}`;
    const senderBody = utf8Bytes(JSON.stringify({ max_bytes: 10 * 1024 * 1024 }));
    const putHeaders = await signOwnerHeaders(owner, "PUT", senderPath, senderBody, "cf-nonce-sender-1");
    const putResp = await SELF.fetch(`${ORIGIN}${senderPath}`, {
      method: "PUT",
      headers: { ...putHeaders, "Content-Type": "application/json" },
      body: senderBody,
    });
    expect(putResp.status).toBe(204);

    // Nonce replay must fail with 401.
    const replayResp = await SELF.fetch(`${ORIGIN}${senderPath}`, {
      method: "PUT",
      headers: { ...putHeaders, "Content-Type": "application/json" },
      body: senderBody,
    });
    expect(replayResp.status).toBe(401);

    // 2. Create transfer -> receives inline presigned PUT URLs.
    const nowMs = Date.now();
    const liveEnv = {
      ...vector.transfer.envelope,
      created_ms: nowMs,
      expires_ms: nowMs + 60_000,
    };
    const createResp = await SELF.fetch(`${ORIGIN}/v1/relay/mailboxes/${mailboxId}/transfers`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${deliveryToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(liveEnv),
    });
    expect(createResp.status).toBe(200);
    const created = (await createResp.json()) as {
      transfer_id: string;
      upload_mode: string;
      upload_urls: Array<{ index: number; method: string; url: string }>;
    };
    expect(created.upload_mode).toBe("presigned");
    expect(created.upload_urls).toHaveLength(2);

    // 3. Direct PUT both chunks to mock S3, then commit via relay.
    for (let i = 0; i < vector.transfer.ciphertexts_hex.length; i++) {
      const ct = hexToBytes(vector.transfer.ciphertexts_hex[i]);
      const directPut = await fetch(created.upload_urls[i].url, { method: "PUT", body: ct });
      expect(directPut.status).toBe(200);

      const commitResp = await SELF.fetch(
        `${ORIGIN}/v1/relay/mailboxes/${mailboxId}/transfers/${liveEnv.transfer_id}/chunks/${i}/commit`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${deliveryToken}` },
        }
      );
      expect(commitResp.status).toBe(204);
    }
    expect(mockS3Objects.size).toBe(2);

    // 4. Verify SSE Last-Event-ID replays chunk_ready events.
    const ssePath = `/v1/relay/mailboxes/${mailboxId}/events`;
    const sseHeaders = await signOwnerHeaders(owner, "GET", ssePath, new Uint8Array(0), "cf-nonce-sse-replay");
    const sseResp = await SELF.fetch(`${ORIGIN}${ssePath}`, {
      method: "GET",
      headers: { ...sseHeaders, "Last-Event-ID": "1" },
    });
    expect(sseResp.status).toBe(200);
    const reader = sseResp.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (!buf.includes('"chunk_index":1')) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }
    await reader.cancel();
    expect(buf).toContain("event: chunk_ready");

    // 5. Receiver obtains presigned GET URL and downloads directly from S3.
    const dlPath = `/v1/relay/mailboxes/${mailboxId}/transfers/${liveEnv.transfer_id}/chunks/0`;
    const dlResp = await SELF.fetch(`${ORIGIN}${dlPath}`, {
      method: "GET",
      headers: await signOwnerHeaders(owner, "GET", dlPath, new Uint8Array(0), "cf-nonce-dl-0"),
    });
    expect(dlResp.status).toBe(200);
    const dlGrant = (await dlResp.json()) as { method: string; url: string; size: number };
    expect(dlGrant.method).toBe("GET");
    const directGet = await fetch(dlGrant.url);
    expect(directGet.status).toBe(200);
    expect(new Uint8Array(await directGet.arrayBuffer())).toEqual(hexToBytes(vector.transfer.ciphertexts_hex[0]));

    // 6. ACK deletes both objects in S3.
    const ackPath = `/v1/relay/mailboxes/${mailboxId}/transfers/${liveEnv.transfer_id}/ack`;
    const ackResp = await SELF.fetch(`${ORIGIN}${ackPath}`, {
      method: "POST",
      headers: await signOwnerHeaders(owner, "POST", ackPath, new Uint8Array(0), "cf-nonce-ack-1"),
    });
    expect(ackResp.status).toBe(204);
    expect(mockS3Objects.size).toBe(0);
  });

  it("purges expired transfer objects from S3 via Durable Object Alarm", async () => {
    const owner = await importSeedKey(vector.keys.sender.seed);
    const mailboxId = (await deriveMailboxId(ORIGIN, owner.pub))!;

    const deliveryToken = "alarm-token-0123456789abcdef0123456789";
    const tokHash = await tokenHashHex(deliveryToken);
    const senderPath = `/v1/relay/mailboxes/${mailboxId}/senders/${tokHash}`;
    const putResp = await SELF.fetch(`${ORIGIN}${senderPath}`, {
      method: "PUT",
      headers: await signOwnerHeaders(owner, "PUT", senderPath, new Uint8Array(0), "cf-nonce-alarm-sender"),
    });
    expect(putResp.status).toBe(204);

    const ct0 = hexToBytes(vector.transfer.ciphertexts_hex[0]);
    const nowMs = Date.now();
    const shortEnv = {
      ...vector.transfer.envelope,
      transfer_id: "abcdef0123456789abcdef0123456789",
      created_ms: nowMs,
      expires_ms: nowMs + 50,
      total_chunks: 1,
      chunk_size: ct0.length,
      total_ciphertext_bytes: ct0.length,
      chunk_hashes: [vector.transfer.envelope.chunk_hashes[0]],
    };
    const createResp = await SELF.fetch(`${ORIGIN}/v1/relay/mailboxes/${mailboxId}/transfers`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${deliveryToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(shortEnv),
    });
    expect(createResp.status).toBe(200);
    const created = (await createResp.json()) as { upload_urls: Array<{ url: string }> };
    await fetch(created.upload_urls[0].url, { method: "PUT", body: ct0 });
    expect(mockS3Objects.size).toBe(1);

    await new Promise((r) => setTimeout(r, 80));
    const stub = env.MAILBOX_DO.get(env.MAILBOX_DO.idFromName(mailboxId));
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(mockS3Objects.size).toBe(0);
  });

  it("enforces shared X-Unic-Relay-Key and RELAY_ALLOWED_PUBKEYS admission policies", async () => {
    expect(await verifyAccessKey("secret-key-v2", "secret-key-v2")).toBe(true);
    expect(await verifyAccessKey("wrong-key", "secret-key-v2")).toBe(false);
    expect(await verifyAccessKey(null, "secret-key-v2")).toBe(false);
    expect(await verifyAccessKey(null, undefined)).toBe(true);

    const allowed = parseAllowedPubKeys(vector.owner_auth.headers.PubKey);
    expect(isPubKeyAllowed(vector.owner_auth.headers.PubKey, allowed)).toBe(true);
    expect(isPubKeyAllowed(base64UrlEncode(hexToBytes(vector.keys.sender.public)), allowed)).toBe(false);

    const gatedEnv = { ...env, RELAY_ACCESS_KEY: "shared-instance-key" };
    const healthResp = await worker.fetch(new Request(`${ORIGIN}/healthz`), gatedEnv);
    expect(healthResp.status).toBe(200);

    const unauthResp = await worker.fetch(
      new Request(`${ORIGIN}/v1/relay/mailboxes/${vector.keys.recipient.mailbox_id}/transfers`),
      gatedEnv
    );
    expect(unauthResp.status).toBe(401);
  });
});
