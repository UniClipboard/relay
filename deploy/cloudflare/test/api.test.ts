// SPDX-License-Identifier: AGPL-3.0-only

import { env, runDurableObjectAlarm, runInDurableObject, SELF } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import vector from "../../../vectors/hybrid-relay-v1.json";
import {
  clearCloudVerifyCache,
  isPubKeyAllowed,
  parseAllowedPubKeys,
  verifyAccessKey,
  verifyCloudAccessKey,
} from "../src/auth";
import {
  base64UrlEncode,
  bytesToHex,
  concatBytes,
  deriveMailboxId,
  hexToBytes,
  ownerAuthPayload,
  sha256,
  tokenHashHex,
  utf8Bytes,
} from "../src/crypto";
import worker from "../src/index";
import { configuredStorageProfiles, loadS3ConfigForProfile, S3Client } from "../src/s3";

const ORIGIN = "http://example.com";
const MOCK_S3_ORIGIN = "https://mock-s3.example";
const MOCK_CN_S3_ORIGIN = "https://mock-cos-cn.example";
const MOCK_CLOUD_VERIFY_URL = "https://mock-cloud.example/api/relay/v2/keys/verify";

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

function withCfCountry(req: Request, country: string): Request {
  Object.defineProperty(req, "cf", {
    value: { country },
    configurable: true,
  });
  return req;
}

async function readSSEFrame(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<string> {
  const { value, done } = await reader.read();
  if (done) throw new Error("Expected an SSE frame");
  return new TextDecoder().decode(value);
}

describe("Cloudflare Worker + Durable Object Direct-to-S3 Relay API", () => {
  const mockGlobalObjects = new Map<string, Uint8Array>();
  const mockCnObjects = new Map<string, Uint8Array>();
  let cloudHandler: ((req: Request) => Promise<Response>) | null = null;
  let onStorageDelete: ((path: string) => Promise<void>) | null = null;

  async function objectETag(obj: Uint8Array): Promise<string> {
    return `"${bytesToHex(await sha256(obj))}"`;
  }

  async function handleMockS3(store: Map<string, Uint8Array>, req: Request, url: URL): Promise<Response> {
    if (req.method === "PUT") {
      const copySource = req.headers.get("x-amz-copy-source");
      if (copySource) {
        if (!(req.headers.get("Authorization") ?? "").startsWith("AWS4-HMAC-SHA256 ")) {
          return new Response(null, { status: 403 });
        }
        const source = store.get(copySource);
        if (!source) return new Response(null, { status: 404 });
        if (req.headers.get("x-amz-copy-source-if-match") !== await objectETag(source)) {
          return new Response(null, { status: 412 });
        }
        store.set(url.pathname, source.slice());
        return new Response("<CopyObjectResult></CopyObjectResult>");
      }
      if (!url.searchParams.get("X-Amz-Signature")) {
        return new Response("forbidden", { status: 403 });
      }
      const obj = new Uint8Array(await req.arrayBuffer());
      store.set(url.pathname, obj);
      return new Response(null, { status: 200, headers: { ETag: await objectETag(obj) } });
    }
    if (req.method === "HEAD") {
      if (!(req.headers.get("Authorization") ?? "").startsWith("AWS4-HMAC-SHA256 ")) {
        return new Response(null, { status: 403 });
      }
      const obj = store.get(url.pathname);
      if (!obj) return new Response(null, { status: 404 });
      return new Response(null, {
        status: 200,
        headers: { "Content-Length": String(obj.byteLength), ETag: await objectETag(obj) },
      });
    }
    if (req.method === "GET") {
      if (!url.searchParams.get("X-Amz-Signature")) {
        return new Response("forbidden", { status: 403 });
      }
      const obj = store.get(url.pathname);
      if (!obj) return new Response(null, { status: 404 });
      return new Response(obj, { status: 200, headers: { "Content-Type": "application/octet-stream" } });
    }
    if (req.method === "DELETE") {
      if (!(req.headers.get("Authorization") ?? "").startsWith("AWS4-HMAC-SHA256 ")) {
        return new Response(null, { status: 403 });
      }
      await onStorageDelete?.(url.pathname);
      store.delete(url.pathname);
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 405 });
  }

  beforeEach(() => {
    mockGlobalObjects.clear();
    mockCnObjects.clear();
    cloudHandler = null;
    onStorageDelete = null;
    clearCloudVerifyCache();

    const origFetch = globalThis.fetch.bind(globalThis);
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = input instanceof Request ? input : new Request(input, init);
      const url = new URL(req.url);
      if (url.origin === MOCK_S3_ORIGIN) {
        return handleMockS3(mockGlobalObjects, req, url);
      }
      if (url.origin === MOCK_CN_S3_ORIGIN) {
        return handleMockS3(mockCnObjects, req, url);
      }
      if (req.url === MOCK_CLOUD_VERIFY_URL && cloudHandler) {
        return cloudHandler(req);
      }
      return origFetch(input, init);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("serves /healthz with storage=s3-direct and storage_profiles without authentication", async () => {
    const resp = await SELF.fetch(`${ORIGIN}/healthz`);
    expect(resp.status).toBe(200);
    expect(await resp.json()).toEqual({
      status: "ok",
      service: "hyper-relay",
      runtime: "cloudflare-workers",
      storage: "s3-direct",
      storage_profiles: ["global", "cn"],
    });

    const globalOnlyEnv: Env = {
      ...env,
      S3_CN_ENDPOINT: undefined,
      S3_CN_BUCKET: undefined,
      S3_CN_ACCESS_KEY_ID: undefined,
      S3_CN_SECRET_ACCESS_KEY: undefined,
    };
    const respGlobal = await worker.fetch(new Request(`${ORIGIN}/healthz`), globalOnlyEnv);
    expect(respGlobal.status).toBe(200);
    expect(await respGlobal.json()).toEqual({
      status: "ok",
      service: "hyper-relay",
      runtime: "cloudflare-workers",
      storage: "s3-direct",
      storage_profiles: ["global"],
    });
  });

  it("loads dual S3 storage profiles with clean fallback behavior", () => {
    const globalOnly: Env = {
      ...env,
      S3_CN_ENDPOINT: undefined,
      S3_CN_BUCKET: undefined,
      S3_CN_ACCESS_KEY_ID: undefined,
      S3_CN_SECRET_ACCESS_KEY: undefined,
    };
    expect(configuredStorageProfiles(globalOnly)).toEqual(["global"]);
    expect(loadS3ConfigForProfile(globalOnly, "cn")?.endpoint).toBe(MOCK_S3_ORIGIN);

    const cnOnly: Env = {
      ...env,
      S3_ENDPOINT: undefined,
      S3_BUCKET: undefined,
      S3_ACCESS_KEY_ID: undefined,
      S3_SECRET_ACCESS_KEY: undefined,
    };
    expect(configuredStorageProfiles(cnOnly)).toEqual(["cn"]);
    expect(loadS3ConfigForProfile(cnOnly, "global")?.endpoint).toBe(MOCK_CN_S3_ORIGIN);
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

    // 2. Create transfer -> receives inline presigned PUT URLs (default global profile).
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
    expect(new URL(created.upload_urls[0].url).origin).toBe(MOCK_S3_ORIGIN);

    // 3. Direct PUT both chunks, then verify live commits carry no download grants.
    const ssePath = `/v1/relay/mailboxes/${mailboxId}/events`;
    const live = await SELF.fetch(`${ORIGIN}${ssePath}`, {
      headers: await signOwnerHeaders(owner, "GET", ssePath, new Uint8Array(0), "cf-nonce-sse-live"),
    });
    expect(live.status).toBe(200);
    const liveReader = live.body!.getReader();
    try {
      expect(await readSSEFrame(liveReader)).toBe(": connected\n\n");
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
        const frame = await readSSEFrame(liveReader);
        expect(frame.includes("event: chunk_ready\n")).toBe(true);
        expect(frame.includes(`"chunk_index":${i}`)).toBe(true);
        expect(frame.includes("download_grant")).toBe(false);
      }
    } finally {
      await liveReader.cancel();
    }
    expect(mockGlobalObjects.size).toBe(4);
    expect(mockCnObjects.size).toBe(0);

    // 4. Verify SSE Last-Event-ID replays chunk_ready events.
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

    // 5. Simulate an older transfer that recorded only the size for its first chunk.
    const stub = env.MAILBOX_DO.get(env.MAILBOX_DO.idFromName(mailboxId));
    const previousKey = await runInDurableObject(stub, (_instance, state) => {
      const { chunk_sizes_json } = state.storage.sql.exec<{ chunk_sizes_json: string }>(
        "SELECT chunk_sizes_json FROM transfers_v2 WHERE transfer_id = ?", liveEnv.transfer_id
      ).one();
      const sizes = JSON.parse(chunk_sizes_json) as Record<string, number | { size: number; key: string }>;
      const first = sizes[0];
      if (typeof first === "number") throw new Error("Expected a committed object");
      sizes[0] = first.size;
      state.storage.sql.exec(
        "UPDATE transfers_v2 SET chunk_sizes_json = ? WHERE transfer_id = ?", JSON.stringify(sizes), liveEnv.transfer_id
      );
      return first.key;
    });
    mockGlobalObjects.delete(`/unic-global-bucket/${previousKey}`);

    // The receiver obtains a presigned GET for a copy of the legacy chunk.
    const dlPath = `/v1/relay/mailboxes/${mailboxId}/transfers/${liveEnv.transfer_id}/chunks/0`;
    const dlResp = await SELF.fetch(`${ORIGIN}${dlPath}`, {
      method: "GET",
      headers: await signOwnerHeaders(owner, "GET", dlPath, new Uint8Array(0), "cf-nonce-dl-0"),
    });
    expect(dlResp.status).toBe(200);
    const dlGrant = (await dlResp.json()) as { method: string; url: string; size: number };
    expect(dlGrant.method).toBe("GET");
    expect(new URL(dlGrant.url).pathname).not.toBe(new URL(created.upload_urls[0].url).pathname);
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
    expect(mockGlobalObjects.size).toBe(0);
  });

  it.each([
    { name: "global profile", country: "US", origin: MOCK_S3_ORIGIN, ttlMs: 600_000, failPresign: false },
    { name: "CN profile", country: "CN", origin: MOCK_CN_S3_ORIGIN, ttlMs: 60_000, failPresign: false },
    { name: "presign failure", country: "US", origin: MOCK_S3_ORIGIN, ttlMs: 60_000, failPresign: true },
  ])("delivers a live single-chunk commit to the owner ($name)", async ({ country, origin, ttlMs, failPresign }) => {
    const owner = await importSeedKey(vector.keys.recipient.seed);
    const other = await importSeedKey(vector.keys.sender.seed);
    const mailboxId = (await deriveMailboxId(ORIGIN, owner.pub))!;
    const mailboxPath = `/v1/relay/mailboxes/${mailboxId}`;
    const ssePath = `${mailboxPath}/events`;
    const token = "delivery-token-inline-download-fixture";
    const senderHeaders = { Authorization: `Bearer ${token}` };
    const senderPath = `${mailboxPath}/senders/${await tokenHashHex(token)}`;
    const ownerFetch = async (path: string, method = "GET", headers: Record<string, string> = {}) =>
      SELF.fetch(`${ORIGIN}${path}`, {
        method,
        headers: { ...await signOwnerHeaders(owner, method, path, new Uint8Array(0), crypto.randomUUID()), ...headers },
      });
    expect((await ownerFetch(senderPath, "PUT")).status).toBe(204);
    expect((await SELF.fetch(`${ORIGIN}${ssePath}`, { headers: senderHeaders })).status).toBe(401);
    expect((await SELF.fetch(`${ORIGIN}${ssePath}`, {
      headers: await signOwnerHeaders(other, "GET", ssePath, new Uint8Array(0), crypto.randomUUID()),
    })).status).toBe(401);

    const live = await ownerFetch(ssePath);
    expect(live.status).toBe(200);
    expect(live.headers.get("Cache-Control")).toBe("no-store");
    const reader = live.body!.getReader();
    try {
      expect(await readSSEFrame(reader)).toBe(": connected\n\n");
      const ciphertext = hexToBytes(vector.transfer.ciphertexts_hex[0]);
      const now = Date.now();
      const envelope = {
        ...vector.transfer.envelope,
        transfer_id: crypto.randomUUID().replaceAll("-", ""),
        created_ms: now,
        expires_ms: now + ttlMs,
        total_chunks: 1,
        chunk_size: ciphertext.length,
        total_ciphertext_bytes: ciphertext.length,
        chunk_hashes: [vector.transfer.envelope.chunk_hashes[0]],
      };
      const transfersPath = `${mailboxPath}/transfers`;
      const transferPath = `${transfersPath}/${envelope.transfer_id}`;
      const chunkPath = `${transferPath}/chunks/0`;
      const create = await worker.fetch(withCfCountry(new Request(`${ORIGIN}${transfersPath}`, {
        method: "POST",
        headers: senderHeaders,
        body: JSON.stringify(envelope),
      }), country), env);
      expect(create.status).toBe(200);
      const { upload_urls: [upload] } = await create.json<{ upload_urls: { url: string }[] }>();
      const announced = await readSSEFrame(reader);
      expect(announced.includes("event: transfer_announced\n")).toBe(true);
      expect(announced.includes("download_grant")).toBe(false);
      expect((await fetch(upload.url, { method: "PUT", body: ciphertext })).status).toBe(200);

      const presign = failPresign
        ? vi.spyOn(S3Client.prototype, "presignGet").mockRejectedValueOnce(new Error("Test signing failure"))
        : undefined;
      const commitStarted = Date.now();
      const commit = await worker.fetch(withCfCountry(new Request(`${ORIGIN}${chunkPath}/commit`, {
        method: "POST",
        headers: senderHeaders,
      }), "US"), env);
      expect(commit.status).toBe(204);
      expect(await commit.text()).toBe("");
      if (presign) {
        expect(presign).toHaveBeenCalledTimes(1);
        presign.mockRestore();
      }

      const frame = await readSSEFrame(reader);
      expect(frame.includes("event: chunk_ready\n")).toBe(true);
      type Grant = { method: string; url: string; size: number; expires_at_ms: number };
      const { download_grant: inline, ...ready } = JSON.parse(frame.split("\n")[2].slice("data: ".length)) as {
        id: string; event: string; transfer_id: string; chunk_index: number; download_grant?: Grant;
      };
      expect(ready).toMatchObject({ event: "chunk_ready", transfer_id: envelope.transfer_id, chunk_index: 0 });
      expect(Boolean(inline)).toBe(!failPresign);

      // A previously issued PUT still writes to staging after the commit.
      expect((await fetch(upload.url, { method: "PUT", body: new Uint8Array(ciphertext.length) })).status).toBe(200);
      const expectDownload = async (grant: Grant) => {
        expect(grant.method).toBe("GET");
        expect(grant.size).toBe(ciphertext.length);
        expect(grant.expires_at_ms).toBeGreaterThan(commitStarted);
        expect(grant.expires_at_ms).toBeLessThanOrEqual(envelope.expires_ms);
        const url = new URL(grant.url);
        expect(url.origin).toBe(origin);
        expect(url.pathname.startsWith(`${new URL(upload.url).pathname}/committed/`)).toBe(true);
        expect(Number(url.searchParams.get("X-Amz-Expires"))).toBeLessThanOrEqual(300);
        const downloaded = await fetch(grant.url, { method: grant.method });
        expect(downloaded.status).toBe(200);
        expect(new Uint8Array(await downloaded.arrayBuffer())).toEqual(ciphertext);
        return url.pathname;
      };
      const inlinePath = inline && await expectDownload(inline);

      const stub = env.MAILBOX_DO.get(env.MAILBOX_DO.idFromName(mailboxId));
      const stored = await runInDurableObject(stub, (_instance, state) => state.storage.sql
        .exec<{ payload_json: string }>("SELECT payload_json FROM events WHERE id = ?", Number(ready.id))
        .one().payload_json);
      const { id, ...baseEvent } = ready;
      expect(stored === JSON.stringify(baseEvent)).toBe(true);
      const replay = await ownerFetch(ssePath, "GET", { "Last-Event-ID": String(Number(id) - 1) });
      expect(replay.status).toBe(200);
      const replayReader = replay.body!.getReader();
      try {
        expect(await readSSEFrame(replayReader)).toBe(": connected\n\n");
        const replayedFrame = await readSSEFrame(replayReader);
        expect(replayedFrame === `id: ${id}\nevent: chunk_ready\ndata: ${JSON.stringify(ready)}\n\n`).toBe(true);
      } finally {
        await replayReader.cancel();
      }

      expect((await SELF.fetch(`${ORIGIN}${chunkPath}`, { headers: senderHeaders })).status).toBe(401);
      const legacy = await ownerFetch(chunkPath);
      expect(legacy.status).toBe(200);
      const legacyPath = await expectDownload(await legacy.json<Grant>());
      if (inlinePath) expect(legacyPath).toBe(inlinePath);
      expect((await ownerFetch(`${transferPath}/ack`, "POST")).status).toBe(204);
    } finally {
      await reader.cancel();
    }
  });

  it.each([
    { code: "payload_too_large", status: 413, size: 1024 * 1024 + 1 },
    { code: "chunk_too_large", status: 413, size: 1024 * 1024 + 17 },
    { code: "size_mismatch", status: 400, size: 0 },
  ])("isolates downloads and clears only the rejected chunk ($code)", async ({ code, status, size }) => {
    const owner = await importSeedKey(vector.keys.recipient.seed);
    const mailboxId = (await deriveMailboxId(ORIGIN, owner.pub))!;
    const token = "delivery-token-chunk-commit-check";
    const mib = 1024 * 1024;
    const transfersPath = `/v1/relay/mailboxes/${mailboxId}/transfers`;
    const senderPath = `/v1/relay/mailboxes/${mailboxId}/senders/${await tokenHashHex(token)}`;
    const ownerFetch = async (path: string, method = "GET") => SELF.fetch(`${ORIGIN}${path}`, {
      method,
      headers: await signOwnerHeaders(owner, method, path, new Uint8Array(0), crypto.randomUUID()),
    });
    expect((await ownerFetch(senderPath, "PUT")).status).toBe(204);

    const envelope = {
      ...vector.transfer.envelope,
      transfer_id: crypto.randomUUID().replaceAll("-", ""),
      expires_ms: Date.now() + 60_000,
      chunk_size: mib,
      total_ciphertext_bytes: 2 * mib,
    };
    const senderHeaders = { Authorization: `Bearer ${token}` };
    const create = await SELF.fetch(`${ORIGIN}${transfersPath}`, {
      method: "POST",
      headers: senderHeaders,
      body: JSON.stringify(envelope),
    });
    expect(create.status).toBe(200);
    const { upload_urls: uploads } = await create.json<{ upload_urls: { url: string }[] }>();
    const transferPath = `${transfersPath}/${envelope.transfer_id}`;
    const chunkPath = (index: number) => `${transferPath}/chunks/${index}`;
    const upload = async (index: number, count: number, value: number) => {
      expect((await fetch(uploads[index].url, { method: "PUT", body: new Uint8Array(count).fill(value) })).status)
        .toBe(200);
    };
    const commit = (index: number) => SELF.fetch(`${ORIGIN}${chunkPath(index)}/commit`, {
      method: "POST",
      headers: senderHeaders,
    });
    const getGrant = async (index: number) => {
      const response = await ownerFetch(chunkPath(index));
      expect(response.status).toBe(200);
      return response.json<{ url: string; size: number }>();
    };
    const expectDownload = async (grant: { url: string; size: number }, count: number, value: number) => {
      expect(grant.size).toBe(count);
      const download = await fetch(grant.url);
      expect(download.status).toBe(200);
      const bytes = new Uint8Array(await download.arrayBuffer());
      expect(bytes.byteLength).toBe(count);
      expect(bytes.every((byte) => byte === value)).toBe(true);
    };

    await upload(0, mib, 10);
    await upload(1, mib, 20);
    expect((await commit(0)).status).toBe(204);
    expect((await commit(1)).status).toBe(204);
    const firstGrant = await getGrant(0);
    expect((await commit(0)).status).toBe(204);
    await expectDownload(firstGrant, mib, 10);
    await expectDownload(await getGrant(1), mib, 20);

    // The sender may reuse its PUT grant. Existing and new GET grants still return the committed bytes.
    await upload(0, size, 30);
    await expectDownload(firstGrant, mib, 10);
    await expectDownload(await getGrant(0), mib, 10);

    // Commit a replacement for the other index while deletion of the rejected upload is in flight.
    const rejectedPath = new URL(uploads[0].url).pathname;
    await upload(1, mib - 1, 40);
    onStorageDelete = async (path) => {
      if (path === rejectedPath) expect((await commit(1)).status).toBe(204);
    };
    const rejected = await commit(0);
    onStorageDelete = null;
    expect(rejected.status).toBe(status);
    expect(await rejected.json()).toEqual({ error: code });
    expect((await ownerFetch(chunkPath(0))).status).toBe(404);
    expect((await fetch(firstGrant.url)).status).toBe(404);
    await expectDownload(await getGrant(1), mib - 1, 40);
    const listed = await ownerFetch(transfersPath);
    const { transfers } = await listed.json<{ transfers: { transfer_id: string; available_bitmap: string }[] }>();
    expect(transfers.find((tr) => tr.transfer_id === envelope.transfer_id)?.available_bitmap).toBe("Ag");

    // The rejected size no longer reserves bytes when the surviving chunk is recommitted.
    await upload(1, mib + 1, 50);
    expect((await commit(1)).status).toBe(204);
    await upload(0, mib - 1, 60);
    expect((await commit(0)).status).toBe(204);
    await expectDownload(await getGrant(0), mib - 1, 60);
    await expectDownload(await getGrant(1), mib + 1, 50);
    expect((await ownerFetch(`${transferPath}/ack`, "POST")).status).toBe(204);
    expect(mockGlobalObjects.size).toBe(0);
  });

  it("routes CN senders to COS bucket, supports cross-region overseas download, and cleans up exact bucket on ACK and Alarm", async () => {
    const owner = await importSeedKey(vector.keys.recipient.seed);
    const mailboxId = (await deriveMailboxId(ORIGIN, owner.pub))!;

    const deliveryToken = "cn-geo-token-0123456789abcdef0123456789";
    const tokHash = await tokenHashHex(deliveryToken);
    const senderPath = `/v1/relay/mailboxes/${mailboxId}/senders/${tokHash}`;
    const putResp = await worker.fetch(
      withCfCountry(
        new Request(`${ORIGIN}${senderPath}`, {
          method: "PUT",
          headers: await signOwnerHeaders(owner, "PUT", senderPath, new Uint8Array(0), "cf-nonce-cn-sender"),
        }),
        "US"
      ),
      env
    );
    expect(putResp.status).toBe(204);

    // 1. CN sender creates transfer (and tries to spoof X-Internal-Storage-Profile: global -> must be ignored!).
    const ct0 = hexToBytes(vector.transfer.ciphertexts_hex[0]);
    const nowMs = Date.now();
    const cnEnvPayload = {
      ...vector.transfer.envelope,
      transfer_id: "11112222333344445555666677778888",
      created_ms: nowMs,
      expires_ms: nowMs + 60_000,
      total_chunks: 1,
      chunk_size: ct0.length,
      total_ciphertext_bytes: ct0.length,
      chunk_hashes: [vector.transfer.envelope.chunk_hashes[0]],
    };
    const cnCreateResp = await worker.fetch(
      withCfCountry(
        new Request(`${ORIGIN}/v1/relay/mailboxes/${mailboxId}/transfers`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${deliveryToken}`,
            "Content-Type": "application/json",
            "X-Internal-Storage-Profile": "global",
          },
          body: JSON.stringify(cnEnvPayload),
        }),
        "CN"
      ),
      env
    );
    expect(cnCreateResp.status).toBe(200);
    const cnCreated = (await cnCreateResp.json()) as { upload_urls: Array<{ url: string }> };
    expect(new URL(cnCreated.upload_urls[0].url).origin).toBe(MOCK_CN_S3_ORIGIN);

    // Upload chunk to COS and commit (even if commit arrives from non-CN edge, it uses transfer's stored 'cn' profile!).
    const putCn = await fetch(cnCreated.upload_urls[0].url, { method: "PUT", body: ct0 });
    expect(putCn.status).toBe(200);
    expect(mockCnObjects.size).toBe(1);
    expect(mockGlobalObjects.size).toBe(0);

    const commitCn = await worker.fetch(
      withCfCountry(
        new Request(`${ORIGIN}/v1/relay/mailboxes/${mailboxId}/transfers/${cnEnvPayload.transfer_id}/chunks/0/commit`, {
          method: "POST",
          headers: { Authorization: `Bearer ${deliveryToken}` },
        }),
        "US"
      ),
      env
    );
    expect(commitCn.status).toBe(204);

    // 2. Overseas (US) receiver downloads cross-region -> presigned GET MUST point to COS!
    const dlPath = `/v1/relay/mailboxes/${mailboxId}/transfers/${cnEnvPayload.transfer_id}/chunks/0`;
    const dlResp = await worker.fetch(
      withCfCountry(
        new Request(`${ORIGIN}${dlPath}`, {
          method: "GET",
          headers: await signOwnerHeaders(owner, "GET", dlPath, new Uint8Array(0), "cf-nonce-cn-dl"),
        }),
        "US"
      ),
      env
    );
    expect(dlResp.status).toBe(200);
    const dlGrant = (await dlResp.json()) as { url: string };
    expect(new URL(dlGrant.url).origin).toBe(MOCK_CN_S3_ORIGIN);
    const gotBytes = new Uint8Array(await (await fetch(dlGrant.url)).arrayBuffer());
    expect(gotBytes).toEqual(ct0);

    // 3. Overseas ACK deletes object from COS bucket.
    const ackPath = `/v1/relay/mailboxes/${mailboxId}/transfers/${cnEnvPayload.transfer_id}/ack`;
    const ackResp = await worker.fetch(
      withCfCountry(
        new Request(`${ORIGIN}${ackPath}`, {
          method: "POST",
          headers: await signOwnerHeaders(owner, "POST", ackPath, new Uint8Array(0), "cf-nonce-cn-ack"),
        }),
        "US"
      ),
      env
    );
    expect(ackResp.status).toBe(204);
    expect(mockCnObjects.size).toBe(0);

    // 4. Create BOTH a CN transfer and a Global transfer with short TTL, then trigger DO Alarm -> both buckets cleaned!
    const expNow = Date.now();
    const expCnEnv = {
      ...cnEnvPayload,
      transfer_id: "aaaa1111bbbb2222cccc3333dddd4444",
      created_ms: expNow,
      expires_ms: expNow + 50,
    };
    const expGlobalEnv = {
      ...cnEnvPayload,
      transfer_id: "eeee5555ffff66660000777711118888",
      created_ms: expNow,
      expires_ms: expNow + 50,
    };

    const r1 = await worker.fetch(
      withCfCountry(
        new Request(`${ORIGIN}/v1/relay/mailboxes/${mailboxId}/transfers`, {
          method: "POST",
          headers: { Authorization: `Bearer ${deliveryToken}`, "Content-Type": "application/json" },
          body: JSON.stringify(expCnEnv),
        }),
        "CN"
      ),
      env
    );
    expect(r1.status).toBe(200);
    const c1 = (await r1.json()) as { upload_urls: Array<{ url: string }> };
    expect(new URL(c1.upload_urls[0].url).origin).toBe(MOCK_CN_S3_ORIGIN);
    await fetch(c1.upload_urls[0].url, { method: "PUT", body: ct0 });

    const r2 = await worker.fetch(
      withCfCountry(
        new Request(`${ORIGIN}/v1/relay/mailboxes/${mailboxId}/transfers`, {
          method: "POST",
          headers: { Authorization: `Bearer ${deliveryToken}`, "Content-Type": "application/json" },
          body: JSON.stringify(expGlobalEnv),
        }),
        "SG"
      ),
      env
    );
    expect(r2.status).toBe(200);
    const c2 = (await r2.json()) as { upload_urls: Array<{ url: string }> };
    expect(new URL(c2.upload_urls[0].url).origin).toBe(MOCK_S3_ORIGIN);
    await fetch(c2.upload_urls[0].url, { method: "PUT", body: ct0 });

    expect(mockCnObjects.size).toBe(1);
    expect(mockGlobalObjects.size).toBe(1);

    await new Promise((r) => setTimeout(r, 80));
    const stub = env.MAILBOX_DO.get(env.MAILBOX_DO.idFromName(mailboxId));
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(mockCnObjects.size).toBe(0);
    expect(mockGlobalObjects.size).toBe(0);
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
    expect(mockGlobalObjects.size).toBe(1);

    await new Promise((r) => setTimeout(r, 80));
    const stub = env.MAILBOX_DO.get(env.MAILBOX_DO.idFromName(mailboxId));
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect(mockGlobalObjects.size).toBe(0);
  });

  it("enforces Cloud API key verification: allow, deny, cache, 503 fail-closed, max_transfer_bytes cap, and no raw key leakage", async () => {
    const rawAllowKey = "uc_live_cf_allowed_key_secret_abc";
    const rawDenyKey = "uc_live_cf_denied_key_secret_xyz";
    const allowHash = bytesToHex(await sha256(utf8Bytes(rawAllowKey)));
    const denyHash = bytesToHex(await sha256(utf8Bytes(rawDenyKey)));

    let cloudCalls = 0;
    let forceCloudStatus = 200;
    const seenBodies: string[] = [];

    cloudHandler = async (req: Request) => {
      cloudCalls++;
      expect(req.headers.get("Authorization")).toBe("Bearer cf-cloud-secret");
      const rawBody = await req.text();
      seenBodies.push(rawBody);
      if (forceCloudStatus !== 200) {
        return new Response("upstream error", { status: forceCloudStatus });
      }
      const parsed = JSON.parse(rawBody) as { key_hash: string };
      if (parsed.key_hash === allowHash) {
        return Response.json({
          allowed: true,
          subject: "usr_cloud_1",
          key_id: "key_cloud_1",
          max_transfer_bytes: 12,
        });
      }
      if (parsed.key_hash === denyHash) {
        return Response.json({ allowed: false, reason: "revoked" });
      }
      return Response.json({ allowed: false, reason: "unknown" });
    };

    const cloudEnv: Env = {
      ...env,
      CLOUD_VERIFY_URL: MOCK_CLOUD_VERIFY_URL,
      CLOUD_VERIFY_SECRET: "cf-cloud-secret",
      CLOUD_VERIFY_CACHE_TTL_SEC: "60",
      RELAY_ACCESS_KEY: "static-override-key",
    };

    // 1. Missing CLOUD_VERIFY_SECRET fails closed with 503.
    const brokenEnv: Env = { ...env, CLOUD_VERIFY_URL: MOCK_CLOUD_VERIFY_URL, CLOUD_VERIFY_SECRET: undefined };
    const brokenRes = await verifyCloudAccessKey(rawAllowKey, brokenEnv);
    expect(brokenRes).toEqual({ allowed: false, status: 503, error: "auth_unavailable" });

    // 2. Missing X-Unic-Relay-Key -> 401 without calling Cloud.
    const missingRes = await verifyCloudAccessKey(null, cloudEnv);
    expect(missingRes).toEqual({ allowed: false, status: 401, error: "unauthorized" });
    expect(cloudCalls).toBe(0);

    // 3. Static RELAY_ACCESS_KEY matches immediately without calling Cloud.
    const staticRes = await verifyCloudAccessKey("static-override-key", cloudEnv);
    expect(staticRes.allowed).toBe(true);
    expect(cloudCalls).toBe(0);

    // 4. Allowed Cloud key -> cached for 60s.
    const t0 = 1_700_000_000_000;
    const allow1 = await verifyCloudAccessKey(rawAllowKey, cloudEnv, { nowMs: t0 });
    expect(allow1).toEqual({
      allowed: true,
      status: 200,
      subject: "usr_cloud_1",
      keyId: "key_cloud_1",
      maxTransferBytes: 12,
      cloudKeyHash: allowHash,
    });
    expect(cloudCalls).toBe(1);

    const allowCached = await verifyCloudAccessKey(rawAllowKey, cloudEnv, { nowMs: t0 + 30_000 });
    expect(allowCached.allowed).toBe(true);
    expect(cloudCalls).toBe(1);

    const allowRefreshed = await verifyCloudAccessKey(rawAllowKey, cloudEnv, { nowMs: t0 + 61_000 });
    expect(allowRefreshed.allowed).toBe(true);
    expect(cloudCalls).toBe(2);

    // 5. Denied Cloud key -> 401 and negative-cached for 10s.
    const deny1 = await verifyCloudAccessKey(rawDenyKey, cloudEnv, { nowMs: t0 });
    expect(deny1).toEqual({ allowed: false, status: 401, error: "unauthorized" });
    expect(cloudCalls).toBe(3);

    const denyCached = await verifyCloudAccessKey(rawDenyKey, cloudEnv, { nowMs: t0 + 5_000 });
    expect(denyCached.allowed).toBe(false);
    expect(cloudCalls).toBe(3);

    const denyExpired = await verifyCloudAccessKey(rawDenyKey, cloudEnv, { nowMs: t0 + 11_000 });
    expect(denyExpired.allowed).toBe(false);
    expect(cloudCalls).toBe(4);

    // 6. Cloud 5xx -> fail closed 503 and NOT cached.
    forceCloudStatus = 502;
    const err1 = await verifyCloudAccessKey("uc_live_outage_key", cloudEnv, { nowMs: t0 });
    expect(err1).toEqual({ allowed: false, status: 503, error: "auth_unavailable" });
    const err2 = await verifyCloudAccessKey("uc_live_outage_key", cloudEnv, { nowMs: t0 + 1_000 });
    expect(err2).toEqual({ allowed: false, status: 503, error: "auth_unavailable" });
    expect(cloudCalls).toBe(6);
    forceCloudStatus = 200;

    // 7. Verify NO raw API key was ever sent to Cloud.
    for (const body of seenBodies) {
      expect(body).not.toContain(rawAllowKey);
      expect(body).not.toContain(rawDenyKey);
      expect(body).not.toContain("uc_live_");
    }

    // 8. End-to-end Worker -> DO enforcement of per-key max_transfer_bytes (12 bytes) & X-Internal-* stripping.
    const owner = await importSeedKey(vector.keys.recipient.seed);
    const mailboxId = (await deriveMailboxId(ORIGIN, owner.pub))!;
    const deliveryToken = "cloud-cap-token-0123456789abcdef012345";
    const tokHash = await tokenHashHex(deliveryToken);
    const senderPath = `/v1/relay/mailboxes/${mailboxId}/senders/${tokHash}`;
    const putResp = await worker.fetch(
      new Request(`${ORIGIN}${senderPath}`, {
        method: "PUT",
        headers: {
          ...(await signOwnerHeaders(owner, "PUT", senderPath, new Uint8Array(0), "cf-nonce-cloud-cap")),
          "X-Unic-Relay-Key": rawAllowKey,
        },
      }),
      cloudEnv
    );
    expect(putResp.status).toBe(204);

    const nowMs = Date.now();
    const overCapEnv = {
      ...vector.transfer.envelope,
      transfer_id: "99998888777766665555444433332222",
      created_ms: nowMs,
      expires_ms: nowMs + 60_000,
    };
    const cappedResp = await worker.fetch(
      new Request(`${ORIGIN}/v1/relay/mailboxes/${mailboxId}/transfers`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${deliveryToken}`,
          "Content-Type": "application/json",
          "X-Unic-Relay-Key": rawAllowKey,
          // Client attempts to spoof a huge internal cap -> must be stripped & overwritten!
          "X-Internal-Max-Transfer-Bytes": "999999999",
        },
        body: JSON.stringify(overCapEnv),
      }),
      cloudEnv
    );
    expect(cappedResp.status).toBe(413);
    expect(await cappedResp.json()).toEqual({ error: "payload_too_large" });
  });

  it("enforces optional RATE_LIMITER binding with 429 and Retry-After: 60 keyed by Cloud subject or CF-Connecting-IP", async () => {
    const seenKeys: string[] = [];
    let allowLimit = true;
    const rateLimitedEnv: Env = {
      ...env,
      RATE_LIMITER: {
        async limit({ key }) {
          seenKeys.push(key);
          return { success: allowLimit };
        },
      },
    };

    const mb = vector.keys.recipient.mailbox_id;
    // Allowed request keyed by CF-Connecting-IP.
    const r1 = await worker.fetch(
      new Request(`${ORIGIN}/v1/relay/mailboxes/${mb}/transfers`, {
        headers: { "CF-Connecting-IP": "203.0.113.9" },
      }),
      rateLimitedEnv
    );
    expect(r1.status).toBe(401); // Passed rate limit, failed owner auth.
    expect(seenKeys).toEqual(["203.0.113.9"]);

    // Rate-limited request returns 429 JSON + Retry-After: 60.
    allowLimit = false;
    const r2 = await worker.fetch(
      new Request(`${ORIGIN}/v1/relay/mailboxes/${mb}/transfers`, {
        headers: { "CF-Connecting-IP": "203.0.113.9" },
      }),
      rateLimitedEnv
    );
    expect(r2.status).toBe(429);
    expect(r2.headers.get("Retry-After")).toBe("60");
    expect(await r2.json()).toEqual({ error: "rate_limited" });

    // Cloud-verified request uses Cloud subject as rate-limit key.
    cloudHandler = async () =>
      Response.json({ allowed: true, subject: "user-rl-subject", key_id: "k1" });
    const cloudRateLimitedEnv: Env = {
      ...rateLimitedEnv,
      CLOUD_VERIFY_URL: MOCK_CLOUD_VERIFY_URL,
      CLOUD_VERIFY_SECRET: "rl-secret",
    };
    const r3 = await worker.fetch(
      new Request(`${ORIGIN}/v1/relay/mailboxes/${mb}/transfers`, {
        headers: {
          "X-Unic-Relay-Key": "uc_live_rl_key",
          "CF-Connecting-IP": "203.0.113.9",
        },
      }),
      cloudRateLimitedEnv
    );
    expect(r3.status).toBe(429);
    expect(seenKeys[seenKeys.length - 1]).toBe("user-rl-subject");
  });

  it("safely migrates existing Durable Object transfers_v2 table lacking storage_profile column", async () => {
    const owner = await importSeedKey(vector.keys.sender.seed);
    const mailboxId = (await deriveMailboxId(ORIGIN, owner.pub))!;
    const stub = env.MAILBOX_DO.get(env.MAILBOX_DO.idFromName(mailboxId));

    const migratedProfile = await runInDurableObject(stub, async (instance, state) => {
      // Simulate a pre-migration DO SQLite database without storage_profile column.
      state.storage.sql.exec("DROP TABLE IF EXISTS transfers_v2");
      state.storage.sql.exec(`
        CREATE TABLE transfers_v2 (
          transfer_id TEXT PRIMARY KEY,
          sender_hash TEXT NOT NULL,
          envelope_json TEXT NOT NULL,
          chunk_sizes_json TEXT NOT NULL,
          available_b64 TEXT NOT NULL,
          total_chunks INTEGER NOT NULL,
          chunk_size INTEGER NOT NULL,
          total_ciphertext_bytes INTEGER NOT NULL,
          expires_at_ms INTEGER NOT NULL
        );
      `);
      state.storage.sql.exec(
        `INSERT INTO transfers_v2 (
          transfer_id, sender_hash, envelope_json, chunk_sizes_json,
          available_b64, total_chunks, chunk_size, total_ciphertext_bytes, expires_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        "0123456789abcdef0123456789abcdef",
        "0".repeat(64),
        JSON.stringify(vector.transfer.envelope),
        "{}",
        "AA",
        1,
        1024,
        1024,
        Date.now() + 60_000
      );

      // Run idempotent constructor schema migration.
      (instance as unknown as { ensureSchema(): void }).ensureSchema();

      const cols = state.storage.sql.exec<{ name: string }>("PRAGMA table_info(transfers_v2)").toArray();
      expect(cols.some((c) => c.name === "storage_profile")).toBe(true);

      const rows = state.storage.sql
        .exec<{ storage_profile: string }>(
          "SELECT storage_profile FROM transfers_v2 WHERE transfer_id = ?",
          "0123456789abcdef0123456789abcdef"
        )
        .toArray();
      return rows[0]?.storage_profile;
    });

    expect(migratedProfile).toBe("global");
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
