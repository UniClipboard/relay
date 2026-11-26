// SPDX-License-Identifier: AGPL-3.0-only

import { env, runDurableObjectAlarm, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import vector from "../../../vectors/hybrid-relay-v1.json";
import { isPubKeyAllowed, parseAllowedPubKeys, verifyAccessKey } from "../src/auth";
import worker from "../src/index";
import {
  base64UrlEncode,
  concatBytes,
  deriveMailboxId,
  encodeSingleFrame,
  hexToBytes,
  ownerAuthPayload,
  sha256,
  tokenHashHex,
  utf8Bytes,
} from "../src/crypto";

const ORIGIN = "http://example.com";

// Wrap a 32-byte raw Ed25519 seed in PKCS#8 DER for WebCrypto importKey("pkcs8").
function ed25519SeedToPkcs8(seed: Uint8Array): Uint8Array {
  const prefix = hexToBytes("302e020100300506032b657004220420");
  return concatBytes(prefix, seed);
}

async function importSeedKey(seedHex: string): Promise<{ priv: CryptoKey; pub: Uint8Array }> {
  const seed = hexToBytes(seedHex);
  const priv = await crypto.subtle.importKey("pkcs8", ed25519SeedToPkcs8(seed), { name: "Ed25519" }, false, ["sign"]);
  // Derive public key from deterministic vector when matching, else generate.
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

describe("Cloudflare Worker + Durable Object + R2 Relay HTTP API v1", () => {
  it("serves /healthz without authentication", async () => {
    const resp = await SELF.fetch(`${ORIGIN}/healthz`);
    expect(resp.status).toBe(200);
    const data = (await resp.json()) as { status: string; service: string; runtime: string };
    expect(data).toEqual({
      status: "ok",
      service: "hyper-relay",
      runtime: "cloudflare-workers",
    });
  });

  it("handles full multi-chunk upload, SSE + Last-Event-ID replay, R2 download, ACK immediate delete, and nonce replay rejection", async () => {
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

    // Replaying the exact same Owner Auth nonce must return 401.
    const replayResp = await SELF.fetch(`${ORIGIN}${senderPath}`, {
      method: "PUT",
      headers: { ...putHeaders, "Content-Type": "application/json" },
      body: senderBody,
    });
    expect(replayResp.status).toBe(401);

    // 2. Create multi-chunk transfer with vector ciphertexts & updated live timestamps.
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

    // 3. Upload both chunks and verify R2 storage.
    for (let i = 0; i < vector.transfer.ciphertexts_hex.length; i++) {
      const ct = hexToBytes(vector.transfer.ciphertexts_hex[i]);
      const upResp = await SELF.fetch(
        `${ORIGIN}/v1/relay/mailboxes/${mailboxId}/transfers/${liveEnv.transfer_id}/chunks/${i}`,
        {
          method: "PUT",
          headers: {
            Authorization: `Bearer ${deliveryToken}`,
            "Content-Type": "application/octet-stream",
          },
          body: ct,
        }
      );
      expect(upResp.status).toBe(204);
    }

    // Verify chunk objects exist in R2.
    const r2Key0 = `mailboxes/${mailboxId}/transfers/${liveEnv.transfer_id}/chunks/0`;
    expect(await env.CHUNKS_BUCKET.head(r2Key0)).not.toBeNull();

    // 4. Verify SSE Last-Event-ID replays chunk_ready events (events after id 1).
    const ssePath = `/v1/relay/mailboxes/${mailboxId}/events`;
    const sseHeaders = await signOwnerHeaders(owner, "GET", ssePath, new Uint8Array(0), "cf-nonce-sse-replay");
    const sseResp = await SELF.fetch(`${ORIGIN}${ssePath}`, {
      method: "GET",
      headers: { ...sseHeaders, "Last-Event-ID": "1" },
    });
    expect(sseResp.status).toBe(200);
    expect(sseResp.headers.get("Content-Type")).toBe("text/event-stream");

    const reader = sseResp.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (!buf.includes('"chunk_index":1')) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
    }
    await reader.cancel();
    expect(buf).toContain(": connected");
    expect(buf).toContain("event: chunk_ready");
    expect(buf).toContain('"chunk_index":0');
    expect(buf).toContain('"chunk_index":1');

    // 5. List transfers and download chunks via Owner Auth.
    const listPath = `/v1/relay/mailboxes/${mailboxId}/transfers`;
    const listResp = await SELF.fetch(`${ORIGIN}${listPath}`, {
      method: "GET",
      headers: await signOwnerHeaders(owner, "GET", listPath, new Uint8Array(0), "cf-nonce-list-1"),
    });
    expect(listResp.status).toBe(200);
    const listed = (await listResp.json()) as { transfers: Array<{ transfer_id: string }> };
    expect(listed.transfers).toHaveLength(1);
    expect(listed.transfers[0].transfer_id).toBe(liveEnv.transfer_id);

    for (let i = 0; i < vector.transfer.ciphertexts_hex.length; i++) {
      const dlPath = `/v1/relay/mailboxes/${mailboxId}/transfers/${liveEnv.transfer_id}/chunks/${i}`;
      const dlResp = await SELF.fetch(`${ORIGIN}${dlPath}`, {
        method: "GET",
        headers: await signOwnerHeaders(owner, "GET", dlPath, new Uint8Array(0), `cf-nonce-dl-${i}`),
      });
      expect(dlResp.status).toBe(200);
      const gotBytes = new Uint8Array(await dlResp.arrayBuffer());
      expect(gotBytes).toEqual(hexToBytes(vector.transfer.ciphertexts_hex[i]));
    }

    // 6. ACK transfer and assert R2 objects are deleted immediately.
    const ackPath = `/v1/relay/mailboxes/${mailboxId}/transfers/${liveEnv.transfer_id}/ack`;
    const ackResp = await SELF.fetch(`${ORIGIN}${ackPath}`, {
      method: "POST",
      headers: await signOwnerHeaders(owner, "POST", ackPath, new Uint8Array(0), "cf-nonce-ack-1"),
    });
    expect(ackResp.status).toBe(204);
    expect(await env.CHUNKS_BUCKET.head(r2Key0)).toBeNull();
  });

  it("handles single-chunk fast path and Alarm TTL cleanup of R2 objects", async () => {
    const owner = await importSeedKey(vector.keys.sender.seed);
    const mailboxId = (await deriveMailboxId(ORIGIN, owner.pub))!;

    const deliveryToken = "single-token-0123456789abcdef0123456789";
    const tokHash = await tokenHashHex(deliveryToken);

    const senderPath = `/v1/relay/mailboxes/${mailboxId}/senders/${tokHash}`;
    const putResp = await SELF.fetch(`${ORIGIN}${senderPath}`, {
      method: "PUT",
      headers: await signOwnerHeaders(owner, "PUT", senderPath, new Uint8Array(0), "cf-nonce-single-sender"),
    });
    expect(putResp.status).toBe(204);

    const ct0 = hexToBytes(vector.transfer.ciphertexts_hex[0]);
    const nowMs = Date.now();
    const singleEnv = {
      ...vector.transfer.envelope,
      transfer_id: "abcdef0123456789abcdef0123456789",
      created_ms: nowMs,
      expires_ms: nowMs + 50,
      total_chunks: 1,
      chunk_size: ct0.length,
      total_ciphertext_bytes: ct0.length,
      chunk_hashes: [vector.transfer.envelope.chunk_hashes[0]],
    };
    const frame = encodeSingleFrame(singleEnv, ct0);

    const singleResp = await SELF.fetch(
      `${ORIGIN}/v1/relay/mailboxes/${mailboxId}/transfers/${singleEnv.transfer_id}/single`,
      {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${deliveryToken}`,
          "Content-Type": "application/octet-stream",
        },
        body: frame,
      }
    );
    expect(singleResp.status).toBe(200);

    const r2Key = `mailboxes/${mailboxId}/transfers/${singleEnv.transfer_id}/chunks/0`;
    expect(await env.CHUNKS_BUCKET.head(r2Key)).not.toBeNull();

    // Wait past the 50ms TTL and trigger the DO Alarm.
    await new Promise((r) => setTimeout(r, 80));
    const stub = env.MAILBOX_DO.get(env.MAILBOX_DO.idFromName(mailboxId));
    const ran = await runDurableObjectAlarm(stub);
    expect(ran).toBe(true);

    // R2 object must be deleted by Alarm TTL cleanup.
    expect(await env.CHUNKS_BUCKET.head(r2Key)).toBeNull();
  });

  it("enforces shared X-Unic-Relay-Key and RELAY_ALLOWED_PUBKEYS admission policies", async () => {
    expect(await verifyAccessKey("secret-key-v2", "secret-key-v2")).toBe(true);
    expect(await verifyAccessKey("wrong-key", "secret-key-v2")).toBe(false);
    expect(await verifyAccessKey(null, "secret-key-v2")).toBe(false);
    expect(await verifyAccessKey(null, undefined)).toBe(true);

    const allowed = parseAllowedPubKeys(vector.owner_auth.headers.PubKey);
    expect(isPubKeyAllowed(vector.owner_auth.headers.PubKey, allowed)).toBe(true);
    expect(isPubKeyAllowed(base64UrlEncode(hexToBytes(vector.keys.sender.public)), allowed)).toBe(false);

    // Worker rejects missing/wrong access key with 401 while keeping /healthz open.
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
