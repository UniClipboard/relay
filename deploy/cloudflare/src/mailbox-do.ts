// SPDX-License-Identifier: AGPL-3.0-only

import { DurableObject } from "cloudflare:workers";
import { isPubKeyAllowed, parseAllowedPubKeys } from "./auth";
import {
  base64UrlDecode,
  decodeBitmap,
  decodeSingleFrame,
  encodeBitmap,
  type Envelope,
  GCM_TAG_SIZE,
  hasBit,
  MAX_CHUNK_SIZE,
  MAX_CHUNKS,
  MAX_ENVELOPE_JSON_BYTES,
  MIN_CHUNK_SIZE,
  newBitmap,
  NONCE_REPLAY_WINDOW_MS,
  normalizeRelayOrigin,
  setBit,
  sha256,
  SINGLE_CHUNK_THRESHOLD,
  timingSafeEqualBytes,
  tokenHashHex,
  utf8Bytes,
  validHex64,
  validMailboxId,
  validTransferId,
  verifyOwnerAuth,
  VERSION,
} from "./crypto";

const DEFAULT_MAX_TRANSFER_BYTES = 25 * 1024 * 1024;
const DEFAULT_TTL_SEC = 600;
const DEFAULT_MAX_TTL_SEC = 1800;
const DEFAULT_MAX_SENDERS = 64;
const DEFAULT_MAX_TRANSFERS = 32;
const DEFAULT_EVENT_BUFFER = 128;
const DEFAULT_KEEPALIVE_MS = 25_000;

interface SSEEvent {
  id: string;
  event: string;
  transfer_id: string;
  envelope?: Envelope;
  chunk_index?: number;
  available_bitmap?: string;
  expires_at_ms?: number;
}

type TransferRow = {
  transfer_id: string;
  sender_hash: string;
  envelope_json: string;
  chunk_hashes_json: string;
  available_b64: string;
  total_chunks: number;
  chunk_size: number;
  expires_at_ms: number;
};

type SenderRow = {
  token_hash: string;
  max_bytes: number;
};

type EventRow = {
  id: number;
  event: string;
  payload_json: string;
};

interface Subscriber {
  send: (chunk: Uint8Array) => void;
  close: () => void;
}

export class MailboxDurableObject extends DurableObject<Env> {
  private readonly subscribers = new Set<Subscriber>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS meta (
          k TEXT PRIMARY KEY,
          v TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS senders (
          token_hash TEXT PRIMARY KEY,
          max_bytes INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transfers (
          transfer_id TEXT PRIMARY KEY,
          sender_hash TEXT NOT NULL,
          envelope_json TEXT NOT NULL,
          chunk_hashes_json TEXT NOT NULL,
          available_b64 TEXT NOT NULL,
          total_chunks INTEGER NOT NULL,
          chunk_size INTEGER NOT NULL,
          expires_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS nonces (
          nonce TEXT PRIMARY KEY,
          expires_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event TEXT NOT NULL,
          payload_json TEXT NOT NULL
        );
      `);
    });
  }

  private cfgInt(raw: string | undefined, fallback: number): number {
    if (!raw) return fallback;
    const n = Number.parseInt(raw, 10);
    return Number.isFinite(n) && n > 0 ? n : fallback;
  }

  private get maxTransferBytes(): number {
    return this.cfgInt(this.env.HYPER_MAX_TRANSFER_BYTES, DEFAULT_MAX_TRANSFER_BYTES);
  }

  private get defaultTtlMs(): number {
    const def = this.cfgInt(this.env.HYPER_DEFAULT_TTL_SEC, DEFAULT_TTL_SEC);
    const max = this.maxTtlMs / 1000;
    return Math.min(def, max) * 1000;
  }

  private get maxTtlMs(): number {
    return this.cfgInt(this.env.HYPER_MAX_TTL_SEC, DEFAULT_MAX_TTL_SEC) * 1000;
  }

  private get maxSenders(): number {
    return this.cfgInt(this.env.HYPER_MAX_SENDERS, DEFAULT_MAX_SENDERS);
  }

  private get maxTransfers(): number {
    return this.cfgInt(this.env.HYPER_MAX_TRANSFERS, DEFAULT_MAX_TRANSFERS);
  }

  private get keepaliveMs(): number {
    return this.cfgInt(this.env.HYPER_KEEPALIVE_MS, DEFAULT_KEEPALIVE_MS);
  }

  private setMailboxId(mailboxId: string): void {
    this.ctx.storage.sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES ('mailbox_id', ?)", mailboxId);
  }

  private getMailboxId(): string | null {
    const rows = this.ctx.storage.sql.exec<{ v: string }>("SELECT v FROM meta WHERE k = 'mailbox_id'").toArray();
    return rows.length > 0 ? rows[0].v : null;
  }

  private r2ChunkKey(mailboxId: string, transferId: string, index: number): string {
    return `mailboxes/${mailboxId}/transfers/${transferId}/chunks/${index}`;
  }

  private async deleteR2Transfer(mailboxId: string, transferId: string, totalChunks: number, availableB64: string): Promise<void> {
    const bm = decodeBitmap(availableB64, totalChunks);
    const keys: string[] = [];
    for (let i = 0; i < totalChunks; i++) {
      if (!bm || hasBit(bm, i)) {
        keys.push(this.r2ChunkKey(mailboxId, transferId, i));
      }
    }
    for (let offset = 0; offset < keys.length; offset += 1000) {
      const batch = keys.slice(offset, offset + 1000);
      if (batch.length > 0) {
        await this.env.CHUNKS_BUCKET.delete(batch);
      }
    }
  }

  private async scheduleNextAlarm(): Promise<void> {
    const tRows = this.ctx.storage.sql
      .exec<{ m: number | null }>("SELECT MIN(expires_at_ms) AS m FROM transfers")
      .toArray();
    const nRows = this.ctx.storage.sql
      .exec<{ m: number | null }>("SELECT MIN(expires_at_ms) AS m FROM nonces")
      .toArray();

    const candidates: number[] = [];
    if (tRows.length > 0 && tRows[0].m !== null) candidates.push(tRows[0].m);
    if (nRows.length > 0 && nRows[0].m !== null) candidates.push(nRows[0].m);

    if (candidates.length === 0) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    const earliest = Math.min(...candidates);
    await this.ctx.storage.setAlarm(Math.max(earliest, Date.now() + 1000));
  }

  private async sweepExpired(mailboxId: string | null, nowMs: number): Promise<void> {
    const expiredTransfers = this.ctx.storage.sql
      .exec<Pick<TransferRow, "transfer_id" | "total_chunks" | "available_b64">>(
        "SELECT transfer_id, total_chunks, available_b64 FROM transfers WHERE expires_at_ms <= ?",
        nowMs
      )
      .toArray();

    if (expiredTransfers.length > 0) {
      this.ctx.storage.sql.exec("DELETE FROM transfers WHERE expires_at_ms <= ?", nowMs);
      const mbId = mailboxId ?? this.getMailboxId();
      if (mbId) {
        await Promise.all(
          expiredTransfers.map((tr) =>
            this.deleteR2Transfer(mbId, tr.transfer_id, tr.total_chunks, tr.available_b64)
          )
        );
      }
    }

    this.ctx.storage.sql.exec("DELETE FROM nonces WHERE expires_at_ms <= ?", nowMs);
  }

  override async alarm(): Promise<void> {
    const nowMs = Date.now();
    await this.sweepExpired(this.getMailboxId(), nowMs);
    await this.scheduleNextAlarm();
  }

  private resolveOrigin(request: Request): string {
    if (this.env.RELAY_ORIGIN && this.env.RELAY_ORIGIN.trim()) {
      return normalizeRelayOrigin(this.env.RELAY_ORIGIN) ?? this.env.RELAY_ORIGIN.trim();
    }
    const url = new URL(request.url);
    const proto = request.headers.get("X-Forwarded-Proto")?.toLowerCase() === "https" ? "https" : url.protocol.replace(/:$/, "");
    return normalizeRelayOrigin(`${proto}://${url.host}`) ?? `${proto}://${url.host}`;
  }

  private async verifyOwner(request: Request, mailboxId: string, body: Uint8Array): Promise<Response | null> {
    const pubKey = request.headers.get("X-Unic-PubKey") ?? "";
    const timestamp = request.headers.get("X-Unic-Timestamp") ?? request.headers.get("X-Unic-TS") ?? "";
    const nonce = request.headers.get("X-Unic-Nonce") ?? "";
    const sig = request.headers.get("X-Unic-Sig") ?? "";

    const allowed = parseAllowedPubKeys(this.env.RELAY_ALLOWED_PUBKEYS);
    if (!isPubKeyAllowed(pubKey, allowed)) {
      return jsonErr(403, "forbidden");
    }

    const url = new URL(request.url);
    const pathAndQuery = url.pathname + url.search;
    const nowMs = Date.now();
    const verifiedPk = await verifyOwnerAuth(
      this.resolveOrigin(request),
      mailboxId,
      request.method,
      pathAndQuery,
      body,
      { pubKey, timestamp, nonce, sig },
      nowMs
    );
    if (!verifiedPk) {
      return jsonErr(401, "unauthorized");
    }

    this.ctx.storage.sql.exec("DELETE FROM nonces WHERE expires_at_ms <= ?", nowMs);
    const dup = this.ctx.storage.sql.exec<{ nonce: string }>("SELECT nonce FROM nonces WHERE nonce = ?", nonce).toArray();
    if (dup.length > 0) {
      return jsonErr(401, "unauthorized");
    }
    this.ctx.storage.sql.exec(
      "INSERT INTO nonces (nonce, expires_at_ms) VALUES (?, ?)",
      nonce,
      nowMs + NONCE_REPLAY_WINDOW_MS
    );
    await this.scheduleNextAlarm();
    return null;
  }

  private bearerToken(request: Request): string | null {
    const auth = (request.headers.get("Authorization") ?? "").trim();
    if (!auth.startsWith("Bearer ")) return null;
    const token = auth.slice("Bearer ".length).trim();
    if (token.length < 16 || token.length > 256) return null;
    return token;
  }

  private async authorizeSender(token: string): Promise<SenderRow | null> {
    const th = await tokenHashHex(token);
    const rows = this.ctx.storage.sql
      .exec<SenderRow>("SELECT token_hash, max_bytes FROM senders WHERE token_hash = ?", th)
      .toArray();
    return rows.length > 0 ? rows[0] : null;
  }

  private publishEvent(evt: Omit<SSEEvent, "id">): void {
    const inserted = this.ctx.storage.sql
      .exec<{ id: number }>(
        "INSERT INTO events (event, payload_json) VALUES (?, ?) RETURNING id",
        evt.event,
        JSON.stringify(evt)
      )
      .one();

    const fullEvent: SSEEvent = {
      id: String(inserted.id),
      ...evt,
    };

    // Retain only the newest DEFAULT_EVENT_BUFFER events.
    this.ctx.storage.sql.exec(
      "DELETE FROM events WHERE id <= ?",
      inserted.id - DEFAULT_EVENT_BUFFER
    );

    const frame = utf8Bytes(`id: ${fullEvent.id}\nevent: ${fullEvent.event}\ndata: ${JSON.stringify(fullEvent)}\n\n`);
    for (const sub of this.subscribers) {
      try {
        sub.send(frame);
      } catch {
        this.subscribers.delete(sub);
      }
    }
  }

  private validateEnvelope(
    env: Envelope,
    expectedTransferId: string,
    maxBytes: number,
    nowMs: number
  ): { hashes: Uint8Array[]; expiresAtMs: number } | Response {
    if (
      !env ||
      env.v !== VERSION ||
      !validTransferId(env.transfer_id) ||
      (expectedTransferId && env.transfer_id !== expectedTransferId)
    ) {
      return jsonErr(400, "invalid_envelope");
    }
    if (
      !Number.isInteger(env.total_chunks) ||
      env.total_chunks <= 0 ||
      env.total_chunks > MAX_CHUNKS ||
      !Array.isArray(env.chunk_hashes) ||
      env.chunk_hashes.length !== env.total_chunks
    ) {
      return jsonErr(400, "invalid_chunk_count");
    }
    if (!Number.isInteger(env.total_ciphertext_bytes) || env.total_ciphertext_bytes <= 0 || env.total_ciphertext_bytes > maxBytes) {
      return jsonErr(413, "payload_too_large");
    }
    if (env.total_chunks === 1) {
      if (!Number.isInteger(env.chunk_size) || env.chunk_size <= 0 || env.chunk_size > SINGLE_CHUNK_THRESHOLD) {
        return jsonErr(400, "invalid_chunk_size");
      }
    } else {
      if (!Number.isInteger(env.chunk_size) || env.chunk_size < MIN_CHUNK_SIZE || env.chunk_size > MAX_CHUNK_SIZE) {
        return jsonErr(400, "invalid_chunk_size");
      }
    }

    const hashes: Uint8Array[] = [];
    for (const hs of env.chunk_hashes) {
      if (typeof hs !== "string") return jsonErr(400, "invalid_chunk_hash");
      const hb = base64UrlDecode(hs);
      if (!hb || hb.length !== 32) return jsonErr(400, "invalid_chunk_hash");
      hashes.push(hb);
    }

    let expiresAtMs = nowMs + this.defaultTtlMs;
    if (env.expires_ms > 0) {
      if (nowMs >= env.expires_ms) {
        return jsonErr(400, "expired");
      }
      expiresAtMs = Math.min(env.expires_ms, nowMs + this.maxTtlMs);
    }

    return { hashes, expiresAtMs };
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const prefix = "/v1/relay/mailboxes/";
    if (!url.pathname.startsWith(prefix)) {
      return jsonErr(404, "not_found");
    }
    const parts = url.pathname.slice(prefix.length).split("/");
    if (parts.length < 2 || !validMailboxId(parts[0])) {
      return jsonErr(400, "invalid_path");
    }
    const mailboxId = parts[0];
    this.setMailboxId(mailboxId);

    if (parts.length === 3 && parts[1] === "senders") {
      if (request.method === "PUT") return this.handlePutSender(request, mailboxId, parts[2]);
      if (request.method === "DELETE") return this.handleDeleteSender(request, mailboxId, parts[2]);
      return jsonErr(405, "method_not_allowed");
    }

    if (parts.length === 2 && parts[1] === "events") {
      if (request.method !== "GET") return jsonErr(405, "method_not_allowed");
      return this.handleEvents(request, mailboxId);
    }

    if (parts.length === 2 && parts[1] === "transfers") {
      if (request.method === "GET") return this.handleListTransfers(request, mailboxId);
      if (request.method === "POST") return this.handleCreateTransfer(request, mailboxId);
      return jsonErr(405, "method_not_allowed");
    }

    if (parts.length === 4 && parts[1] === "transfers" && parts[3] === "single") {
      if (request.method !== "PUT") return jsonErr(405, "method_not_allowed");
      if (!validTransferId(parts[2])) return jsonErr(400, "invalid_transfer_id");
      return this.handleSingleTransfer(request, mailboxId, parts[2]);
    }

    if (parts.length === 5 && parts[1] === "transfers" && parts[3] === "chunks") {
      if (!validTransferId(parts[2])) return jsonErr(400, "invalid_transfer_id");
      if (!/^\d+$/.test(parts[4])) return jsonErr(400, "invalid_chunk_index");
      const idx = Number.parseInt(parts[4], 10);
      if (idx < 0 || idx >= MAX_CHUNKS) return jsonErr(400, "invalid_chunk_index");
      if (request.method === "PUT") return this.handleUploadChunk(request, mailboxId, parts[2], idx);
      if (request.method === "GET") return this.handleDownloadChunk(request, mailboxId, parts[2], idx);
      return jsonErr(405, "method_not_allowed");
    }

    if (parts.length === 4 && parts[1] === "transfers" && parts[3] === "ack") {
      if (request.method !== "POST") return jsonErr(405, "method_not_allowed");
      if (!validTransferId(parts[2])) return jsonErr(400, "invalid_transfer_id");
      return this.handleAckTransfer(request, mailboxId, parts[2]);
    }

    if (parts.length === 3 && parts[1] === "transfers") {
      if (request.method !== "DELETE") return jsonErr(405, "method_not_allowed");
      if (!validTransferId(parts[2])) return jsonErr(400, "invalid_transfer_id");
      return this.handleDeleteTransfer(request, mailboxId, parts[2]);
    }

    return jsonErr(404, "not_found");
  }

  private async handlePutSender(request: Request, mailboxId: string, tokenHash: string): Promise<Response> {
    if (!validHex64(tokenHash)) return jsonErr(400, "invalid_token_hash");
    const body = await readLimited(request.body, 4096);
    if (body === null) return jsonErr(413, "body_too_large");

    const authErr = await this.verifyOwner(request, mailboxId, body);
    if (authErr) return authErr;

    let maxBytes = this.maxTransferBytes;
    if (body.length > 0) {
      try {
        const parsed = JSON.parse(new TextDecoder().decode(body)) as { max_bytes?: number };
        if (parsed.max_bytes !== undefined) {
          if (typeof parsed.max_bytes !== "number" || parsed.max_bytes < 0) {
            return jsonErr(400, "invalid_json");
          }
          if (parsed.max_bytes > 0 && parsed.max_bytes < maxBytes) {
            maxBytes = Math.floor(parsed.max_bytes);
          }
        }
      } catch {
        return jsonErr(400, "invalid_json");
      }
    }

    const exists = this.ctx.storage.sql
      .exec<{ token_hash: string }>("SELECT token_hash FROM senders WHERE token_hash = ?", tokenHash)
      .toArray();
    if (exists.length === 0) {
      const count = this.ctx.storage.sql.exec<{ c: number }>("SELECT COUNT(*) AS c FROM senders").one().c;
      if (count >= this.maxSenders) {
        return jsonErr(429, "too_many_senders");
      }
    }

    this.ctx.storage.sql.exec(
      "INSERT OR REPLACE INTO senders (token_hash, max_bytes) VALUES (?, ?)",
      tokenHash,
      maxBytes
    );
    return new Response(null, { status: 204 });
  }

  private async handleDeleteSender(request: Request, mailboxId: string, tokenHash: string): Promise<Response> {
    if (!validHex64(tokenHash)) return jsonErr(400, "invalid_token_hash");
    const body = await readLimited(request.body, 1024);
    if (body === null) return jsonErr(413, "body_too_large");

    const authErr = await this.verifyOwner(request, mailboxId, body);
    if (authErr) return authErr;

    this.ctx.storage.sql.exec("DELETE FROM senders WHERE token_hash = ?", tokenHash);
    return new Response(null, { status: 204 });
  }

  private async handleSingleTransfer(request: Request, mailboxId: string, transferId: string): Promise<Response> {
    const tok = this.bearerToken(request);
    if (!tok) return jsonErr(401, "unauthorized");
    const sender = await this.authorizeSender(tok);
    if (!sender) return jsonErr(403, "forbidden");

    const maxFrame =
      Math.min(sender.max_bytes, SINGLE_CHUNK_THRESHOLD + GCM_TAG_SIZE) + MAX_ENVELOPE_JSON_BYTES + 4;
    const frame = await readLimited(request.body, maxFrame);
    if (frame === null) return jsonErr(413, "payload_too_large");

    const decoded = decodeSingleFrame(frame);
    if (!decoded || decoded.envelope.total_chunks !== 1) {
      return jsonErr(400, "invalid_frame");
    }

    const nowMs = Date.now();
    const validated = this.validateEnvelope(decoded.envelope, transferId, sender.max_bytes, nowMs);
    if (validated instanceof Response) return validated;

    if (decoded.ciphertext.length !== decoded.envelope.total_ciphertext_bytes) {
      return jsonErr(400, "size_mismatch");
    }
    const digest = await sha256(decoded.ciphertext);
    if (!timingSafeEqualBytes(digest, validated.hashes[0])) {
      return jsonErr(400, "chunk_hash_mismatch");
    }

    await this.sweepExpired(mailboxId, nowMs);

    const existing = this.ctx.storage.sql
      .exec<{ transfer_id: string }>("SELECT transfer_id FROM transfers WHERE transfer_id = ?", transferId)
      .toArray();
    if (existing.length > 0) return jsonErr(409, "already_exists");

    const activeCount = this.ctx.storage.sql.exec<{ c: number }>("SELECT COUNT(*) AS c FROM transfers").one().c;
    if (activeCount >= this.maxTransfers) return jsonErr(429, "mailbox_full");

    await this.env.CHUNKS_BUCKET.put(this.r2ChunkKey(mailboxId, transferId, 0), decoded.ciphertext, {
      httpMetadata: { contentType: "application/octet-stream" },
    });

    const bm = newBitmap(1);
    setBit(bm, 0);
    const availableB64 = encodeBitmap(bm);

    this.ctx.storage.sql.exec(
      `INSERT INTO transfers (
        transfer_id, sender_hash, envelope_json, chunk_hashes_json,
        available_b64, total_chunks, chunk_size, expires_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      transferId,
      sender.token_hash,
      JSON.stringify(decoded.envelope),
      JSON.stringify(decoded.envelope.chunk_hashes),
      availableB64,
      1,
      decoded.envelope.chunk_size,
      validated.expiresAtMs
    );
    await this.scheduleNextAlarm();

    this.publishEvent({
      event: "transfer_single_ready",
      transfer_id: transferId,
      envelope: decoded.envelope,
      available_bitmap: availableB64,
      expires_at_ms: validated.expiresAtMs,
    });

    return Response.json({
      transfer_id: transferId,
      expires_at_ms: validated.expiresAtMs,
    });
  }

  private async handleCreateTransfer(request: Request, mailboxId: string): Promise<Response> {
    const tok = this.bearerToken(request);
    if (!tok) return jsonErr(401, "unauthorized");
    const sender = await this.authorizeSender(tok);
    if (!sender) return jsonErr(403, "forbidden");

    const body = await readLimited(request.body, MAX_ENVELOPE_JSON_BYTES);
    if (body === null) return jsonErr(413, "envelope_too_large");

    let env: Envelope;
    try {
      env = JSON.parse(new TextDecoder().decode(body)) as Envelope;
    } catch {
      return jsonErr(400, "invalid_json");
    }

    const nowMs = Date.now();
    const validated = this.validateEnvelope(env, "", sender.max_bytes, nowMs);
    if (validated instanceof Response) return validated;

    await this.sweepExpired(mailboxId, nowMs);

    const existing = this.ctx.storage.sql
      .exec<{ transfer_id: string }>("SELECT transfer_id FROM transfers WHERE transfer_id = ?", env.transfer_id)
      .toArray();
    if (existing.length > 0) return jsonErr(409, "already_exists");

    const activeCount = this.ctx.storage.sql.exec<{ c: number }>("SELECT COUNT(*) AS c FROM transfers").one().c;
    if (activeCount >= this.maxTransfers) return jsonErr(429, "mailbox_full");

    const availableB64 = encodeBitmap(newBitmap(env.total_chunks));
    this.ctx.storage.sql.exec(
      `INSERT INTO transfers (
        transfer_id, sender_hash, envelope_json, chunk_hashes_json,
        available_b64, total_chunks, chunk_size, expires_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      env.transfer_id,
      sender.token_hash,
      JSON.stringify(env),
      JSON.stringify(env.chunk_hashes),
      availableB64,
      env.total_chunks,
      env.chunk_size,
      validated.expiresAtMs
    );
    await this.scheduleNextAlarm();

    this.publishEvent({
      event: "transfer_announced",
      transfer_id: env.transfer_id,
      envelope: env,
      available_bitmap: availableB64,
      expires_at_ms: validated.expiresAtMs,
    });

    return Response.json({
      transfer_id: env.transfer_id,
      expires_at_ms: validated.expiresAtMs,
      max_chunk_bytes: MAX_CHUNK_SIZE + GCM_TAG_SIZE,
    });
  }

  private async handleUploadChunk(
    request: Request,
    mailboxId: string,
    transferId: string,
    index: number
  ): Promise<Response> {
    const tok = this.bearerToken(request);
    if (!tok) return jsonErr(401, "unauthorized");
    const sender = await this.authorizeSender(tok);
    if (!sender) return jsonErr(403, "forbidden");

    const nowMs = Date.now();
    await this.sweepExpired(mailboxId, nowMs);

    const rows = this.ctx.storage.sql
      .exec<TransferRow>("SELECT * FROM transfers WHERE transfer_id = ?", transferId)
      .toArray();
    if (rows.length === 0) return jsonErr(404, "not_found");
    const tr = rows[0];

    if (tr.sender_hash !== sender.token_hash) return jsonErr(403, "forbidden");
    if (index < 0 || index >= tr.total_chunks) return jsonErr(400, "invalid_chunk_index");

    const hashes = JSON.parse(tr.chunk_hashes_json) as string[];
    const wantHash = base64UrlDecode(hashes[index]);
    if (!wantHash || wantHash.length !== 32) return jsonErr(500, "corrupt_metadata");

    const maxChunk = tr.chunk_size + GCM_TAG_SIZE;
    const body = await readLimited(request.body, maxChunk);
    if (body === null) return jsonErr(413, "chunk_too_large");

    const digest = await sha256(body);
    if (!timingSafeEqualBytes(digest, wantHash)) {
      return jsonErr(400, "chunk_hash_mismatch");
    }

    await this.env.CHUNKS_BUCKET.put(this.r2ChunkKey(mailboxId, transferId, index), body, {
      httpMetadata: { contentType: "application/octet-stream" },
    });

    // Re-check transfer existence after async R2 write (may have been ACKed or expired).
    const postRows = this.ctx.storage.sql
      .exec<TransferRow>("SELECT * FROM transfers WHERE transfer_id = ?", transferId)
      .toArray();
    if (postRows.length === 0) {
      await this.env.CHUNKS_BUCKET.delete(this.r2ChunkKey(mailboxId, transferId, index));
      return jsonErr(410, "gone");
    }
    const latest = postRows[0];
    const bm = decodeBitmap(latest.available_b64, latest.total_chunks) ?? newBitmap(latest.total_chunks);
    setBit(bm, index);
    const updatedB64 = encodeBitmap(bm);

    this.ctx.storage.sql.exec(
      "UPDATE transfers SET available_b64 = ? WHERE transfer_id = ?",
      updatedB64,
      transferId
    );

    this.publishEvent({
      event: "chunk_ready",
      transfer_id: transferId,
      chunk_index: index,
      available_bitmap: updatedB64,
      expires_at_ms: latest.expires_at_ms,
    });

    return new Response(null, { status: 204 });
  }

  private async handleListTransfers(request: Request, mailboxId: string): Promise<Response> {
    const authErr = await this.verifyOwner(request, mailboxId, new Uint8Array(0));
    if (authErr) return authErr;

    await this.sweepExpired(mailboxId, Date.now());
    const rows = this.ctx.storage.sql.exec<TransferRow>("SELECT * FROM transfers").toArray();
    const transfers = rows.map((tr) => ({
      transfer_id: tr.transfer_id,
      envelope: JSON.parse(tr.envelope_json) as Envelope,
      available_bitmap: tr.available_b64,
      expires_at_ms: tr.expires_at_ms,
    }));
    return Response.json({ transfers });
  }

  private async handleDownloadChunk(
    request: Request,
    mailboxId: string,
    transferId: string,
    index: number
  ): Promise<Response> {
    const authErr = await this.verifyOwner(request, mailboxId, new Uint8Array(0));
    if (authErr) return authErr;

    await this.sweepExpired(mailboxId, Date.now());
    const rows = this.ctx.storage.sql
      .exec<TransferRow>("SELECT * FROM transfers WHERE transfer_id = ?", transferId)
      .toArray();
    if (rows.length === 0) return jsonErr(404, "not_found");
    const tr = rows[0];
    const bm = decodeBitmap(tr.available_b64, tr.total_chunks);
    if (!bm || !hasBit(bm, index)) return jsonErr(404, "not_found");

    const obj = await this.env.CHUNKS_BUCKET.get(this.r2ChunkKey(mailboxId, transferId, index));
    if (!obj) return jsonErr(404, "not_found");

    return new Response(obj.body, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(obj.size),
      },
    });
  }

  private async handleAckTransfer(request: Request, mailboxId: string, transferId: string): Promise<Response> {
    const body = await readLimited(request.body, 1024);
    if (body === null) return jsonErr(413, "body_too_large");

    const authErr = await this.verifyOwner(request, mailboxId, body);
    if (authErr) return authErr;

    const rows = this.ctx.storage.sql
      .exec<Pick<TransferRow, "total_chunks" | "available_b64">>(
        "SELECT total_chunks, available_b64 FROM transfers WHERE transfer_id = ?",
        transferId
      )
      .toArray();
    if (rows.length > 0) {
      this.ctx.storage.sql.exec("DELETE FROM transfers WHERE transfer_id = ?", transferId);
      await this.deleteR2Transfer(mailboxId, transferId, rows[0].total_chunks, rows[0].available_b64);
      await this.scheduleNextAlarm();
    }
    return new Response(null, { status: 204 });
  }

  private async handleDeleteTransfer(request: Request, mailboxId: string, transferId: string): Promise<Response> {
    const tok = this.bearerToken(request);
    if (tok) {
      const sender = await this.authorizeSender(tok);
      if (!sender) return jsonErr(403, "forbidden");

      const rows = this.ctx.storage.sql
        .exec<Pick<TransferRow, "sender_hash" | "total_chunks" | "available_b64">>(
          "SELECT sender_hash, total_chunks, available_b64 FROM transfers WHERE transfer_id = ?",
          transferId
        )
        .toArray();
      if (rows.length > 0) {
        if (rows[0].sender_hash !== sender.token_hash) return jsonErr(403, "forbidden");
        this.ctx.storage.sql.exec("DELETE FROM transfers WHERE transfer_id = ?", transferId);
        await this.deleteR2Transfer(mailboxId, transferId, rows[0].total_chunks, rows[0].available_b64);
        await this.scheduleNextAlarm();
      }
      return new Response(null, { status: 204 });
    }

    const authErr = await this.verifyOwner(request, mailboxId, new Uint8Array(0));
    if (authErr) return authErr;

    const rows = this.ctx.storage.sql
      .exec<Pick<TransferRow, "total_chunks" | "available_b64">>(
        "SELECT total_chunks, available_b64 FROM transfers WHERE transfer_id = ?",
        transferId
      )
      .toArray();
    if (rows.length > 0) {
      this.ctx.storage.sql.exec("DELETE FROM transfers WHERE transfer_id = ?", transferId);
      await this.deleteR2Transfer(mailboxId, transferId, rows[0].total_chunks, rows[0].available_b64);
      await this.scheduleNextAlarm();
    }
    return new Response(null, { status: 204 });
  }

  private async handleEvents(request: Request, mailboxId: string): Promise<Response> {
    const authErr = await this.verifyOwner(request, mailboxId, new Uint8Array(0));
    if (authErr) return authErr;

    let afterId = 0;
    const rawLastId = (request.headers.get("Last-Event-ID") ?? "").trim();
    if (/^\d+$/.test(rawLastId)) {
      afterId = Number.parseInt(rawLastId, 10);
    }

    const backlogRows =
      afterId > 0
        ? this.ctx.storage.sql
            .exec<EventRow>("SELECT id, event, payload_json FROM events WHERE id > ? ORDER BY id ASC", afterId)
            .toArray()
        : [];

    const keepaliveMs = this.keepaliveMs;
    let subRef: Subscriber | null = null;
    let timer: ReturnType<typeof setInterval> | null = null;

    const cleanup = () => {
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
      if (subRef) {
        this.subscribers.delete(subRef);
        subRef = null;
      }
    };

    const stream = new ReadableStream<Uint8Array>({
      start: (controller) => {
        const sub: Subscriber = {
          send: (chunk: Uint8Array) => {
            try {
              controller.enqueue(chunk);
            } catch {
              cleanup();
            }
          },
          close: () => {
            cleanup();
            try {
              controller.close();
            } catch {
              // Already closed.
            }
          },
        };
        subRef = sub;
        this.subscribers.add(sub);

        controller.enqueue(utf8Bytes(": connected\n\n"));
        for (const row of backlogRows) {
          const parsed = JSON.parse(row.payload_json) as Omit<SSEEvent, "id">;
          const ev: SSEEvent = { id: String(row.id), ...parsed };
          controller.enqueue(utf8Bytes(`id: ${ev.id}\nevent: ${ev.event}\ndata: ${JSON.stringify(ev)}\n\n`));
        }

        timer = setInterval(() => {
          sub.send(utf8Bytes(": keepalive\n\n"));
        }, keepaliveMs);
      },
      cancel: () => {
        cleanup();
      },
    });

    return new Response(stream, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      },
    });
  }
}

async function readLimited(body: ReadableStream<Uint8Array> | null, limit: number): Promise<Uint8Array | null> {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

function jsonErr(status: number, code: string): Response {
  return Response.json({ error: code }, { status });
}
