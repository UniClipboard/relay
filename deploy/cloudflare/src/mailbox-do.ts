// SPDX-License-Identifier: AGPL-3.0-only

import { DurableObject } from "cloudflare:workers";
import { isPubKeyAllowed, parseAllowedPubKeys, reserveCloudTransfer } from "./auth";
import {
  base64UrlDecode,
  decodeBitmap,
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
import {
  hasS3Profile,
  loadS3ConfigForProfile,
  type ObjectMeta,
  parseStorageProfile,
  resolveStorageProfile,
  S3Client,
  type StorageProfile,
} from "./s3";

const DEFAULT_MAX_TRANSFER_BYTES = 25 * 1024 * 1024;
const DEFAULT_TTL_SEC = 600;
const DEFAULT_MAX_TTL_SEC = 1800;
const DEFAULT_MAX_SENDERS = 64;
const DEFAULT_MAX_TRANSFERS = 32;
const DEFAULT_EVENT_BUFFER = 128;
const DEFAULT_KEEPALIVE_MS = 25_000;
const MAX_INLINE_UPLOAD_URLS = 16;
const OFFICIAL_RELAY_ORIGIN = "https://relay.uniclipboard.app";

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
  chunk_sizes_json: string;
  available_b64: string;
  total_chunks: number;
  chunk_size: number;
  total_ciphertext_bytes: number;
  expires_at_ms: number;
  storage_profile: string;
};

type CommittedChunk = { size: number; key: string; etag: string };
type ChunkSizes = Record<string, number | CommittedChunk>;

function readChunkSizes(tr: TransferRow): ChunkSizes {
  return JSON.parse(tr.chunk_sizes_json) as ChunkSizes;
}

function totalChunkBytes(sizes: ChunkSizes): number {
  return Object.values(sizes).reduce<number>(
    (bytes, chunk) => bytes + (typeof chunk === "number" ? chunk : chunk.size),
    0
  );
}

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
  // Serialize fallback and commit per chunk. Track storage mutations for cleanup.
  private readonly chunkOperations = new Map<string, Map<number, Promise<void> | null>>();
  private readonly deletingTransfers = new Set<string>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ensureSchema();
    });
  }

  private ensureSchema(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        k TEXT PRIMARY KEY,
        v TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS senders (
        token_hash TEXT PRIMARY KEY,
        max_bytes INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS transfers_v2 (
        transfer_id TEXT PRIMARY KEY,
        sender_hash TEXT NOT NULL,
        envelope_json TEXT NOT NULL,
        chunk_sizes_json TEXT NOT NULL,
        available_b64 TEXT NOT NULL,
        total_chunks INTEGER NOT NULL,
        chunk_size INTEGER NOT NULL,
        total_ciphertext_bytes INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        storage_profile TEXT NOT NULL DEFAULT 'global'
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

    const cols = this.ctx.storage.sql
      .exec<{ name: string }>("PRAGMA table_info(transfers_v2)")
      .toArray();
    if (!cols.some((c) => c.name === "storage_profile")) {
      this.ctx.storage.sql.exec(
        "ALTER TABLE transfers_v2 ADD COLUMN storage_profile TEXT NOT NULL DEFAULT 'global'"
      );
    }
  }

  private getS3ClientForProfile(profile: StorageProfile): S3Client | null {
    const cfg = loadS3ConfigForProfile(this.env, profile);
    if (!cfg) return null;
    return new S3Client(cfg);
  }

  private async deleteStoredTransfer(
    mailboxId: string | null,
    transfer: TransferRow
  ): Promise<void> {
    const id = transfer.transfer_id;
    const operations = this.chunkOperations.get(id);
    this.deletingTransfers.add(id);
    this.chunkOperations.delete(id);
    try {
      this.ctx.storage.sql.exec("DELETE FROM transfers_v2 WHERE transfer_id = ?", id);
      // Removing the operation map prevents new mutations by in-flight handlers.
      if (operations) await Promise.allSettled(operations.values());
      const s3 = this.getS3ClientForProfile(parseStorageProfile(transfer.storage_profile));
      if (mailboxId && s3) await this.deleteTransferObjects(s3, mailboxId, transfer);
    } finally {
      this.deletingTransfers.delete(id);
    }
  }

  private async withChunkOperation(
    transferId: string,
    index: number,
    run: (operations: Map<number, Promise<void> | null>) => Promise<Response>
  ): Promise<Response> {
    const operations = this.chunkOperations.get(transferId) ?? new Map<number, Promise<void> | null>();
    if (operations.has(index)) return jsonErr(409, "upload_in_progress");
    operations.set(index, null);
    this.chunkOperations.set(transferId, operations);
    try {
      return await run(operations);
    } finally {
      operations.delete(index);
      if (operations.size === 0 && this.chunkOperations.get(transferId) === operations) {
        this.chunkOperations.delete(transferId);
      }
    }
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

  private get presignTtlSec(): number {
    return this.cfgInt(this.env.S3_PRESIGN_TTL_SEC, 300);
  }

  private presignTtlFor(nowMs: number, expiresAtMs: number, maxPresignTtlSec?: number): number {
    const remainingSec = Math.floor((expiresAtMs - nowMs) / 1000);
    if (remainingSec <= 0) return 1;
    return Math.min(remainingSec, maxPresignTtlSec ?? this.presignTtlSec);
  }

  private setMailboxId(mailboxId: string): void {
    this.ctx.storage.sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES ('mailbox_id', ?)", mailboxId);
  }

  private getMailboxId(): string | null {
    const rows = this.ctx.storage.sql.exec<{ v: string }>("SELECT v FROM meta WHERE k = 'mailbox_id'").toArray();
    return rows.length > 0 ? rows[0].v : null;
  }

  private async scheduleNextAlarm(): Promise<void> {
    const tRows = this.ctx.storage.sql
      .exec<{ m: number | null }>("SELECT MIN(expires_at_ms) AS m FROM transfers_v2")
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
      .exec<TransferRow>(
        "SELECT * FROM transfers_v2 WHERE expires_at_ms <= ?",
        nowMs
      )
      .toArray();

    if (expiredTransfers.length > 0) {
      const mbId = mailboxId ?? this.getMailboxId();
      await Promise.all(expiredTransfers.map((tr) => this.deleteStoredTransfer(mbId, tr)));
    }

    this.ctx.storage.sql.exec("DELETE FROM nonces WHERE expires_at_ms <= ?", nowMs);
  }

  private getTransfer(transferId: string): TransferRow | undefined {
    return this.ctx.storage.sql
      .exec<TransferRow>("SELECT * FROM transfers_v2 WHERE transfer_id = ?", transferId)
      .toArray()[0];
  }

  private getCurrentTransfer(previous: TransferRow): TransferRow | undefined {
    const current = this.getTransfer(previous.transfer_id);
    if (!current ||
        current.envelope_json !== previous.envelope_json ||
        current.expires_at_ms !== previous.expires_at_ms ||
        current.sender_hash !== previous.sender_hash ||
        current.storage_profile !== previous.storage_profile) return undefined;
    return current;
  }

  private saveChunkState(transferId: string, availableB64: string, sizes: ChunkSizes): void {
    this.ctx.storage.sql.exec(
      "UPDATE transfers_v2 SET available_b64 = ?, chunk_sizes_json = ? WHERE transfer_id = ?",
      availableB64,
      JSON.stringify(sizes),
      transferId
    );
  }

  private async deleteTransferObjects(s3: S3Client, mailboxId: string, tr: TransferRow): Promise<void> {
    const keys = Object.values(readChunkSizes(tr)).flatMap((chunk) => typeof chunk === "number" ? [] : [chunk.key]);
    await s3.deleteTransfer(mailboxId, tr.transfer_id, tr.total_chunks, keys);
  }

  private async snapshotChunk(s3: S3Client, uploadKey: string, meta: ObjectMeta): Promise<CommittedChunk> {
    // No upload grant can write this key, including grants issued before the commit.
    const key = `${uploadKey}/committed/${crypto.randomUUID()}`;
    try {
      await s3.copyObject(uploadKey, key, meta.etag);
      const snapshot = await s3.headObject(key);
      if (snapshot?.size !== meta.size) throw new Error("Chunk size changed during copy");
      return { size: snapshot.size, key, etag: meta.etag };
    } catch (error) {
      await s3.deleteObject(key).catch(() => undefined);
      throw error;
    }
  }

  private async removeRejectedChunk(s3: S3Client, uploadKey: string, previous: TransferRow, index: number): Promise<void> {
    await s3.deleteObject(uploadKey).catch(() => undefined);
    const tr = this.getCurrentTransfer(previous);
    if (!tr) return;

    const bm = decodeBitmap(tr.available_b64, tr.total_chunks) ?? newBitmap(tr.total_chunks);
    bm[index >>> 3] &= ~(1 << (index & 7));
    const sizes = readChunkSizes(tr);
    const rejected = sizes[index];
    delete sizes[index];
    this.saveChunkState(tr.transfer_id, encodeBitmap(bm), sizes);
    if (rejected && typeof rejected !== "number") {
      await s3.deleteObject(rejected.key).catch(() => undefined);
    }
  }

  override async alarm(): Promise<void> {
    const nowMs = Date.now();
    await this.sweepExpired(this.getMailboxId(), nowMs);
    await this.scheduleNextAlarm();
  }

  private resolveOrigin(request: Request): string {
    const configured = (this.env.RELAY_ORIGIN ?? "").trim();
    if (configured) {
      return normalizeRelayOrigin(configured) ?? configured;
    }
    const url = new URL(request.url);
    const proto =
      request.headers.get("X-Forwarded-Proto")?.toLowerCase() === "https"
        ? "https"
        : url.protocol.replace(/:$/, "");
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

    this.ctx.storage.sql.exec("DELETE FROM events WHERE id <= ?", inserted.id - DEFAULT_EVENT_BUFFER);

    const frame = utf8Bytes(`id: ${fullEvent.id}\nevent: ${fullEvent.event}\ndata: ${JSON.stringify(fullEvent)}\n\n`);
    for (const sub of this.subscribers) {
      try {
        sub.send(frame);
      } catch {
        this.subscribers.delete(sub);
      }
    }
  }

  private validateEnvelope(env: Envelope, maxBytes: number, nowMs: number): { expiresAtMs: number } | Response {
    if (!env || env.v !== VERSION || !validTransferId(env.transfer_id)) {
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

    for (const hs of env.chunk_hashes) {
      if (typeof hs !== "string") return jsonErr(400, "invalid_chunk_hash");
      const hb = base64UrlDecode(hs);
      if (!hb || hb.length !== 32) return jsonErr(400, "invalid_chunk_hash");
    }

    let expiresAtMs = nowMs + this.defaultTtlMs;
    if (env.expires_ms > 0) {
      if (nowMs >= env.expires_ms) {
        return jsonErr(400, "expired");
      }
      expiresAtMs = Math.min(env.expires_ms, nowMs + this.maxTtlMs);
    }

    return { expiresAtMs };
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

    if (parts.length === 6 && parts[1] === "transfers" && parts[3] === "chunks" && parts[5] === "upload-url") {
      if (request.method !== "POST") return jsonErr(405, "method_not_allowed");
      if (!validTransferId(parts[2])) return jsonErr(400, "invalid_transfer_id");
      const idx = parseChunkIndex(parts[4]);
      if (idx === null) return jsonErr(400, "invalid_chunk_index");
      return this.handleChunkUploadURL(request, mailboxId, parts[2], idx);
    }

    if (parts.length === 6 && parts[1] === "transfers" && parts[3] === "chunks" && parts[5] === "upload" &&
        url.origin === OFFICIAL_RELAY_ORIGIN) {
      if (request.method !== "PUT") return jsonErr(405, "method_not_allowed");
      if (!validTransferId(parts[2])) return jsonErr(400, "invalid_transfer_id");
      const idx = parseChunkIndex(parts[4]);
      if (idx === null) return jsonErr(400, "invalid_chunk_index");
      return this.handleRelayChunkUpload(request, mailboxId, parts[2], idx);
    }

    if (parts.length === 6 && parts[1] === "transfers" && parts[3] === "chunks" && parts[5] === "commit") {
      if (request.method !== "POST") return jsonErr(405, "method_not_allowed");
      if (!validTransferId(parts[2])) return jsonErr(400, "invalid_transfer_id");
      const idx = parseChunkIndex(parts[4]);
      if (idx === null) return jsonErr(400, "invalid_chunk_index");
      return this.handleCommitChunk(request, mailboxId, parts[2], idx);
    }

    if (parts.length === 5 && parts[1] === "transfers" && parts[3] === "chunks") {
      if (request.method !== "GET") return jsonErr(405, "method_not_allowed");
      if (!validTransferId(parts[2])) return jsonErr(400, "invalid_transfer_id");
      const idx = parseChunkIndex(parts[4]);
      if (idx === null) return jsonErr(400, "invalid_chunk_index");
      return this.handleChunkDownloadURL(request, mailboxId, parts[2], idx);
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

  private async handleCreateTransfer(request: Request, mailboxId: string): Promise<Response> {
    const tok = this.bearerToken(request);
    if (!tok) return jsonErr(401, "unauthorized");
    const sender = await this.authorizeSender(tok);
    if (!sender) return jsonErr(403, "forbidden");

    const requestedProfile = parseStorageProfile(request.headers.get("X-Internal-Storage-Profile"));
    const storageProfile = resolveStorageProfile(this.env, requestedProfile);
    const s3 = this.getS3ClientForProfile(storageProfile);
    if (!s3) return jsonErr(503, "s3_not_configured");

    const body = await readLimited(request.body, MAX_ENVELOPE_JSON_BYTES);
    if (body === null) return jsonErr(413, "envelope_too_large");

    let env: Envelope;
    try {
      env = JSON.parse(new TextDecoder().decode(body)) as Envelope;
    } catch {
      return jsonErr(400, "invalid_json");
    }

    let effectiveMaxBytes = Math.min(sender.max_bytes, this.maxTransferBytes);
    const rawInternalMax = request.headers.get("X-Internal-Max-Transfer-Bytes");
    if (rawInternalMax) {
      const keyMax = Number.parseInt(rawInternalMax, 10);
      if (Number.isFinite(keyMax) && keyMax > 0 && keyMax < effectiveMaxBytes) {
        effectiveMaxBytes = keyMax;
      }
    }

    const nowMs = Date.now();
    const validated = this.validateEnvelope(env, effectiveMaxBytes, nowMs);
    if (validated instanceof Response) return validated;

    await this.sweepExpired(mailboxId, nowMs);

    // Serialize transfer creation while Cloud commits the quota reservation.
    return this.ctx.blockConcurrencyWhile(async () => {
      if (this.deletingTransfers.has(env.transfer_id) || this.getTransfer(env.transfer_id)) {
        return jsonErr(409, "already_exists");
      }

      const activeCount = this.ctx.storage.sql.exec<{ c: number }>("SELECT COUNT(*) AS c FROM transfers_v2").one().c;
      if (activeCount >= this.maxTransfers) return jsonErr(429, "mailbox_full");

      const inlineCount = Math.min(env.total_chunks, MAX_INLINE_UPLOAD_URLS);
      const presignTtl = this.presignTtlFor(nowMs, validated.expiresAtMs, s3.presignTtlSec);
      const uploadUrls = await Promise.all(
        Array.from({ length: inlineCount }, async (_, i) => {
          const signed = await s3.presignPut(s3.objectKey(mailboxId, env.transfer_id, i), presignTtl, nowMs);
          return { index: i, ...signed };
        })
      );

      const cloudKeyHash = request.headers.get("X-Internal-Cloud-Key-Hash");
      if (cloudKeyHash) {
        const denied = await reserveCloudTransfer(this.env, cloudKeyHash, env.total_ciphertext_bytes);
        if (denied) return denied;
      }

      const availableB64 = encodeBitmap(newBitmap(env.total_chunks));
      this.ctx.storage.sql.exec(
        `INSERT INTO transfers_v2 (
          transfer_id, sender_hash, envelope_json, chunk_sizes_json,
          available_b64, total_chunks, chunk_size, total_ciphertext_bytes, expires_at_ms, storage_profile
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        env.transfer_id,
        sender.token_hash,
        JSON.stringify(env),
        "{}",
        availableB64,
        env.total_chunks,
        env.chunk_size,
        env.total_ciphertext_bytes,
        validated.expiresAtMs,
        storageProfile
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
        upload_mode: "presigned",
        upload_urls: uploadUrls,
        ...(new URL(request.url).origin === OFFICIAL_RELAY_ORIGIN && { relay_upload_fallback: true }),
      });
    });
  }

  private async handleRelayChunkUpload(
    request: Request,
    mailboxId: string,
    transferId: string,
    index: number
  ): Promise<Response> {
    const tok = this.bearerToken(request);
    if (!tok) return jsonErr(401, "unauthorized");
    const sender = await this.authorizeSender(tok);
    if (!sender) return jsonErr(403, "forbidden");

    const tr = this.getTransfer(transferId);
    if (!tr || tr.expires_at_ms <= Date.now()) return jsonErr(404, "not_found");
    if (tr.sender_hash !== sender.token_hash) return jsonErr(403, "forbidden");
    if (index >= tr.total_chunks) return jsonErr(400, "invalid_chunk_index");

    const profile = parseStorageProfile(tr.storage_profile);
    const s3 = hasS3Profile(this.env, profile) ? this.getS3ClientForProfile(profile) : null;
    if (!s3) return jsonErr(503, "s3_not_configured");

    return this.withChunkOperation(transferId, index, async (operations) => {
      const limit = Math.min(tr.chunk_size + GCM_TAG_SIZE, tr.total_ciphertext_bytes);
      const body = await readLimited(request.body, limit).catch(() => undefined);
      if (body === undefined) return jsonErr(400, "invalid_body");
      if (body === null) return jsonErr(413, "chunk_too_large");
      if (body.byteLength === 0 || (tr.total_chunks === 1 && body.byteLength !== tr.total_ciphertext_bytes)) {
        return jsonErr(400, "size_mismatch");
      }

      const envelope = JSON.parse(tr.envelope_json) as Envelope;
      const expected = base64UrlDecode(envelope.chunk_hashes[index]);
      const digest = await sha256(body);
      if (!expected || !timingSafeEqualBytes(digest, expected)) return jsonErr(400, "chunk_hash_mismatch");

      const latest = this.getTransfer(transferId);
      if (!latest || latest.expires_at_ms <= Date.now() || this.chunkOperations.get(transferId) !== operations) {
        return jsonErr(410, "gone");
      }
      const registered = this.ctx.storage.sql
        .exec("SELECT 1 FROM senders WHERE token_hash = ?", sender.token_hash)
        .toArray();
      if (registered.length === 0) return jsonErr(403, "forbidden");
      const bitmap = decodeBitmap(latest.available_b64, latest.total_chunks);
      if (bitmap && hasBit(bitmap, index)) return new Response(null, { status: 204 });

      // Count staged fallback bytes against the same budget as committed bytes.
      // Keep the size after an ambiguous storage failure so retries cannot exceed it.
      const sizes = readChunkSizes(latest);
      sizes[index] = body.byteLength;
      if (totalChunkBytes(sizes) > latest.total_ciphertext_bytes) return jsonErr(413, "payload_too_large");
      this.saveChunkState(transferId, latest.available_b64, sizes);

      const key = s3.objectKey(mailboxId, transferId, index);
      const writing = s3.putObject(key, body, digest);
      operations.set(index, writing);
      const failed = await writing.then(() => false, () => true);
      if (latest.expires_at_ms <= Date.now() || this.chunkOperations.get(transferId) !== operations) {
        return jsonErr(410, "gone");
      }
      if (failed) return jsonErr(502, "storage_error");
      return new Response(null, { status: 204 });
    });
  }

  private async handleChunkUploadURL(
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

    const tr = this.getTransfer(transferId);
    if (!tr) return jsonErr(404, "not_found");
    if (tr.sender_hash !== sender.token_hash) return jsonErr(403, "forbidden");
    if (index < 0 || index >= tr.total_chunks) return jsonErr(400, "invalid_chunk_index");

    const s3 = this.getS3ClientForProfile(parseStorageProfile(tr.storage_profile));
    if (!s3) return jsonErr(503, "s3_not_configured");

    const signed = await s3.presignPut(
      s3.objectKey(mailboxId, transferId, index),
      this.presignTtlFor(nowMs, tr.expires_at_ms, s3.presignTtlSec),
      nowMs
    );
    return Response.json(signed);
  }

  private async handleCommitChunk(
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

    const tr = this.getTransfer(transferId);
    if (!tr) return jsonErr(404, "not_found");
    if (tr.sender_hash !== sender.token_hash) return jsonErr(403, "forbidden");
    if (index < 0 || index >= tr.total_chunks) return jsonErr(400, "invalid_chunk_index");

    const s3 = this.getS3ClientForProfile(parseStorageProfile(tr.storage_profile));
    if (!s3) return jsonErr(503, "s3_not_configured");

    return this.withChunkOperation(transferId, index, async (operations) => {
      const key = s3.objectKey(mailboxId, transferId, index);
      let meta;
      try {
        meta = await s3.headObject(key, nowMs);
      } catch {
        return jsonErr(502, "storage_error");
      }
      if (!meta) return jsonErr(404, "chunk_not_uploaded");

      const beforeCopy = this.getCurrentTransfer(tr);
      if (!beforeCopy || beforeCopy.expires_at_ms <= Date.now() ||
          this.chunkOperations.get(transferId) !== operations) {
        return jsonErr(410, "gone");
      }

      const maxChunk = beforeCopy.chunk_size + GCM_TAG_SIZE;
      if (meta.size <= 0 || meta.size > maxChunk ||
          (beforeCopy.total_chunks === 1 && meta.size !== beforeCopy.total_ciphertext_bytes)) {
        const cleanup = this.removeRejectedChunk(s3, key, tr, index);
        operations.set(index, cleanup);
        await cleanup;
        return meta.size > maxChunk ? jsonErr(413, "chunk_too_large") : jsonErr(400, "size_mismatch");
      }

      const committed = readChunkSizes(beforeCopy)[index];
      if (committed && typeof committed !== "number" && committed.size === meta.size && committed.etag === meta.etag) {
        return new Response(null, { status: 204 });
      }

      const committing = this.snapshotChunk(s3, key, meta).then(async (snapshot) => {
        const latest = this.getCurrentTransfer(tr);
        if (!latest || latest.expires_at_ms <= Date.now() || this.chunkOperations.get(transferId) !== operations) {
          await s3.deleteObject(snapshot.key).catch(() => undefined);
          return jsonErr(410, "gone");
        }
        const sizes = readChunkSizes(latest);
        const previous = sizes[index];
        if (previous && typeof previous !== "number" && previous.size === snapshot.size && previous.etag === snapshot.etag) {
          await s3.deleteObject(snapshot.key).catch(() => undefined);
          return new Response(null, { status: 204 });
        }

        sizes[index] = snapshot;
        if (totalChunkBytes(sizes) > latest.total_ciphertext_bytes) {
          await Promise.all([
            this.removeRejectedChunk(s3, key, tr, index),
            s3.deleteObject(snapshot.key).catch(() => undefined),
          ]);
          return jsonErr(413, "payload_too_large");
        }

        const bm = decodeBitmap(latest.available_b64, latest.total_chunks) ?? newBitmap(latest.total_chunks);
        setBit(bm, index);
        const updatedB64 = encodeBitmap(bm);
        this.saveChunkState(transferId, updatedB64, sizes);
        this.publishEvent({
          event: "chunk_ready",
          transfer_id: transferId,
          chunk_index: index,
          available_bitmap: updatedB64,
          expires_at_ms: latest.expires_at_ms,
        });

        if (previous && typeof previous !== "number") {
          await s3.deleteObject(previous.key).catch(() => undefined);
        }
        return new Response(null, { status: 204 });
      }, () => jsonErr(502, "storage_error"));
      operations.set(index, committing.then(() => undefined, () => undefined));
      return committing;
    });
  }

  private async handleListTransfers(request: Request, mailboxId: string): Promise<Response> {
    const authErr = await this.verifyOwner(request, mailboxId, new Uint8Array(0));
    if (authErr) return authErr;

    await this.sweepExpired(mailboxId, Date.now());
    const rows = this.ctx.storage.sql.exec<TransferRow>("SELECT * FROM transfers_v2").toArray();
    const transfers = rows.map((tr) => ({
      transfer_id: tr.transfer_id,
      envelope: JSON.parse(tr.envelope_json) as Envelope,
      available_bitmap: tr.available_b64,
      expires_at_ms: tr.expires_at_ms,
    }));
    return Response.json({ transfers });
  }

  private async handleChunkDownloadURL(
    request: Request,
    mailboxId: string,
    transferId: string,
    index: number
  ): Promise<Response> {
    const authErr = await this.verifyOwner(request, mailboxId, new Uint8Array(0));
    if (authErr) return authErr;

    const nowMs = Date.now();
    await this.sweepExpired(mailboxId, nowMs);
    const tr = this.getTransfer(transferId);
    if (!tr) return jsonErr(404, "not_found");
    const bm = decodeBitmap(tr.available_b64, tr.total_chunks);
    if (!bm || !hasBit(bm, index)) return jsonErr(404, "not_found");

    const s3 = this.getS3ClientForProfile(parseStorageProfile(tr.storage_profile));
    if (!s3) return jsonErr(503, "s3_not_configured");

    let chunk = readChunkSizes(tr)[index];
    if (chunk === undefined) return jsonErr(404, "not_found");
    if (typeof chunk === "number") {
      // Older transfers recorded only a size. Pin the object before issuing another grant.
      const key = s3.objectKey(mailboxId, transferId, index);
      let snapshot: CommittedChunk;
      try {
        const meta = await s3.headObject(key);
        if (!meta || meta.size !== chunk) return jsonErr(404, "not_found");
        snapshot = await this.snapshotChunk(s3, key, meta);
      } catch {
        return jsonErr(502, "storage_error");
      }
      const latest = this.getCurrentTransfer(tr);
      const sizes = latest && readChunkSizes(latest);
      if (latest && sizes && sizes[index] === chunk) {
        sizes[index] = snapshot;
        this.saveChunkState(transferId, latest.available_b64, sizes);
        chunk = snapshot;
      } else {
        const current = sizes?.[index];
        await s3.deleteObject(snapshot.key).catch(() => undefined);
        if (current === undefined || typeof current === "number") return jsonErr(404, "not_found");
        chunk = current;
      }
    }

    const signed = await s3.presignGet(
      chunk.key,
      this.presignTtlFor(nowMs, tr.expires_at_ms, s3.presignTtlSec),
      nowMs
    );

    return Response.json({
      method: signed.method,
      url: signed.url,
      expires_at_ms: signed.expires_at_ms,
      size: chunk.size,
    });
  }

  private async handleAckTransfer(request: Request, mailboxId: string, transferId: string): Promise<Response> {
    const body = await readLimited(request.body, 1024);
    if (body === null) return jsonErr(413, "body_too_large");

    const authErr = await this.verifyOwner(request, mailboxId, body);
    if (authErr) return authErr;

    const transfer = this.getTransfer(transferId);
    if (transfer) {
      await this.deleteStoredTransfer(mailboxId, transfer);
      await this.scheduleNextAlarm();
    }
    return new Response(null, { status: 204 });
  }

  private async handleDeleteTransfer(request: Request, mailboxId: string, transferId: string): Promise<Response> {
    const tok = this.bearerToken(request);
    let senderHash: string | undefined;
    if (tok) {
      const sender = await this.authorizeSender(tok);
      if (!sender) return jsonErr(403, "forbidden");
      senderHash = sender.token_hash;
    } else {
      const authErr = await this.verifyOwner(request, mailboxId, new Uint8Array(0));
      if (authErr) return authErr;
    }

    const transfer = this.getTransfer(transferId);
    if (transfer) {
      if (senderHash && transfer.sender_hash !== senderHash) return jsonErr(403, "forbidden");
      await this.deleteStoredTransfer(mailboxId, transfer);
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

function parseChunkIndex(raw: string): number | null {
  if (!/^\d+$/.test(raw)) return null;
  const idx = Number.parseInt(raw, 10);
  if (idx < 0 || idx >= MAX_CHUNKS) return null;
  return idx;
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
