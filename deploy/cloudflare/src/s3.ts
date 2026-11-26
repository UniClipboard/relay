// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Lightweight, zero-dependency AWS Signature Version 4 (SigV4) client for
 * Cloudflare Workers using Web Crypto. Supports Tencent COS, Cloudflare R2,
 * AWS S3, Aliyun OSS, MinIO, and Backblaze B2.
 */

import { bytesToHex, sha256, utf8Bytes } from "./crypto";

const EMPTY_PAYLOAD_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
const DEFAULT_PRESIGN_TTL_SEC = 300;
const MAX_PRESIGN_TTL_SEC = 1800;

export interface S3Config {
  endpoint: string;
  publicEndpoint?: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  forcePathStyle: boolean;
  keyPrefix: string;
  presignTtlSec: number;
}

export interface PresignedURL {
  method: "PUT" | "GET";
  url: string;
  expires_at_ms: number;
}

export interface ObjectMeta {
  size: number;
  etag: string;
}

export class S3Error extends Error {
  constructor(
    message: string,
    public readonly status: number
  ) {
    super(message);
  }
}

export function loadS3ConfigFromEnv(env: Env): S3Config | null {
  const endpoint = (env.S3_ENDPOINT ?? "").trim();
  const bucket = (env.S3_BUCKET ?? "").trim();
  const accessKeyId = (env.S3_ACCESS_KEY_ID ?? "").trim();
  const secretAccessKey = (env.S3_SECRET_ACCESS_KEY ?? "").trim();
  if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) {
    return null;
  }
  const region = (env.S3_REGION ?? "").trim() || "auto";
  const publicEndpoint = (env.S3_PUBLIC_ENDPOINT ?? "").trim() || undefined;
  const forcePathStyle = parseBool(env.S3_FORCE_PATH_STYLE);
  const keyPrefix = (env.S3_KEY_PREFIX ?? "").trim().replace(/^\/+|\/+$/g, "") || "mailboxes";
  const rawTtl = Number.parseInt((env.S3_PRESIGN_TTL_SEC ?? "").trim(), 10);
  const presignTtlSec =
    Number.isFinite(rawTtl) && rawTtl > 0
      ? Math.min(rawTtl, MAX_PRESIGN_TTL_SEC)
      : DEFAULT_PRESIGN_TTL_SEC;

  return {
    endpoint,
    publicEndpoint,
    region,
    bucket,
    accessKeyId,
    secretAccessKey,
    forcePathStyle,
    keyPrefix,
    presignTtlSec,
  };
}

export class S3Client {
  private readonly endpointUrl: URL;
  private readonly publicEndpointUrl: URL;

  constructor(private readonly cfg: S3Config) {
    this.endpointUrl = parseEndpointUrl(cfg.endpoint);
    this.publicEndpointUrl = cfg.publicEndpoint ? parseEndpointUrl(cfg.publicEndpoint) : this.endpointUrl;
  }

  objectKey(mailboxId: string, transferId: string, index: number): string {
    return `${this.cfg.keyPrefix}/${mailboxId}/transfers/${transferId}/chunks/${index}`;
  }

  async presignPut(key: string, ttlSec: number, nowMs = Date.now()): Promise<PresignedURL> {
    return this.presign("PUT", key, ttlSec, nowMs);
  }

  async presignGet(key: string, ttlSec: number, nowMs = Date.now()): Promise<PresignedURL> {
    return this.presign("GET", key, ttlSec, nowMs);
  }

  private async presign(method: "PUT" | "GET", key: string, ttlSec: number, nowMs: number): Promise<PresignedURL> {
    const expSec = Math.max(1, Math.min(Math.floor(ttlSec || this.cfg.presignTtlSec), this.cfg.presignTtlSec, MAX_PRESIGN_TTL_SEC));
    const { amzDate, dateStamp } = formatAmzDate(nowMs);
    const scope = `${dateStamp}/${this.cfg.region}/s3/aws4_request`;
    const { scheme, host, canonicalUri } = this.objectAddress(this.publicEndpointUrl, key);

    const queryPairs: Array<[string, string]> = [
      ["X-Amz-Algorithm", "AWS4-HMAC-SHA256"],
      ["X-Amz-Credential", `${this.cfg.accessKeyId}/${scope}`],
      ["X-Amz-Date", amzDate],
      ["X-Amz-Expires", String(expSec)],
      ["X-Amz-SignedHeaders", "host"],
    ];
    const canonicalQuery = buildCanonicalQuery(queryPairs);
    const canonicalRequest = [
      method,
      canonicalUri,
      canonicalQuery,
      `host:${host}\n`,
      "host",
      UNSIGNED_PAYLOAD,
    ].join("\n");

    const stringToSign = [
      "AWS4-HMAC-SHA256",
      amzDate,
      scope,
      bytesToHex(await sha256(utf8Bytes(canonicalRequest))),
    ].join("\n");

    const keyBytes = await deriveSigningKey(this.cfg.secretAccessKey, dateStamp, this.cfg.region, "s3");
    const sig = bytesToHex(await hmacSha256(keyBytes, utf8Bytes(stringToSign)));
    const url = `${scheme}://${host}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${sig}`;

    return {
      method,
      url,
      expires_at_ms: nowMs + expSec * 1000,
    };
  }

  async headObject(key: string, nowMs = Date.now()): Promise<ObjectMeta | null> {
    const resp = await this.signedFetch("HEAD", key, nowMs);
    if (resp.status === 404) return null;
    if (!resp.ok) {
      throw new S3Error(`S3 HEAD failed with status ${resp.status}`, resp.status);
    }
    const rawLen = resp.headers.get("Content-Length") ?? "0";
    const size = Number.parseInt(rawLen, 10);
    return {
      size: Number.isFinite(size) ? size : 0,
      etag: (resp.headers.get("ETag") ?? "").replace(/^"|"$/g, ""),
    };
  }

  async deleteObject(key: string, nowMs = Date.now()): Promise<void> {
    const resp = await this.signedFetch("DELETE", key, nowMs);
    if (resp.status === 404 || resp.ok) {
      return;
    }
    throw new S3Error(`S3 DELETE failed with status ${resp.status}`, resp.status);
  }

  async deleteTransfer(mailboxId: string, transferId: string, totalChunks: number): Promise<void> {
    const tasks: Promise<void>[] = [];
    for (let i = 0; i < totalChunks; i++) {
      tasks.push(
        this.deleteObject(this.objectKey(mailboxId, transferId, i)).catch(() => {
          // Best-effort cleanup; bucket lifecycle rule serves as fallback.
        })
      );
    }
    await Promise.all(tasks);
  }

  private async signedFetch(method: "HEAD" | "DELETE", key: string, nowMs: number): Promise<Response> {
    const { amzDate, dateStamp } = formatAmzDate(nowMs);
    const scope = `${dateStamp}/${this.cfg.region}/s3/aws4_request`;
    const { scheme, host, canonicalUri } = this.objectAddress(this.endpointUrl, key);

    const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${EMPTY_PAYLOAD_SHA256}\nx-amz-date:${amzDate}\n`;
    const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
    const canonicalRequest = [
      method,
      canonicalUri,
      "",
      canonicalHeaders,
      signedHeaders,
      EMPTY_PAYLOAD_SHA256,
    ].join("\n");

    const stringToSign = [
      "AWS4-HMAC-SHA256",
      amzDate,
      scope,
      bytesToHex(await sha256(utf8Bytes(canonicalRequest))),
    ].join("\n");

    const keyBytes = await deriveSigningKey(this.cfg.secretAccessKey, dateStamp, this.cfg.region, "s3");
    const sig = bytesToHex(await hmacSha256(keyBytes, utf8Bytes(stringToSign)));
    const authHeader = `AWS4-HMAC-SHA256 Credential=${this.cfg.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${sig}`;

    return fetch(`${scheme}://${host}${canonicalUri}`, {
      method,
      headers: {
        "x-amz-date": amzDate,
        "x-amz-content-sha256": EMPTY_PAYLOAD_SHA256,
        Authorization: authHeader,
      },
    });
  }

  private objectAddress(ep: URL, key: string): { scheme: string; host: string; canonicalUri: string } {
    const scheme = ep.protocol.replace(/:$/, "");
    const basePath = ep.pathname.replace(/\/+$/, "");
    const cleanKey = key.replace(/^\/+/, "");
    const hostname = ep.hostname;
    const isIpOrLocal = hostname === "localhost" || /^[0-9.]+$/.test(hostname) || hostname.includes(":");
    const alreadyVhost = hostname.toLowerCase().startsWith(`${this.cfg.bucket.toLowerCase()}.`);

    if (this.cfg.forcePathStyle || isIpOrLocal || alreadyVhost) {
      const path = alreadyVhost
        ? `${basePath}/${cleanKey}`
        : `${basePath}/${this.cfg.bucket}/${cleanKey}`;
      return {
        scheme,
        host: ep.host,
        canonicalUri: encodeUriPath(path),
      };
    }

    return {
      scheme,
      host: `${this.cfg.bucket}.${ep.host}`,
      canonicalUri: encodeUriPath(`${basePath}/${cleanKey}`),
    };
  }
}

function parseEndpointUrl(raw: string): URL {
  const u = new URL(raw);
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    throw new Error("S3 endpoint must use http or https");
  }
  return u;
}

function parseBool(v: string | undefined): boolean {
  if (!v) return false;
  return ["1", "true", "yes", "on"].includes(v.trim().toLowerCase());
}

function formatAmzDate(nowMs: number): { amzDate: string; dateStamp: string } {
  const d = new Date(nowMs);
  const pad = (n: number) => String(n).padStart(2, "0");
  const dateStamp = `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}`;
  const timeStamp = `${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`;
  return { amzDate: `${dateStamp}T${timeStamp}Z`, dateStamp };
}

function awsPercentEncode(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function encodeUriPath(path: string): string {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  return normalized
    .split("/")
    .map((seg) => awsPercentEncode(seg))
    .join("/");
}

function buildCanonicalQuery(pairs: Array<[string, string]>): string {
  return pairs
    .map(([k, v]): [string, string] => [awsPercentEncode(k), awsPercentEncode(v)])
    .sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data));
}

async function deriveSigningKey(
  secret: string,
  dateStamp: string,
  region: string,
  service: string
): Promise<Uint8Array> {
  const kDate = await hmacSha256(utf8Bytes(`AWS4${secret}`), utf8Bytes(dateStamp));
  const kRegion = await hmacSha256(kDate, utf8Bytes(region));
  const kService = await hmacSha256(kRegion, utf8Bytes(service));
  return hmacSha256(kService, utf8Bytes("aws4_request"));
}
