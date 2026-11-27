// SPDX-License-Identifier: AGPL-3.0-only

// Augments Wrangler-generated Env with optional secrets, Cloud verification,
// dual-region S3 object storage configuration, and optional rate limiting that
// are intentionally omitted from top-level version-controlled wrangler.jsonc.
interface Env {
  RELAY_ACCESS_KEY?: string;
  RELAY_ORIGIN?: string;
  RELAY_ALLOWED_PUBKEYS?: string;

  CLOUD_VERIFY_URL?: string;
  CLOUD_VERIFY_SECRET?: string;
  CLOUD_VERIFY_CACHE_TTL_SEC?: string;

  S3_ENDPOINT?: string;
  S3_PUBLIC_ENDPOINT?: string;
  S3_REGION?: string;
  S3_BUCKET?: string;
  S3_ACCESS_KEY_ID?: string;
  S3_SECRET_ACCESS_KEY?: string;
  S3_FORCE_PATH_STYLE?: string;
  S3_KEY_PREFIX?: string;
  S3_PRESIGN_TTL_SEC?: string;

  S3_CN_ENDPOINT?: string;
  S3_CN_PUBLIC_ENDPOINT?: string;
  S3_CN_REGION?: string;
  S3_CN_BUCKET?: string;
  S3_CN_ACCESS_KEY_ID?: string;
  S3_CN_SECRET_ACCESS_KEY?: string;
  S3_CN_FORCE_PATH_STYLE?: string;
  S3_CN_KEY_PREFIX?: string;
  S3_CN_PRESIGN_TTL_SEC?: string;

  RATE_LIMITER?: {
    limit(options: { key: string }): Promise<{ success: boolean }>;
  };
}
