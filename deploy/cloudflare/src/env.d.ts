// SPDX-License-Identifier: AGPL-3.0-only

// Augments Wrangler-generated Env with optional secrets and S3 object storage
// configuration that are intentionally omitted from version-controlled wrangler.jsonc.
interface Env {
  RELAY_ACCESS_KEY?: string;
  RELAY_ORIGIN?: string;
  RELAY_ALLOWED_PUBKEYS?: string;

  S3_ENDPOINT?: string;
  S3_PUBLIC_ENDPOINT?: string;
  S3_REGION?: string;
  S3_BUCKET?: string;
  S3_ACCESS_KEY_ID?: string;
  S3_SECRET_ACCESS_KEY?: string;
  S3_FORCE_PATH_STYLE?: string;
  S3_KEY_PREFIX?: string;
  S3_PRESIGN_TTL_SEC?: string;
}
