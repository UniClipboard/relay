// SPDX-License-Identifier: AGPL-3.0-only

// Augments Wrangler-generated Env with optional secrets and runtime overrides
// that are intentionally omitted from version-controlled wrangler.jsonc vars.
interface Env {
  RELAY_ACCESS_KEY?: string;
  RELAY_ORIGIN?: string;
  RELAY_ALLOWED_PUBKEYS?: string;
}
