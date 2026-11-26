// SPDX-License-Identifier: AGPL-3.0-only

import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          S3_ENDPOINT: "https://mock-s3.example",
          S3_REGION: "ap-guangzhou",
          S3_BUCKET: "unic-test-bucket",
          S3_ACCESS_KEY_ID: "AKTEST",
          S3_SECRET_ACCESS_KEY: "SKTEST",
          S3_FORCE_PATH_STYLE: "true",
          S3_KEY_PREFIX: "mailboxes",
          S3_PRESIGN_TTL_SEC: "300",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
