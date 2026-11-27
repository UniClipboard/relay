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
          S3_REGION: "auto",
          S3_BUCKET: "unic-global-bucket",
          S3_ACCESS_KEY_ID: "AKGLOBAL",
          S3_SECRET_ACCESS_KEY: "SKGLOBAL",
          S3_FORCE_PATH_STYLE: "true",
          S3_KEY_PREFIX: "mailboxes",
          S3_PRESIGN_TTL_SEC: "300",
          S3_CN_ENDPOINT: "https://mock-cos-cn.example",
          S3_CN_REGION: "ap-guangzhou",
          S3_CN_BUCKET: "unic-cn-bucket",
          S3_CN_ACCESS_KEY_ID: "AKCN",
          S3_CN_SECRET_ACCESS_KEY: "SKCN",
          S3_CN_FORCE_PATH_STYLE: "true",
          S3_CN_KEY_PREFIX: "mailboxes",
          S3_CN_PRESIGN_TTL_SEC: "300",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
