// SPDX-License-Identifier: AGPL-3.0-only

import { ACCESS_KEY_HEADER, type AuthEnv, verifyCloudAccessKey } from "./auth";
import { validMailboxId } from "./crypto";
import { configuredStorageProfiles, hasS3Profile, resolveStorageProfile, type StorageProfile } from "./s3";

export { MailboxDurableObject } from "./mailbox-do";

type RelayEnv = Env & AuthEnv;

export default {
  async fetch(request: Request, env: RelayEnv): Promise<Response> {
    try {
      const url = new URL(request.url);

      if (url.pathname === "/healthz") {
        if (request.method !== "GET" && request.method !== "HEAD") {
          return Response.json({ error: "method_not_allowed" }, { status: 405 });
        }
        if (request.method === "HEAD") {
          return new Response(null, {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return Response.json({
          status: "ok",
          service: "hyper-relay",
          runtime: "cloudflare-workers",
          storage: "s3-direct",
          storage_profiles: configuredStorageProfiles(env),
        });
      }

      const authResult = await verifyCloudAccessKey(request.headers.get(ACCESS_KEY_HEADER), env);
      if (!authResult.allowed) {
        return Response.json(
          { error: authResult.error ?? "unauthorized" },
          { status: authResult.status || 401 }
        );
      }

      if (env.RATE_LIMITER && url.pathname.startsWith("/v1/relay/")) {
        const rateLimitKey =
          authResult.subject || request.headers.get("CF-Connecting-IP")?.trim() || "anon";
        const outcome = await env.RATE_LIMITER.limit({ key: rateLimitKey });
        if (!outcome.success) {
          return Response.json(
            { error: "rate_limited" },
            { status: 429, headers: { "Retry-After": "60" } }
          );
        }
      }

      const prefix = "/v1/relay/mailboxes/";
      if (!url.pathname.startsWith(prefix)) {
        return Response.json({ error: "not_found" }, { status: 404 });
      }
      const parts = url.pathname.slice(prefix.length).split("/");
      if (parts.length < 2 || !validMailboxId(parts[0])) {
        return Response.json({ error: "invalid_path" }, { status: 400 });
      }

      // Strip any client-supplied X-Internal-* headers before attaching trusted routing metadata.
      const forwardedHeaders = new Headers(request.headers);
      for (const headerName of Array.from(forwardedHeaders.keys())) {
        if (headerName.toLowerCase().startsWith("x-internal-")) {
          forwardedHeaders.delete(headerName);
        }
      }

      const cfCountry = (request as Request & { cf?: { country?: string } }).cf?.country?.toUpperCase();
      const preferredProfile: StorageProfile = cfCountry === "CN" && hasS3Profile(env, "cn") ? "cn" : "global";
      const storageProfile = resolveStorageProfile(env, preferredProfile);
      forwardedHeaders.set("X-Internal-Storage-Profile", storageProfile);

      if (authResult.maxTransferBytes && authResult.maxTransferBytes > 0) {
        forwardedHeaders.set("X-Internal-Max-Transfer-Bytes", String(authResult.maxTransferBytes));
      }
      if (authResult.cloudKeyHash && request.method === "POST" && parts.length === 2 && parts[1] === "transfers") {
        forwardedHeaders.set("X-Internal-Cloud-Key-Hash", authResult.cloudKeyHash);
      }

      const mailboxId = parts[0];
      const stub = env.MAILBOX_DO.get(env.MAILBOX_DO.idFromName(mailboxId));
      const forwardedRequest = new Request(request, { headers: forwardedHeaders });
      return await stub.fetch(forwardedRequest);
    } catch (err) {
      const message = err instanceof Error ? err.message : "unknown_error";
      console.error(JSON.stringify({ message: "unhandled worker error", error: message }));
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  },
} satisfies ExportedHandler<RelayEnv>;
