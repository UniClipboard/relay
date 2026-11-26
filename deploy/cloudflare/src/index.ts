// SPDX-License-Identifier: AGPL-3.0-only

import { ACCESS_KEY_HEADER, type AuthEnv, verifyAccessKey } from "./auth";
import { validMailboxId } from "./crypto";

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
        });
      }

      const accessOk = await verifyAccessKey(request.headers.get(ACCESS_KEY_HEADER), env.RELAY_ACCESS_KEY);
      if (!accessOk) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }

      const prefix = "/v1/relay/mailboxes/";
      if (!url.pathname.startsWith(prefix)) {
        return Response.json({ error: "not_found" }, { status: 404 });
      }
      const parts = url.pathname.slice(prefix.length).split("/");
      if (parts.length < 2 || !validMailboxId(parts[0])) {
        return Response.json({ error: "invalid_path" }, { status: 400 });
      }

      const mailboxId = parts[0];
      const stub = env.MAILBOX_DO.get(env.MAILBOX_DO.idFromName(mailboxId));
      return await stub.fetch(request);
    } catch (err) {
      const message = err instanceof Error ? err.message : "unknown_error";
      console.error(JSON.stringify({ message: "unhandled worker error", error: message }));
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  },
} satisfies ExportedHandler<RelayEnv>;
