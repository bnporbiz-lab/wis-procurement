/* Telegram proxy: the bot token (TG_TOKEN) lives ONLY in Cloudflare environment
   variables. The browser calls /api/tg/sendMessage etc.; the token is injected
   server-side. Both JSON bodies and multipart uploads (PDFs) pass straight through. */
import { requireAuth } from "../_auth.js";

const ALLOWED = new Set(["sendMessage", "sendDocument", "getMe"]);

export async function onRequestPost(ctx) {
  const { env, request, params } = ctx;
  const authFail = await requireAuth(ctx);
  if (authFail) return authFail;
  const method = String(params.method || "").replace(/[^A-Za-z]/g, "");
  if (!ALLOWED.has(method)) {
    return new Response(JSON.stringify({ ok: false, description: "method_not_allowed" }),
      { status: 400, headers: { "Content-Type": "application/json" } });
  }
  if (!env.TG_TOKEN) {
    return new Response(JSON.stringify({ ok: false, description: "proxy_not_configured" }),
      { status: 500, headers: { "Content-Type": "application/json" } });
  }
  const url = "https://api.telegram.org/bot" + env.TG_TOKEN + "/" + method;
  const init = { method: "POST", body: request.body };
  const ct = request.headers.get("Content-Type");
  if (ct) init.headers = { "Content-Type": ct };
  const resp = await fetch(url, init);
  return new Response(await resp.text(), { status: resp.status, headers: { "Content-Type": "application/json" } });
}
