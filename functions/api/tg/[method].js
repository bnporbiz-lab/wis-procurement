/* Telegram proxy: the bot token (TG_TOKEN) lives ONLY in Cloudflare environment
   variables. The browser calls /api/tg/sendMessage etc.; the token is injected
   server-side. The body is BUFFERED and forwarded as bytes — works identically
   for JSON payloads and multipart uploads (PDF documents). */
import { requireAuth } from "../_auth.js";

const ALLOWED = new Set(["sendMessage", "sendDocument", "getMe"]);

export async function onRequestPost(ctx) {
  const { env, request, params } = ctx;
  const authFail = await requireAuth(ctx);
  if (authFail) return authFail;
  const method = String(params.method || "").replace(/[^A-Za-z]/g, "");
  if (!ALLOWED.has(method)) {
    return json({ ok: false, description: "method_not_allowed" }, 400);
  }
  if (!env.TG_TOKEN) {
    return json({ ok: false, description: "proxy_not_configured" }, 500);
  }
  try {
    const bodyBytes = await request.arrayBuffer();               // buffer, don't stream
    const init = { method: "POST" };
    if (bodyBytes && bodyBytes.byteLength) {
      init.body = bodyBytes;
      const ct = request.headers.get("Content-Type");
      if (ct) init.headers = { "Content-Type": ct };
    }
    const resp = await fetch("https://api.telegram.org/bot" + env.TG_TOKEN + "/" + method, init);
    const text = await resp.text();
    return new Response(text, { status: resp.status, headers: { "Content-Type": "application/json" } });
  } catch (e) {
    console.log("tg proxy error:", String(e && e.message || e));
    return json({ ok: false, description: "upstream_failed" }, 502);
  }
}
function json(o, status) {
  return new Response(JSON.stringify(o), { status: status || 200, headers: { "Content-Type": "application/json" } });
}
