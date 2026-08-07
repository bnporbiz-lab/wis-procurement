/* Apps Script proxy: the shared secret (GS_KEY) and script URL (GS_URL) live ONLY
   in Cloudflare environment variables. The browser sends {params:{action:...}};
   this function injects the key server-side and forwards to Google Apps Script. */
import { requireAuth } from "./_auth.js";

export async function onRequestPost(ctx) {
  const { env, request } = ctx;
  const authFail = await requireAuth(ctx);
  if (authFail) return authFail;
  if (!env.GS_URL || !env.GS_KEY) {
    return json({ ok: false, error: "proxy_not_configured" }, 500);
  }
  let body = {};
  try { body = await request.json(); } catch (e) {}
  const params = Object.assign({}, (body && body.params) || {}, { key: env.GS_KEY });
  delete params.callback; // server-to-server: plain JSON, no JSONP
  try {
    let resp;
    if (params.action === "save") {
      const form = new URLSearchParams();
      for (const k of Object.keys(params)) form.set(k, String(params[k] == null ? "" : params[k]));
      resp = await fetch(env.GS_URL, { method: "POST", body: form, redirect: "follow" });
    } else {
      const u = new URL(env.GS_URL);
      for (const k of Object.keys(params)) u.searchParams.set(k, String(params[k] == null ? "" : params[k]));
      resp = await fetch(u.toString(), { redirect: "follow" });
    }
    const text = await resp.text();
    return new Response(text, { status: 200, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  } catch (e) {
    return json({ ok: false, error: "upstream_failed" }, 502);
  }
}
function json(o, status) {
  return new Response(JSON.stringify(o), { status: status || 200, headers: { "Content-Type": "application/json" } });
}
