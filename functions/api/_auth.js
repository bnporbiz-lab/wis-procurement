/* Shared auth helper for WIS Procurement Cloudflare Functions.
   When REQUIRE_AUTH === "true", every request must carry a valid Firebase ID token
   (Authorization: Bearer <token>) of a non-anonymous user of this project.
   RS256 signature verified against Google's published keys. */
export async function requireAuth(ctx) {
  const { env, request } = ctx;
  if (String(env.REQUIRE_AUTH || "").toLowerCase() !== "true") return null;
  const m = (request.headers.get("Authorization") || "").match(/^Bearer (.+)$/);
  if (!m) { console.log("auth: no bearer header"); return deny(); }
  try {
    const why = await verifyFirebaseIdToken(m[1], env.FB_PROJECT_ID || "wis-procurement");
    if (why !== true) { console.log("auth: reject -", why); return deny(); }
    return null;
  } catch (e) { console.log("auth: exception -", String(e && e.message || e)); return deny(); }
}
function deny() {
  return new Response(JSON.stringify({ ok: false, error: "unauthorized" }),
    { status: 401, headers: { "Content-Type": "application/json" } });
}
function b64uToBytes(s) {
  s = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";                      // atob needs padding — JWT segments omit it
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function verifyFirebaseIdToken(token, projectId) {
  const parts = String(token).split(".");
  if (parts.length !== 3) return "malformed";
  let header, payload;
  try {
    header = JSON.parse(new TextDecoder().decode(b64uToBytes(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(b64uToBytes(parts[1])));
  } catch (e) { return "decode: " + String(e && e.message || e); }
  const now = Math.floor(Date.now() / 1000);
  if (payload.aud !== projectId) return "aud=" + payload.aud;
  if (payload.iss !== "https://securetoken.google.com/" + projectId) return "iss=" + payload.iss;
  if (!(payload.exp > now)) return "expired";
  if (payload.firebase && payload.firebase.sign_in_provider === "anonymous") return "anonymous";
  const resp = await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com");
  if (!resp.ok) return "jwks http " + resp.status;
  const jwks = await resp.json();
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid);
  if (!jwk) return "kid not found";
  let key;
  try {
    key = await crypto.subtle.importKey("jwk", { kty: jwk.kty, n: jwk.n, e: jwk.e },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  } catch (e) { return "importKey: " + String(e && e.message || e); }
  const data = new TextEncoder().encode(parts[0] + "." + parts[1]);
  const okSig = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uToBytes(parts[2]), data);
  return okSig ? true : "bad signature";
}
