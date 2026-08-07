/* Shared auth helper for WIS Procurement Cloudflare Functions.
   When the environment variable REQUIRE_AUTH is "true", every request must
   carry a valid Firebase ID token (Authorization: Bearer <token>) belonging
   to a non-anonymous user of the configured project. Signature is verified
   against Google's published JWKs (RS256). */
export async function requireAuth(ctx) {
  const { env, request } = ctx;
  if (String(env.REQUIRE_AUTH || "").toLowerCase() !== "true") return null; // auth not enforced yet
  const m = (request.headers.get("Authorization") || "").match(/^Bearer (.+)$/);
  if (!m) return deny();
  try {
    const ok = await verifyFirebaseIdToken(m[1], env.FB_PROJECT_ID || "wis-procurement");
    return ok ? null : deny();
  } catch (e) { return deny(); }
}
function deny() {
  return new Response(JSON.stringify({ ok: false, error: "unauthorized" }),
    { status: 401, headers: { "Content-Type": "application/json" } });
}
function b64uToBytes(s) {
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}
async function verifyFirebaseIdToken(token, projectId) {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const dec = x => JSON.parse(new TextDecoder().decode(b64uToBytes(x)));
  const header = dec(parts[0]), payload = dec(parts[1]);
  const now = Math.floor(Date.now() / 1000);
  if (payload.aud !== projectId) return false;
  if (payload.iss !== "https://securetoken.google.com/" + projectId) return false;
  if (!(payload.exp > now)) return false;
  if (payload.firebase && payload.firebase.sign_in_provider === "anonymous") return false;
  const jwksResp = await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
    { cf: { cacheTtl: 3600, cacheEverything: true } });
  const jwks = await jwksResp.json();
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid);
  if (!jwk) return false;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const data = new TextEncoder().encode(parts[0] + "." + parts[1]);
  return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uToBytes(parts[2]), data);
}
