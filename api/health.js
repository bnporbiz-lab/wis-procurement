/* Probe endpoint: the app detects the secure proxy by calling GET /api/health. */
export async function onRequestGet() {
  return new Response(JSON.stringify({ wis: "ok" }),
    { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}
