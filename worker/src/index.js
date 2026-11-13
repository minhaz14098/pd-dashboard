/**
 * PD Dashboard API — Cloudflare Worker
 *
 * Keeps the existing dashboard contract:
 *   GET /             -> { tracker: "<CSV>", costing: "<CSV>" }
 *   GET /api/health   -> health/status JSON
 *
 * Configure TRACKER_CSV_URL and COSTING_CSV_URL as Worker variables.
 * Do not put private API keys or passwords in this file.
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Cache-Control": "no-store",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

async function readCsv(url, label) {
  if (!url) throw new Error(`${label}_CSV_URL is not configured`);
  const response = await fetch(url, {
    headers: { Accept: "text/csv,text/plain,*/*" },
    cf: { cacheTtl: 0, cacheEverything: false },
  });
  if (!response.ok) throw new Error(`${label} sheet returned HTTP ${response.status}`);
  const text = await response.text();
  if (!text.trim() || /^\s*<(?:!doctype|html)/i.test(text)) {
    throw new Error(`${label} sheet returned empty data or a sign-in page`);
  }
  return text;
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }
    if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);

    const url = new URL(request.url);
    if (url.pathname === "/api/health") {
      return json({
        ok: true,
        service: "pd-dashboard-api",
        configured: Boolean(env.TRACKER_CSV_URL && env.COSTING_CSV_URL),
      });
    }

    if (url.pathname !== "/" && url.pathname !== "/api/sheets") {
      return json({ error: "Not found" }, 404);
    }

    try {
      const [tracker, costing] = await Promise.all([
        readCsv(env.TRACKER_CSV_URL, "TRACKER"),
        readCsv(env.COSTING_CSV_URL, "COSTING"),
      ]);
      return json({ tracker, costing });
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : "Unable to load sheets" }, 502);
    }
  },
};
