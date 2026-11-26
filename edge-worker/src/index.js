/**
 * CrackSentinel Cloudflare Edge Worker (sentinel.breakthematrix.id)
 * Pattern adopted from KlipForge hybrid architecture:
 * - Static Web UI served directly from Cloudflare Edge [assets] (instant load 24/7)
 * - /api/* proxied cleanly to HomeServer Go Engine via self-healing Cloudflare Tunnel URL in KV (`STATE`)
 * - /_edge-register protected by BRIDGE_SECRET + per-IP KV brute-force rate limit
 * - /edge-health exposes edge + origin status without leaking secrets
 */

const ORIGIN_KEY = "origin_url";
const UPDATED_KEY = "origin_updated_at";
const REG_MAX_FAILS = 10;
const REG_WINDOW_SEC = 300;

function getClientIP(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

function timingSafeEqual(a, b) {
  const sa = String(a || "");
  const sb = String(b || "");
  const len = Math.max(sa.length, sb.length);
  let diff = sa.length ^ sb.length;
  for (let i = 0; i < len; i++) {
    diff |= (sa.charCodeAt(i) || 0) ^ (sb.charCodeAt(i) || 0);
  }
  return diff === 0;
}

async function isRateLimited(env, ip) {
  if (!env.STATE || !ip || ip === "unknown") return false;
  const count = parseInt((await env.STATE.get(`rl:reg:${ip}`)) || "0", 10);
  return Number.isFinite(count) && count >= REG_MAX_FAILS;
}

async function recordFailure(env, ip) {
  if (!env.STATE || !ip || ip === "unknown") return;
  const k = `rl:reg:${ip}`;
  const next = (parseInt((await env.STATE.get(k)) || "0", 10) || 0) + 1;
  await env.STATE.put(k, String(next), { expirationTtl: REG_WINDOW_SEC });
}

async function clearFailures(env, ip) {
  if (!env.STATE || !ip || ip === "unknown") return;
  await env.STATE.delete(`rl:reg:${ip}`);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const ip = getClientIP(request);

    // 1. Bridge registration endpoint (called by HomeServer systemd tunnel bridge)
    if ((url.pathname === "/_edge-register" || url.pathname === "/edge-register") && request.method === "POST") {
      if (await isRateLimited(env, ip)) {
        return Response.json({ error: "Rate limit exceeded" }, { status: 429, headers: { "Retry-After": String(REG_WINDOW_SEC) } });
      }
      const expected = (env.BRIDGE_SECRET || "").trim();
      const provided = (request.headers.get("X-Bridge-Secret") || "").trim();
      if (!expected || !timingSafeEqual(provided, expected)) {
        await recordFailure(env, ip);
        return Response.json({ error: "Unauthorized bridge secret" }, { status: 401 });
      }
      await clearFailures(env, ip);
      let body;
      try {
        body = await request.json();
      } catch {
        return Response.json({ error: "Invalid JSON body" }, { status: 400 });
      }
      const origin = String(body.origin || "").trim().replace(/\/+$/, "");
      if (!/^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(origin)) {
        return Response.json({ error: "Invalid HTTPS origin URL" }, { status: 400 });
      }
      const now = new Date().toISOString();
      await env.STATE.put(ORIGIN_KEY, origin);
      await env.STATE.put(UPDATED_KEY, now);
      return Response.json({ ok: true, origin, updated_at: now });
    }

    // 2. Edge health diagnostics
    if (url.pathname === "/_edge-status" || url.pathname === "/edge-health") {
      const origin = await env.STATE.get(ORIGIN_KEY);
      const updated = await env.STATE.get(UPDATED_KEY);
      return Response.json({
        ok: true,
        app: env.APP_NAME || "CrackSentinel",
        host: url.host,
        engineConfigured: Boolean(origin),
        updatedAt: updated || null,
      });
    }

    // 3. Proxy /api/* to HomeServer Go Engine via live Cloudflare Tunnel
    if (url.pathname.startsWith("/api/")) {
      const origin = await env.STATE.get(ORIGIN_KEY);
      if (!origin) {
        return Response.json(
          { error: "CrackSentinel HomeServer engine belum terhubung. Tunggu beberapa detik...", engineOffline: true },
          { status: 503, headers: { "Cache-Control": "no-store" } }
        );
      }

      const target = `${origin}${url.pathname}${url.search}`;
      const headers = new Headers(request.headers);
      headers.delete("host");
      headers.delete("cf-connecting-ip");
      headers.delete("cf-ipcountry");
      headers.delete("cf-ray");
      headers.delete("cf-visitor");
      headers.set("X-Forwarded-Host", url.host);
      headers.set("X-Forwarded-Proto", "https");

      const isBody = request.method !== "GET" && request.method !== "HEAD";
      try {
        const upstream = await fetch(target, {
          method: request.method,
          headers,
          body: isBody ? request.body : undefined,
          redirect: "manual",
        });
        const respHeaders = new Headers(upstream.headers);
        respHeaders.set("X-CrackSentinel-Edge", "cloudflare");
        return new Response(upstream.body, {
          status: upstream.status,
          statusText: upstream.statusText,
          headers: respHeaders,
        });
      } catch (err) {
        return Response.json(
          { error: "HomeServer upstream unreachable", engineOffline: true, detail: String(err) },
          { status: 502, headers: { "Cache-Control": "no-store" } }
        );
      }
    }

    // 4. Serve static Dashboard UI directly from Cloudflare Edge Assets (instant 24/7)
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return new Response("CrackSentinel Edge Assets not bound", { status: 500 });
  },
};
