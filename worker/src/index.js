// CrackSentinel shared-reputation telemetry worker (vanilla, zero deps).
//
//   POST /v1/report        Bearer <TELEMETRY_KEY>, JSON {reports:[{sha,verdict,score,rules?}]}
//   GET  /v1/lookup/:sha   public, shared reputation for one hash
//   GET  /                 public dashboard (recent reports)
//
// Privacy: only file hashes + verdicts + scores are stored. No filenames,
// no paths, no IPs. Reporting is opt-in on the scanner side.

const VALID = new Set(["CLEAN", "SUSPICIOUS", "MALICIOUS"]);
const SHA_RE = /^[0-9a-f]{64}$/;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function unauthorized() {
  return json({ ok: false, error: "unauthorized" }, 401);
}

// Constant-time compare so key probing gains nothing from timing.
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function authed(req, env) {
  const h = req.headers.get("authorization") || "";
  const tok = h.startsWith("Bearer ") ? h.slice(7) : "";
  return !!env.TELEMETRY_KEY && safeEqual(tok, env.TELEMETRY_KEY);
}

function cleanReport(r) {
  if (!r || typeof r !== "object") return null;
  const sha = String(r.sha || "").toLowerCase();
  const verdict = String(r.verdict || "").toUpperCase();
  let score = Number(r.score);
  if (!SHA_RE.test(sha) || !VALID.has(verdict)) return null;
  if (!Number.isFinite(score)) score = 0;
  score = Math.max(0, Math.min(100, Math.round(score)));
  let rules = "";
  if (Array.isArray(r.rules)) rules = r.rules.map(String).slice(0, 12).join(",");
  else if (typeof r.rules === "string") rules = r.rules.slice(0, 300);
  return { sha, verdict, score, rules };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === "POST" && path === "/v1/report") {
      if (!authed(req, env)) return unauthorized();
      let body;
      try {
        body = await req.json();
      } catch {
        return json({ ok: false, error: "bad json" }, 400);
      }
      const list = Array.isArray(body.reports) ? body.reports : [];
      if (list.length > 500) return json({ ok: false, error: "too many (max 500)" }, 400);
      const now = Math.floor(Date.now() / 1000);
      let stored = 0;
      const stmts = [];
      for (const raw of list) {
        const r = cleanReport(raw);
        if (!r) continue;
        stmts.push(
          env.DB.prepare(
            `INSERT INTO reports (sha, verdict, score, count, rules, first_seen, last_seen)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?5)
             ON CONFLICT(sha) DO UPDATE SET
               verdict=excluded.verdict, score=excluded.score, rules=excluded.rules,
               count=count+1, last_seen=excluded.last_seen`
          ).bind(r.sha, r.verdict, r.score, r.rules, now)
        );
        stored++;
      }
      if (stmts.length) await env.DB.batch(stmts);
      return json({ ok: true, stored });
    }

    const lookup = path.match(/^\/v1\/lookup\/([0-9a-fA-F]{64})$/);
    if (req.method === "GET" && lookup) {
      const sha = lookup[1].toLowerCase();
      const row = await env.DB.prepare(
        "SELECT sha, verdict, score, count, first_seen, last_seen FROM reports WHERE sha=?1"
      )
        .bind(sha)
        .first();
      if (!row) return json({ found: false, sha });
      return json({ found: true, ...row });
    }

    if (req.method === "GET" && (path === "/" || path === "/index.html")) {
      return dashboard(env);
    }

    return json({ ok: false, error: "not found" }, 404);
  },
};

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function dashboard(env) {
  let rows = [];
  try {
    const res = await env.DB.prepare(
      "SELECT sha, verdict, score, count, datetime(last_seen,'unixepoch') AS seen FROM reports ORDER BY last_seen DESC LIMIT 100"
    ).all();
    rows = res.results || [];
  } catch {
    rows = [];
  }
  const tr = rows
    .map(
      (r) =>
        `<tr><td><code>${esc(String(r.sha).slice(0, 16))}…</code></td>` +
        `<td>${esc(r.verdict)}</td><td>${esc(r.score)}</td>` +
        `<td>${esc(r.count)}</td><td>${esc(r.seen)}</td></tr>`
    )
    .join("");
  const html = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="120">
<title>CrackSentinel shared reputation</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.3rem .6rem;font-size:.85rem}
code{font-size:.8rem}</style></head><body>
<h1>CrackSentinel shared reputation</h1>
<p>Opt-in community telemetry: file hashes + verdicts only. No filenames, no paths.</p>
<table><tr><th>sha (prefix)</th><th>verdict</th><th>score</th><th>reports</th><th>last seen (UTC)</th></tr>
${tr || '<tr><td colspan="5">no reports yet</td></tr>'}</table>
</body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
}
