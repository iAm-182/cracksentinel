const LOCAL_API = "http://127.0.0.1:8787";
const CLOUD_API = "https://sentinel.breakthematrix.id";
const $ = (s) => document.querySelector(s);

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function resolveAPI(cfg) {
  for (const base of [LOCAL_API, (cfg.cloudUrl || CLOUD_API).replace(/\/+$/, "")]) {
    try {
      const r = await fetch(`${base}/api/health`);
      if (r.ok) return { base, data: await r.json(), isLocal: base === LOCAL_API };
    } catch (_) {}
  }
  return null;
}

async function init() {
  const cfg = await chrome.storage.local.get({
    autoScan: true,
    autoPauseMaliciousUrl: true,
    cloudUrl: CLOUD_API,
    accessKey: "",
    recent: []
  });
  $("#optScan").checked = cfg.autoScan;
  $("#optPause").checked = cfg.autoPauseMaliciousUrl;
  renderRecent(cfg.recent);

  $("#optScan").addEventListener("change", () => chrome.storage.local.set({ autoScan: $("#optScan").checked }));
  $("#optPause").addEventListener("change", () => chrome.storage.local.set({ autoPauseMaliciousUrl: $("#optPause").checked }));

  const active = await resolveAPI(cfg);
  if (active) {
    $("#st").textContent = (active.isLocal ? "Lokal " : "Cloud 24/7 ") + (active.data.version || "");
    $("#st").className = "status on";
  } else {
    $("#st").textContent = "Offline";
    $("#st").className = "status off";
  }

  $("#btnOpenUI").addEventListener("click", () => {
    chrome.tabs.create({ url: active ? active.base : (cfg.cloudUrl || CLOUD_API) });
  });

  $("#btnCheck").addEventListener("click", async () => {
    const url = $("#uIn").value.trim();
    if (!url) return;
    $("#uOut").innerHTML = '<span class="mut">Memeriksa...</span>';
    const target = active ? active.base : (cfg.cloudUrl || CLOUD_API);
    try {
      const headers = { "Content-Type": "application/json" };
      if (cfg.accessKey) headers["X-Access-Key"] = cfg.accessKey;
      const r = await fetch(`${target}/api/check-url`, {
        method: "POST",
        headers,
        body: JSON.stringify({ url, probe: true })
      });
      const d = await r.json();
      const top = (d.findings || []).find((f) => f.severity > 0);
      $("#uOut").innerHTML = `<span class="b ${esc(d.verdict)}">${esc(d.verdict)} (${d.score})</span><div class="mut" style="margin-top:4px">${esc(top ? top.detail : "Tidak ada indikator mencurigakan.")}</div>`;
    } catch (_) {
      $("#uOut").innerHTML = '<span class="b MALICIOUS">OFFLINE</span> <span class="mut">Server belum aktif.</span>';
    }
  });
}

function renderRecent(items) {
  if (!items || !items.length) return;
  $("#list").innerHTML = items.slice(0, 8).map((x) => `
    <div class="item">
      <span class="b ${esc(x.verdict)}">${esc(x.verdict)} ${x.score}</span>
      <b>${esc(x.target)}</b>
      <div class="mut">${esc(x.time)} · ${esc(x.detail)}</div>
    </div>
  `).join("");
}

init();
