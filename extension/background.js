const LOCAL_API = "http://127.0.0.1:8787";
const CLOUD_API = "https://sentinel.breakthematrix.id";
const MAX_ITEMS = 30;

async function getSettings() {
  return await chrome.storage.local.get({
    autoScan: true,
    autoPauseMaliciousUrl: true,
    cloudUrl: CLOUD_API,
    accessKey: "",
    recent: []
  });
}

function authHeaders(cfg) {
  const h = { "Content-Type": "application/json" };
  if (cfg.accessKey) h["X-Access-Key"] = cfg.accessKey;
  return h;
}

async function recordScan(entry) {
  const { recent } = await getSettings();
  const next = [entry, ...recent].slice(0, MAX_ITEMS);
  await chrome.storage.local.set({ recent: next });
}

function setBadge(verdict) {
  if (verdict === "MALICIOUS") {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#f85149" });
  } else if (verdict === "SUSPICIOUS") {
    chrome.action.setBadgeText({ text: "?" });
    chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
  } else {
    chrome.action.setBadgeText({ text: "OK" });
    chrome.action.setBadgeBackgroundColor({ color: "#22c55e" });
  }
}

function notify(id, title, message) {
  chrome.notifications.create(id, {
    type: "basic",
    iconUrl: "data:image/svg+xml," + encodeURIComponent(
      `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128"><rect width="128" height="128" rx="24" fill="#1d4ed8"/><text x="64" y="82" text-anchor="middle" font-family="Arial,sans-serif" font-weight="bold" font-size="56" fill="#fff">CS</text></svg>`
    ),
    title,
    message,
    priority: 2
  });
}

// Try local CrackSentinel first; fall back to 24/7 cloud endpoint for URL checks.
async function postURLCheck(cfg, payload) {
  const bases = [LOCAL_API, (cfg.cloudUrl || CLOUD_API).replace(/\/+$/, "")];
  for (const base of bases) {
    try {
      const resp = await fetch(`${base}/api/check-url`, {
        method: "POST",
        headers: authHeaders(cfg),
        body: JSON.stringify(payload)
      });
      if (resp.ok) return { data: await resp.json(), base };
    } catch (_) {}
  }
  return null;
}

// 1. Pre-check URL immediately when a download starts (works 24/7 via cloud fallback!).
chrome.downloads.onCreated.addListener(async (item) => {
  const cfg = await getSettings();
  if (!cfg.autoScan) return;
  const targetUrl = item.finalUrl || item.url || "";
  if (!targetUrl.startsWith("http")) return;

  const res = await postURLCheck(cfg, {
    url: targetUrl,
    referrer: item.referrer || "",
    filename: item.filename || "",
    size: item.fileSize > 0 ? item.fileSize : 0,
    probe: false
  });
  if (!res) return;
  const { data } = res;
  if (data.verdict === "MALICIOUS" || data.verdict === "SUSPICIOUS") {
    setBadge(data.verdict);
    const top = (data.findings || []).find((f) => f.severity > 0);
    let msg = `${data.filename || data.domain || targetUrl}\nSkor URL: ${data.score}`;
    if (top) msg += ` — ${top.detail}`;
    if (data.verdict === "MALICIOUS" && cfg.autoPauseMaliciousUrl) {
      try {
        await chrome.downloads.pause(item.id);
        msg = "[DI-PAUSE OTOMATIS] " + msg;
      } catch (_) {}
    }
    notify(`cs-url-${item.id}`, `CrackSentinel Peringatan Link (${data.verdict})`, msg);
    await recordScan({
      time: new Date().toLocaleTimeString(),
      stage: "url-precheck",
      target: data.filename || data.domain || targetUrl,
      verdict: data.verdict,
      score: data.score,
      detail: top ? top.detail : "URL mencurigakan"
    });
  }
});

// 2. Scan the actual downloaded file/archive on local disk when CrackSentinel-UI.bat is running.
chrome.downloads.onChanged.addListener(async (delta) => {
  if (!delta.state || delta.state.current !== "complete") return;
  const cfg = await getSettings();
  if (!cfg.autoScan) return;

  const items = await chrome.downloads.search({ id: delta.id });
  if (!items || !items.length) return;
  const item = items[0];
  if (!item.filename) return;

  try {
    const resp = await fetch(`${LOCAL_API}/api/scan-paths`, {
      method: "POST",
      headers: authHeaders(cfg),
      body: JSON.stringify({
        paths: [item.filename],
        source: "extension",
        source_url: item.finalUrl || item.url || "",
        referrer: item.referrer || ""
      })
    });
    if (!resp.ok) return;
    const data = await resp.json();
    const verdict = data.top_verdict || "CLEAN";
    const score = data.max_score || 0;
    setBadge(verdict);

    let topDetail = "Tidak ada ancaman terdeteksi.";
    const results = (data.summary && data.summary.results) || [];
    for (const r of results) {
      const f = (r.findings || []).find((x) => x.severity > 0);
      if (f) {
        topDetail = `${f.rule}: ${f.detail}`;
        break;
      }
    }

    const shortName = item.filename.split(/[\\/]/).pop();
    notify(
      `cs-file-${item.id}`,
      `CrackSentinel: ${verdict} (Skor ${score})`,
      `${shortName}\n${topDetail}`
    );
    await recordScan({
      id: data.id,
      time: new Date().toLocaleTimeString(),
      stage: "file-scan",
      target: shortName,
      verdict,
      score,
      detail: topDetail
    });
  } catch (_) {}
});

chrome.notifications.onClicked.addListener(async () => {
  const cfg = await getSettings();
  try {
    const r = await fetch(`${LOCAL_API}/api/health`);
    if (r.ok) return chrome.tabs.create({ url: LOCAL_API });
  } catch (_) {}
  chrome.tabs.create({ url: cfg.cloudUrl || CLOUD_API });
});
