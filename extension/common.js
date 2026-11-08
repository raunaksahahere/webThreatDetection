// Shared helpers. No page content, cookies, history or form data are ever read or sent.
export const DEFAULT_BASE = "http://127.0.0.1:8000";
const ALLOWED_BASES = new Set(["http://127.0.0.1:8000"]); // must match host_permissions

export async function settings() {
  const s = await chrome.storage.local.get({ base: DEFAULT_BASE, token: "" });
  if (!ALLOWED_BASES.has(s.base)) s.base = DEFAULT_BASE;
  return s;
}

// Only http(s) URLs with a host are ever submitted, and only after an explicit user action.
export function checkableUrl(u) {
  try {
    const p = new URL(u);
    if (p.protocol !== "http:" && p.protocol !== "https:") return null;
    if (!p.hostname) return null;
    p.hash = "";
    return p.href.slice(0, 2048);
  } catch {
    return null;
  }
}

export async function submitUrl(url) {
  const { base, token } = await settings();
  if (!token) throw new Error("Set the operator token in the extension options first.");
  const r = await fetch(`${base}/api/analyses`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-WTD-Token": token },
    body: JSON.stringify({ kind: "url", url }),
  });
  if (r.status === 401) throw new Error("The WTD server rejected the token (check the extension options).");
  if (r.status === 422) throw new Error((await r.json()).detail || "This address cannot be investigated.");
  if (r.status === 429) throw new Error("Rate limited by the WTD server; try again in a minute.");
  if (!r.ok) throw new Error(`WTD server error (HTTP ${r.status}).`);
  const j = await r.json();
  if (typeof j.id !== "string" || !/^[0-9a-f-]{36}$/.test(j.id)) throw new Error("Unexpected response from the WTD server.");
  await remember({ id: j.id, url, at: Date.now() });
  return j.id;
}

export async function getReport(id) {
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error("bad id");
  const { base, token } = await settings();
  const r = await fetch(`${base}/api/analyses/${id}`, { headers: { "X-WTD-Token": token } });
  if (!r.ok) throw new Error(`WTD server error (HTTP ${r.status}).`);
  return r.json();
}

export async function reportUrl(id) {
  const { base } = await settings();
  return `${base}/#/r/${encodeURIComponent(id)}`;
}

// Job ids persist in storage so results survive the popup closing and service-worker suspension.
export async function remember(job) {
  const { jobs = [] } = await chrome.storage.local.get("jobs");
  const next = [job, ...jobs.filter((j) => j.id !== job.id)].slice(0, 10);
  await chrome.storage.local.set({ jobs: next });
}

export async function recentJobs() {
  const { jobs = [] } = await chrome.storage.local.get("jobs");
  return jobs;
}

export function defang(u) {
  return u.replace(/^http/i, "hxxp").replace(/^([a-z]+:\/\/)([^/?#]*)/i, (_, s, h) => s + h.replaceAll(".", "[.]"));
}
