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

// ---------------------------------------------------------------- real-time mode (opt-in)
// Hosts never sent for real-time checks: local/private names and the WTD server itself.
export function skipRealtime(u) {
  try {
    const h = new URL(u).hostname.toLowerCase();
    if (!h.includes(".") || h === "localhost" || h.endsWith(".local") || h.endsWith(".localhost") || h.endsWith(".internal")) return true;
    if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|\[)/.test(h)) return true;
    return false;
  } catch {
    return true;
  }
}

export async function realtimeEnabled() {
  const { realtime = false } = await chrome.storage.local.get("realtime");
  return realtime === true;
}

/** Address-only verdict (URL rules + local threat list on the WTD server; nothing goes to third parties). */
export async function quickCheck(url, timeoutMs = 3000) {
  const { base, token } = await settings();
  if (!token) return null;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(`${base}/api/quick-check`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-WTD-Token": token },
      body: JSON.stringify({ url }),
      signal: ctl.signal,
    });
    return r.ok ? await r.json() : null;
  } catch {
    return null; // server down or slow: never block browsing
  } finally {
    clearTimeout(t);
  }
}

export async function allowedForSession(host) {
  const { allow = [] } = await chrome.storage.session.get("allow");
  return allow.some((a) => host === a || host.endsWith(`.${a}`)); // "continue" on a site also covers its subdomains
}

export async function allowForSession(host) {
  host = host.replace(/^www\./, "");
  const { allow = [] } = await chrome.storage.session.get("allow");
  await chrome.storage.session.set({ allow: [...new Set([host, ...allow])].slice(0, 200) });
}
