// Service worker: only registers the context menu and handles explicit "check this link" clicks.
// It keeps no in-memory state (it can be suspended at any time); job ids live in chrome.storage.
import { allowedForSession, checkableUrl, quickCheck, realtimeEnabled, reportUrl, skipRealtime, submitUrl } from "./common.js";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "wtd-check-link", title: "Check this link with WTD (without opening it)", contexts: ["link"] });
});

export async function handleMenuClick(info) {
  if (info.menuItemId !== "wtd-check-link") return;
  const url = checkableUrl(info.linkUrl || "");
  if (!url) return;
  try {
    const id = await submitUrl(url);
    // Open the full dashboard report (shows progress); the link itself is never opened by the browser.
    chrome.tabs.create({ url: await reportUrl(id) });
  } catch (e) {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setTitle({ title: `WTD: ${String(e.message || e).slice(0, 200)}` });
  }
}
chrome.contextMenus.onClicked.addListener(handleMenuClick);
globalThis.wtdHandleMenuClick = handleMenuClick; // lets the automated browser test drive the real handler

// ---------------------------------------------------------------- opt-in real-time warning
// Only active when the user turned it on in the options page AND granted the optional "webNavigation" permission.
// For each top-level navigation the address (only) goes to the local WTD server's quick check. High Risk or
// Confirmed Malicious replaces the tab with a warning page. This races the page load: it is a warning that usually
// appears within a fraction of a second, not a guaranteed block.
const WARN_ON = new Set(["High Risk", "Confirmed Malicious"]);

export async function onBeforeNavigate(details) {
  if (details.frameId !== 0) return;
  if (!(await realtimeEnabled())) return;
  const url = checkableUrl(details.url || "");
  if (!url || skipRealtime(url)) return;
  const host = new URL(url).hostname;
  if (await allowedForSession(host)) return;
  const res = await quickCheck(url);
  if (!res || !WARN_ON.has(res.classification)) return;
  const payload = encodeURIComponent(JSON.stringify({ url, res }));
  await chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL(`warning.html#${payload}`) });
}
globalThis.wtdOnBeforeNavigate = onBeforeNavigate; // for the automated browser test

function attachNavigationListener() {
  if (chrome.webNavigation && !chrome.webNavigation.onBeforeNavigate.hasListener(onBeforeNavigate)) {
    const filter = { url: [{ schemes: ["http", "https"] }] };
    chrome.webNavigation.onBeforeNavigate.addListener(onBeforeNavigate, filter);
    // Server-side redirects to another host do not fire onBeforeNavigate again; check the committed address too
    // (the server caches quick-check results, so a repeat check of the same address is cheap).
    chrome.webNavigation.onCommitted.addListener(onBeforeNavigate, filter);
  }
}
attachNavigationListener();
chrome.permissions.onAdded.addListener(attachNavigationListener);
