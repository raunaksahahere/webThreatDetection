// Service worker: only registers the context menu and handles explicit "check this link" clicks.
// It keeps no in-memory state (it can be suspended at any time); job ids live in chrome.storage.
import { checkableUrl, reportUrl, submitUrl } from "./common.js";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "wtd-check-link", title: "Check this link with WTD (without opening it)", contexts: ["link"] });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
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
});
