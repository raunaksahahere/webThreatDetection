import { allowForSession, defang, reportUrl, submitUrl } from "./common.js";

const $ = (id) => document.getElementById(id);
let data = null;
try {
  data = JSON.parse(decodeURIComponent(location.hash.slice(1)));
} catch {
  data = null;
}
if (!data || typeof data.url !== "string" || !/^https?:\/\//.test(data.url)) {
  $("verdict").textContent = "Invalid warning";
} else {
  const res = data.res || {};
  $("verdict").textContent = String(res.classification || "Risky page"); // text only, never HTML
  $("target").textContent = defang(data.url);
  for (const f of (res.findings || []).slice(0, 5)) {
    const li = document.createElement("li");
    li.textContent = `${String(f.severity || "").toUpperCase()}: ${String(f.title || "")}`;
    $("findings").append(li);
  }
  $("rule").textContent = res.rule_id ? `${res.rule_id}: ${res.rule_text || ""}` : "";
  $("back").addEventListener("click", async () => {
    const tab = await chrome.tabs.getCurrent();
    if (history.length > 2) history.go(-2); // skip the risky page's own history entry
    else if (tab) chrome.tabs.remove(tab.id);
  });
  $("investigate").addEventListener("click", async () => {
    try {
      const id = await submitUrl(data.url);
      location.href = await reportUrl(id);
    } catch (e) {
      $("msg").textContent = String(e.message || e);
    }
  });
  $("proceed").addEventListener("click", async () => {
    await allowForSession(new URL(data.url).hostname);
    location.replace(data.url);
  });
}
