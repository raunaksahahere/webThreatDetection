import { DEFAULT_BASE } from "./common.js";

const tokenEl = document.getElementById("token");
chrome.storage.local.get({ token: "" }).then((s) => { tokenEl.value = s.token; });
document.getElementById("save").addEventListener("click", async () => {
  const token = tokenEl.value.trim();
  await chrome.storage.local.set({ token, base: DEFAULT_BASE });
  const status = document.getElementById("status");
  try {
    const r = await fetch(`${DEFAULT_BASE}/api/analyses?limit=1`, { headers: { "X-WTD-Token": token } });
    status.textContent = r.ok ? "Saved. Connected to the WTD server." : `Saved, but the server answered HTTP ${r.status}.`;
  } catch {
    status.textContent = "Saved, but the WTD server is not reachable (is scripts/api.sh running?).";
  }
});
