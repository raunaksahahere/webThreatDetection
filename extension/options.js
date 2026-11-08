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

const rt = document.getElementById("realtime");
const rtStatus = document.getElementById("rt-status");
chrome.storage.local.get({ realtime: false }).then(async (s) => {
  rt.checked = s.realtime && (await chrome.permissions.contains({ permissions: ["webNavigation"] }));
});
rt.addEventListener("change", async () => {
  if (rt.checked) {
    const granted = await chrome.permissions.request({ permissions: ["webNavigation"] }); // needs this click (user gesture)
    if (!granted) {
      rt.checked = false;
      rtStatus.textContent = "Permission not granted; real-time warnings stay off.";
      return;
    }
    await chrome.storage.local.set({ realtime: true });
    rtStatus.textContent = "On. Risky pages will be replaced by a warning.";
  } else {
    await chrome.storage.local.set({ realtime: false });
    await chrome.permissions.remove({ permissions: ["webNavigation"] });
    rtStatus.textContent = "Off. Permission removed.";
  }
});
