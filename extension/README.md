# WTD Companion (optional Chromium MV3 extension)

A small companion to the dashboard. It does **not** replace the investigation interface, and it is **not** real-time or pre-navigation protection.

## What it does (exact coverage)
| Action | Trigger | What is sent | Result |
|---|---|---|---|
| Check this page | You click the toolbar icon, then "Check this page" | The current tab's http(s) URL (fragment removed) | Verdict, rule and top findings in the popup, plus a link to the full report |
| Check this link | Right-click a link → "Check this link with WTD (without opening it)" | The link's http(s) URL | Opens the dashboard report tab; the browser does not open the link itself |

The extension never reads page content, cookies, form data or browsing history, and never checks anything automatically. It talks only to `http://127.0.0.1:8000` (pinned in code and in `host_permissions`). No AI or intelligence keys live in the extension: it holds only the local operator token, which you enter.

Permissions: `activeTab` (read the current tab's URL after your click), `contextMenus`, `storage` (token and the last 10 job ids, so results survive the popup closing and service-worker suspension), and host access to the local server only.

Why not automatic blocking: in Manifest V3, blocking `webRequest` is limited to policy-installed extensions, and `declarativeNetRequest` rules are static and cannot consult a server before a page loads. A page check necessarily happens after navigation.

## Install (unpacked, for the demo)
1. Start the server: `scripts/api.sh start`.
2. Chrome → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select this `extension/` folder.
3. Open the extension's **Details → Extension options**, paste the token from `data/api_token`, and click **Save**. It should say "Connected".

## Tests
- `node extension/test.mjs`: pure-function tests (URL filtering, defanging, job persistence, server pinning, missing-token error), with the chrome API stubbed.
- Manual in-browser check (Chrome 157 no longer supports loading unpacked extensions from the command line, so this step is manual):
  1. On `https://example.com/`, click the icon → **Check this page** → a Low Risk verdict appears.
  2. Close the popup during analysis and reopen it → the result resumes.
  3. Right-click a link → **Check this link with WTD** → the dashboard report tab opens.
  4. Stop the server → **Check this page** → a clear "not reachable" error.
  5. On `chrome://extensions`, the button is disabled ("only http/https pages").
