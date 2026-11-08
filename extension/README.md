# WTD Companion (optional Chromium MV3 extension)

A small companion to the dashboard. It does **not** replace the investigation interface. Its optional real-time mode is an address-level warning, not a guaranteed block.

## What it does (exact coverage)
| Action | Trigger | What is sent | Result |
|---|---|---|---|
| Check this page | You click the toolbar icon, then "Check this page" | The current tab's http(s) URL (fragment removed) | Verdict, rule and top findings in the popup, plus a link to the full report |
| Check this link | Right-click a link → "Check this link with WTD (without opening it)" | The link's http(s) URL | Opens the dashboard report tab; the browser does not open the link itself |
| Warn before risky pages (**off by default**) | You turn it on in the options page and grant the optional `webNavigation` permission | Each top-level http(s) page address you open, to the **local** server's `/api/quick-check` (URL rules + local CERT Polska list; no page fetch, no third-party lookup). Local/private hosts are never sent | High Risk or Confirmed Malicious replaces the tab with a warning page (go back / full investigation / continue for this session) |

The extension never reads page content, cookies or form data. Unless you turn on the warning mode it never checks anything automatically. It talks only to `http://127.0.0.1:8000` (pinned in code and in `host_permissions`). No AI or intelligence keys live in the extension: it holds only the local operator token, which you enter.

Permissions: `activeTab` (read the current tab's URL after your click), `contextMenus`, `storage` (token and the last 10 job ids, so results survive the popup closing and service-worker suspension), and host access to the local server only.

Why a warning and not a block: in Manifest V3, blocking `webRequest` is limited to policy-installed extensions, and `declarativeNetRequest` rules are static and cannot consult a server before a page loads. The warning mode checks the address when navigation starts (and again when it commits, which catches server-side redirects to another host) and replaces the tab as soon as the verdict returns. The local check answers in a few milliseconds, but the page may begin loading first. The full page investigation (TLS, content, redirects) still needs the dashboard or "Run a full investigation".

## Install (unpacked, for the demo)
1. Start the server: `scripts/api.sh start`.
2. Chrome → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select this `extension/` folder.
3. Open the extension's **Details → Extension options**, paste the token from `data/api_token`, and click **Save**. It should say "Connected".

## Tests
- `node extension/test.mjs`: pure-function tests (URL filtering, defanging, job persistence, server pinning, missing-token error), with the chrome API stubbed.
- `cd e2e && node extension.mjs`: automated in a real browser (headless Brave by default) via puppeteer-core: 13 steps, including the privacy checks (no URL access without a click; warning mode off by default), the real context-menu handler, the popup check, and the warning mode (Low Risk page untouched, homograph page replaced by the warning, "continue" allowlists for the session, redirect target caught on commit). Toolbar clicks and the native right-click menu cannot be automated; see the comments in the script for how each is covered.
- Manual in-browser check (still useful before a demo):
  1. On `https://example.com/`, click the icon → **Check this page** → a Low Risk verdict appears.
  2. Close the popup during analysis and reopen it → the result resumes.
  3. Right-click a link → **Check this link with WTD** → the dashboard report tab opens.
  4. Stop the server → **Check this page** → a clear "not reachable" error.
  5. On `chrome://extensions`, the button is disabled ("only http/https pages").
