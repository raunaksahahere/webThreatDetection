// In-browser check of the MV3 companion extension (extension/) in a real Chromium-family browser (Brave by default).
// Part A loads the unpacked extension exactly as shipped:
//   service worker + context-menu registration → no-token error → options page rejects a wrong token and accepts the
//   real one → without a user gesture the popup cannot read the page address (activeTab privacy) → the real
//   context-menu handler checks a link without the browser ever opening it, and opens the dashboard report.
// Part B checks the popup's "Check this page" flow. Automation cannot click the browser toolbar, which is what grants
//   activeTab, so a throwaway copy of the extension gets a host permission for the test origin only — the same
//   access a toolbar click grants — and everything else is unchanged.
// The native right-click menu cannot be driven by automation; its registration and its handler are checked instead.
// Usage: node e2e/extension.mjs   (needs the API running: scripts/api.sh start)
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { launch, ROOT, step, summary, waitForText } from "./lib.mjs";

const TOKEN = readFileSync(join(ROOT, "data/api_token"), "utf8").trim();
const SHOTS = join(ROOT, "docs/screenshots");
const PAGE_URL = "https://example.com/";
const LINK_URL = "https://paypa1.com/signin"; // typosquat; analysed by the server, never opened by the browser
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function start(extDir) {
  const browser = await launch({ extension: extDir });
  const t = await browser.waitForTarget((t) => t.type() === "service_worker" && t.url().endsWith("/sw.js"), { timeout: 15000 });
  const worker = await t.worker();
  for (let i = 0; i < 50 && !(await worker.evaluate(() => typeof chrome !== "undefined" && !!chrome.contextMenus).catch(() => false)); i++) await sleep(200);
  return { browser, worker, extId: new URL(t.url()).host };
}

async function openPopupOn(browser, worker, url) {
  const p = await browser.newPage();
  await p.setViewport({ width: 1200, height: 800 });
  await p.goto(url, { waitUntil: "domcontentloaded" });
  await p.bringToFront();
  await worker.evaluate(() => chrome.action.openPopup());
  const pt = await browser.waitForTarget((t) => t.url().endsWith("/popup.html"), { timeout: 10000 });
  return pt.asPage();
}

let extId;
// ------------------------------------------------------------------ Part A: extension as shipped
{
  const { browser, worker, extId: id } = await start(join(ROOT, "extension"));
  extId = id;
  try {
    await step("Extension loads; service worker starts", async () => `id ${extId}`);

    await step("Context-menu item 'Check this link with WTD' is registered", async () => {
      // onInstalled creates the item right after the worker starts; allow it up to 5 s. update() rejects while it is missing.
      let last;
      for (let i = 0; i < 25; i++) {
        last = await worker.evaluate(() => chrome.contextMenus.update("wtd-check-link", { title: "Check this link with WTD (without opening it)" }).then(() => null, (e) => String(e.message || e)));
        if (!last) return i ? `registered after ${i * 200} ms` : "";
        await sleep(200);
      }
      throw new Error(last);
    });

    await step("Without a token, a link check fails with a clear message (badge '!')", async () => {
      await worker.evaluate((u) => globalThis.wtdHandleMenuClick({ menuItemId: "wtd-check-link", linkUrl: u }), LINK_URL);
      const badge = await worker.evaluate(() => chrome.action.getBadgeText({}));
      const title = await worker.evaluate(() => chrome.action.getTitle({}));
      if (badge !== "!" || !/token/i.test(title)) throw new Error(`badge=${badge} title=${title}`);
      await worker.evaluate(() => chrome.action.setBadgeText({ text: "" }));
      return title;
    });

    await step("Options page reports a wrong token as rejected", async () => {
      const p = await browser.newPage();
      await p.goto(`chrome-extension://${extId}/options.html`);
      await p.type("#token", "wrong-token");
      await p.click("#save");
      const msg = await waitForText(p, "#status", /.+/, 10000);
      if (!/401/.test(msg)) throw new Error(`status: ${msg}`);
      await p.close();
      return msg;
    });

    await step("Options page saves the operator token; server accepts it", async () => {
      const p = await browser.newPage();
      await p.goto(`chrome-extension://${extId}/options.html`);
      await p.$eval("#token", (el) => (el.value = ""));
      await p.type("#token", TOKEN);
      await p.click("#save");
      const msg = await waitForText(p, "#status", /.+/, 10000);
      if (!/Connected/.test(msg)) throw new Error(`status: ${msg}`);
      await p.close();
      return msg;
    });

    await step("Real-time warnings are off by default (no history permission held)", async () => {
      const has = await worker.evaluate(() => chrome.permissions.contains({ permissions: ["webNavigation"] }));
      const on = await worker.evaluate(async () => (await chrome.storage.local.get({ realtime: false })).realtime);
      if (has || on) throw new Error(`permission=${has} realtime=${on}`);
      return "webNavigation not granted; realtime=false";
    });

    await step("Privacy: without a user click the popup cannot read the page address", async () => {
      const popup = await openPopupOn(browser, worker, PAGE_URL);
      const txt = await waitForText(popup, "#target", /cannot be checked/, 5000);
      if (!(await popup.$eval("#check", (b) => b.disabled))) throw new Error("check button enabled without activeTab");
      await popup.close();
      return "URL hidden, check disabled";
    });

    await step("Real context-menu handler checks a link without opening it, then opens the report", async () => {
      await worker.evaluate((u) => globalThis.wtdHandleMenuClick({ menuItemId: "wtd-check-link", linkUrl: u }), LINK_URL);
      const t = await browser.waitForTarget((t) => t.url().startsWith("http://127.0.0.1:8000/#/r/"), { timeout: 15000 });
      if ((await browser.pages()).some((p) => p.url().includes("paypa1.com"))) throw new Error("the browser navigated to the checked link");
      const report = await t.asPage();
      await report.setViewport({ width: 1200, height: 800 });
      const tokenInput = await report.waitForSelector('dialog[open] input[placeholder="Paste the operator token"]', { timeout: 10000 }).catch(() => null);
      if (tokenInput) {
        await tokenInput.type(TOKEN); // the dashboard tab keeps its own token in sessionStorage
        await report.click("::-p-text(Use token)");
      }
      const cls = await waitForText(report, "#verdict-h", /High Risk|Suspicious|Low Risk|Inconclusive|Confirmed Malicious/, 150000);
      if (!/High Risk|Suspicious/.test(cls)) throw new Error(`typosquat verdict was ${cls}`);
      return `link never opened; report verdict ${cls}`;
    });
  } finally {
    await browser.close();
  }
}

// ------------------------------------------------------------------ Part B: popup check (activeTab grant simulated)
{
  const dir = mkdtempSync(join(tmpdir(), "wtd-ext-"));
  cpSync(join(ROOT, "extension"), dir, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  manifest.host_permissions = [...manifest.host_permissions, new URL(PAGE_URL).origin + "/*"];
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
  const { browser, worker } = await start(dir);
  try {
    await worker.evaluate((t) => chrome.storage.local.set({ token: t, base: "http://127.0.0.1:8000" }), TOKEN);
    await step("Popup 'Check this page' investigates the active page and shows the verdict", async () => {
      const popup = await openPopupOn(browser, worker, PAGE_URL);
      const target = await waitForText(popup, "#target", /example/, 5000);
      await popup.click("#check");
      const verdict = await waitForText(popup, "#verdict", /Low Risk|Suspicious|High Risk|Confirmed Malicious|Inconclusive|failed/, 150000);
      await sleep(300);
      await popup.screenshot({ path: join(SHOTS, "08-extension-popup.png") });
      if (verdict !== "Low Risk") throw new Error(`example.com verdict was ${verdict}`);
      return `${target} → ${verdict}`;
    });
  } finally {
    await browser.close();
  }
}
// ------------------------------------------------------------------ Part C: opt-in real-time warning
// The optional webNavigation permission needs a user click to grant, so the throwaway copy declares it as required.
{
  const dir = mkdtempSync(join(tmpdir(), "wtd-ext-rt-"));
  cpSync(join(ROOT, "extension"), dir, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  manifest.permissions = [...manifest.permissions, "webNavigation"];
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
  const { browser, worker } = await start(dir);
  try {
    await worker.evaluate((t) => chrome.storage.local.set({ token: t, base: "http://127.0.0.1:8000", realtime: true }), TOKEN);
    const page = await browser.newPage();
    await page.setViewport({ width: 1200, height: 800 });

    await step("Real-time mode leaves a Low Risk page alone (example.com)", async () => {
      await page.goto(PAGE_URL, { waitUntil: "domcontentloaded" });
      await sleep(2500);
      if (!page.url().startsWith(PAGE_URL)) throw new Error(`redirected to ${page.url()}`);
      return page.url();
    });

    const RISKY = "https://xn--80ak6aa92e.com/"; // public, harmless homograph demonstration page imitating apple.com
    await step("Real-time mode replaces a High Risk page with the warning (homograph demo domain)", async () => {
      await page.goto(RISKY, { waitUntil: "domcontentloaded" }).catch(() => {});
      await page.waitForFunction(() => location.href.includes("/warning.html"), { timeout: 10000 });
      const v = await waitForText(page, "#verdict", /High Risk|Confirmed Malicious/, 5000);
      await sleep(300);
      await page.screenshot({ path: join(SHOTS, "10-extension-warning.png") });
      return v;
    });

    await step("'Continue' allows the site for this session without warning again", async () => {
      await Promise.all([page.waitForNavigation({ timeout: 15000 }).catch(() => {}), page.click("#proceed")]);
      await sleep(2500);
      if (page.url().includes("/warning.html")) throw new Error("warned again after continue");
      if (!/^https:\/\/(www\.)?xn--80ak6aa92e\.com/.test(page.url())) throw new Error(`at ${page.url()}`);
      return page.url();
    });

    await step("A server-side redirect to a risky host is caught on commit", async () => {
      // Fresh session allowlist; ask the real handler about a committed navigation whose final URL is risky.
      await worker.evaluate(() => chrome.storage.session.set({ allow: [] }));
      const tabId = await worker.evaluate(async () => (await chrome.tabs.query({ active: true, currentWindow: true }))[0].id);
      await worker.evaluate((id) => globalThis.wtdOnBeforeNavigate({ frameId: 0, tabId: id, url: "https://www.xn--80ak6aa92e.com/" }), tabId);
      await page.waitForFunction(() => location.href.includes("/warning.html"), { timeout: 10000 });
      return "warning shown for the redirect target";
    });
  } finally {
    await browser.close();
  }
}
process.exit(summary("extension", { extension_id: extId }));
