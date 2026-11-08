// End-to-end check of "bring your own URLhaus key" in a real browser (Brave by default):
// server without a URLhaus key → pill offers "add key" → malformed key blocked → wrong key rejected by abuse.ch →
// real key accepted → saved in sessionStorage only → analysis uses it → key absent from report and database →
// a new tab does not see it → remove key.
// Usage: WTD_E2E_URLHAUS_KEY=<your abuse.ch key> node e2e/urlhaus-key.mjs [--base http://127.0.0.1:8000] [--shots docs/screenshots]
// Start the API without a server key for this test: URLHAUS_AUTH_KEY= scripts/api.sh start
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { launch, ROOT, step, summary, waitForText } from "./lib.mjs";

const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith("--") ? [...a, [v.slice(2), all[i + 1]]] : a), []));
const BASE = args.base || "http://127.0.0.1:8000";
const SHOTS = resolve(ROOT, args.shots || "docs/screenshots");
const TOKEN = readFileSync(join(ROOT, "data/api_token"), "utf8").trim();
const KEY = (process.env.WTD_E2E_URLHAUS_KEY || "").trim();
if (!KEY) {
  console.error("Set WTD_E2E_URLHAUS_KEY to an abuse.ch Auth-Key");
  process.exit(2);
}
const WRONG = "0".repeat(48);
const KEY_INPUT = 'input[placeholder^="Paste your abuse.ch"], input[placeholder^="Paste a different key"]';
const pillText = (p) => p.$eval(".pill-btn", (b) => b.textContent.trim());

const browser = await launch();
const page = await browser.newPage();
await page.setViewport({ width: 1366, height: 900, deviceScaleFactor: 1 });
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
const sentHeaders = [];
page.on("request", (r) => r.url().includes("/api/") && sentHeaders.push({ url: r.url(), key: r.headers()["x-urlhaus-key"] || null }));

let reportId;
try {
  await step("Server has no URLhaus key; header pill and form line offer to add one", async () => {
    const h = await (await fetch(`${BASE}/api/health`)).json();
    if (h.intel.urlhaus !== "not configured") throw new Error(`server reports urlhaus '${h.intel.urlhaus}'; start it with URLHAUS_AUTH_KEY=`);
    await page.goto(`${BASE}/#/`, { waitUntil: "networkidle0" });
    await page.evaluate((t) => sessionStorage.setItem("wtd.operatorToken", t), TOKEN);
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector(".pill-btn");
    const pill = await pillText(page);
    if (pill !== "urlhaus · add key") throw new Error(`pill says '${pill}'`);
    await waitForText(page, ".intake-intel", /off on this server/);
    return pill;
  });

  await step("Malformed key is blocked in the dialog (Save disabled)", async () => {
    await page.click(".pill-btn");
    await page.waitForSelector(KEY_INPUT, { visible: true });
    await page.type(KEY_INPUT, "not a key!");
    await waitForText(page, "#urlhaus-title + p ~ p.dialog-warn", /letters and digits/);
    const disabled = await page.$eval("dialog[open] button[type=submit]", (b) => b.disabled);
    if (!disabled) throw new Error("Save was enabled for a malformed key");
  });

  await step("Well-formed wrong key: abuse.ch rejects it on Test", async () => {
    await page.$eval(KEY_INPUT, (i) => i.select());
    await page.keyboard.press("Backspace");
    await page.type(KEY_INPUT, WRONG);
    await page.click("::-p-text(Test key)");
    return await waitForText(page, "dialog[open] [role=status]", /rejected[^.]*/i, 20000);
  });

  await step("Real key: abuse.ch accepts it; Save keeps it in sessionStorage only", async () => {
    await page.$eval(KEY_INPUT, (i) => i.select());
    await page.keyboard.press("Backspace");
    await page.type(KEY_INPUT, KEY);
    await page.click("::-p-text(Test key)");
    await waitForText(page, "dialog[open] [role=status]", /accepted/i, 20000);
    await page.screenshot({ path: join(SHOTS, "18-urlhaus-own-key.png") });
    await page.click("::-p-text(Save for this tab)");
    await page.waitForFunction(() => !document.querySelector("dialog[open]"));
    const where = await page.evaluate((k) => ({
      session: sessionStorage.getItem("wtd.urlhausKey") === k,
      local: Object.keys(localStorage).some((x) => localStorage.getItem(x) === k),
    }), KEY);
    if (!where.session || where.local) throw new Error(JSON.stringify(where));
    const pill = await pillText(page);
    if (pill !== "urlhaus · your key") throw new Error(`pill says '${pill}'`);
    await waitForText(page, ".intake-intel", /use your own key/);
    return pill;
  });

  await step("URL analysis sends the key and URLhaus runs with it", async () => {
    await page.click("#tab-url");
    await page.type("#panel-url input", "https://example.com/");
    await page.click("button[type=submit]");
    await page.waitForFunction(() => location.hash.startsWith("#/r/"), { timeout: 20000 });
    reportId = decodeURIComponent((await page.evaluate(() => location.hash)).slice(4));
    const sent = sentHeaders.filter((h) => h.key);
    if (!sent.every((h) => /\/api\/(analyses|intel\/urlhaus\/check)$/.test(h.url))) throw new Error(`key sent to ${sent.map((h) => h.url)}`);
    if (!sent.some((h) => h.url.endsWith("/api/analyses"))) throw new Error("analysis request carried no X-URLhaus-Key");
    await waitForText(page, "#verdict-h", /High Risk|Suspicious|Confirmed Malicious|Low Risk|Inconclusive/, 150000);
    const r = await (await fetch(`${BASE}/api/analyses/${reportId}`, { headers: { "X-WTD-Token": TOKEN } })).json();
    const chk = r.checks.find((c) => c.name === "intel.urlhaus");
    if (!chk || chk.status !== "succeeded" || !/own key/.test(chk.detail)) throw new Error(`urlhaus check: ${JSON.stringify(chk)}`);
    await page.screenshot({ path: join(SHOTS, "19-report-own-urlhaus-key.png") });
    return `${r.assessment.classification}; check: ${chk.detail}`;
  });

  await step("Key is absent from the report JSON and the database files", async () => {
    const body = await (await fetch(`${BASE}/api/analyses/${reportId}`, { headers: { "X-WTD-Token": TOKEN } })).text();
    if (body.includes(KEY)) throw new Error("key found in report JSON");
    const data = join(ROOT, "data");
    const dbFiles = readdirSync(data).filter((f) => f.startsWith("wtd.sqlite3"));
    for (const f of dbFiles) if (readFileSync(join(data, f)).includes(Buffer.from(KEY))) throw new Error(`key found in ${f}`);
    const log = readFileSync(join(data, "api.log"), "utf8");
    if (log.includes(KEY)) throw new Error("key found in api.log");
    return `checked ${dbFiles.join(", ")} and api.log`;
  });

  await step("A new tab does not see the key (sessionStorage is per tab)", async () => {
    const tab2 = await browser.newPage();
    await tab2.goto(`${BASE}/#/`, { waitUntil: "networkidle0" });
    await tab2.waitForSelector(".pill-btn");
    const pill = await pillText(tab2);
    await tab2.close();
    if (pill !== "urlhaus · add key") throw new Error(`new tab pill says '${pill}'`);
    return pill;
  });

  await step("Remove key clears it from this tab", async () => {
    await page.goto(`${BASE}/#/`, { waitUntil: "networkidle0" });
    await page.click(".pill-btn");
    await page.waitForSelector("dialog[open]");
    await page.click("::-p-text(Remove key)");
    await page.waitForFunction(() => !document.querySelector("dialog[open]") && !sessionStorage.getItem("wtd.urlhausKey"));
    const pill = await pillText(page);
    if (pill !== "urlhaus · add key") throw new Error(`pill says '${pill}'`);
    if (errors.length) throw new Error(`page errors: ${errors.join(" | ")}`);
    return pill;
  });
} catch {
  /* reported by step() */
} finally {
  await browser.close();
}
process.exit(summary("urlhaus-key", { report: reportId }));
