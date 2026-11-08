// End-to-end check of the public demo mode (WTD_PUBLIC_DEMO=1) in a real browser (Brave by default):
// banner and quota line → analysis with no token and no token dialog → on-chain register + app verify on the
// local chain without a token → quota counts down → session limit enforced with the server's explanation →
// a new tab starts a new session.
// Usage: start the API with a small session limit, e.g.
//   WTD_PUBLIC_DEMO=1 WTD_PUBLIC_SESSION_LIMIT=3 scripts/api.sh start   (plus scripts/chain.sh start; scripts/deploy.sh)
//   node e2e/public-demo.mjs [--base http://127.0.0.1:8000] [--shots docs/screenshots]
import { join, resolve } from "node:path";
import { launch, ROOT, step, summary, waitForText } from "./lib.mjs";

const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith("--") ? [...a, [v.slice(2), all[i + 1]]] : a), []));
const BASE = args.base || "http://127.0.0.1:8000";
const SHOTS = resolve(ROOT, args.shots || "docs/screenshots");

const browser = await launch();
const page = await browser.newPage();
await page.setViewport({ width: 1366, height: 900, deviceScaleFactor: 1 });
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));
const tokenHeaders = [];
page.on("request", (r) => r.headers()["x-wtd-token"] && tokenHeaders.push(r.url()));
const tokenDialogOpen = () => page.$eval("body", () => !!document.querySelector('dialog[open] input[placeholder="Paste the operator token"]'));

let limit;
try {
  await step("Server is a public demo; banner and quota line show without a token", async () => {
    const h = await (await fetch(`${BASE}/api/health`)).json();
    if (h.access?.mode !== "public_demo") throw new Error(`access mode is ${JSON.stringify(h.access)}; start with WTD_PUBLIC_DEMO=1`);
    limit = h.access.session_limit;
    if (limit < 2 || limit > 5) throw new Error(`use a small WTD_PUBLIC_SESSION_LIMIT (2-5) for this test, got ${limit}`);
    await page.goto(`${BASE}/#/`, { waitUntil: "networkidle0" });
    await waitForText(page, ".public-banner", /PUBLIC DEMO/);
    const q = await waitForText(page, ".intake-quota", new RegExp(`${limit} of ${limit} analyses left`));
    await page.screenshot({ path: join(SHOTS, "20-public-demo.png") });
    return q;
  });

  await step("URL analysis runs with no token and no token dialog", async () => {
    await page.click("#tab-url");
    await page.type("#panel-url input", "https://example.com/");
    await page.click("button[type=submit]");
    await page.waitForFunction(() => location.hash.startsWith("#/r/"), { timeout: 20000 });
    if (await tokenDialogOpen()) throw new Error("token dialog opened");
    return await waitForText(page, "#verdict-h", /High Risk|Suspicious|Confirmed Malicious|Low Risk|Inconclusive/, 150000);
  });

  await step("Register on the local chain and verify, without a token", async () => {
    await page.$eval("#registry", (el) => el.scrollIntoView());
    await page.click("::-p-text(Register commitment on-chain)");
    await page.waitForSelector("::-p-text(Verify integrity (app))", { timeout: 60000 });
    await page.click("::-p-text(Verify integrity (app))");
    const m = await waitForText(page, ".verify-result", /Match: .*revision 0 \(latest\)/, 20000);
    if (await tokenDialogOpen()) throw new Error("token dialog opened");
    return m;
  });

  await step("Quota counts down, then the session limit is enforced with an explanation", async () => {
    await page.goto(`${BASE}/#/`, { waitUntil: "networkidle0" });
    await waitForText(page, ".intake-quota", new RegExp(`${limit - 1} of ${limit} analyses left`));
    // Use up the rest of the session from the same tab (same session id), then try once more in the UI.
    const codes = await page.evaluate(async (n) => {
      const out = [];
      for (let i = 0; i < n; i++) {
        const r = await fetch("/api/analyses", { method: "POST", headers: { "Content-Type": "application/json", "X-WTD-Session": sessionStorage.getItem("wtd.session") }, body: JSON.stringify({ kind: "url", url: `https://example.org/q${i}` }) });
        out.push(r.status);
      }
      return out;
    }, limit - 1);
    if (!codes.every((c) => c === 202)) throw new Error(`fill-up codes ${codes}`);
    await page.reload({ waitUntil: "networkidle0" });
    await waitForText(page, ".intake-quota", /Session limit reached/);
    await page.click("#tab-url");
    await page.type("#panel-url input", "https://example.net/");
    await page.click("button[type=submit]");
    const msg = await waitForText(page, ".intake", new RegExp(`allows ${limit} analyses per browser session`), 10000);
    if ((await page.evaluate(() => location.hash)).startsWith("#/r/")) throw new Error("navigated to a report past the limit");
    await page.screenshot({ path: join(SHOTS, "21-public-demo-limit.png") });
    return msg;
  });

  await step("A new tab is a new session with a fresh allowance", async () => {
    const tab2 = await browser.newPage();
    await tab2.goto(`${BASE}/#/`, { waitUntil: "networkidle0" });
    const q = await waitForText(tab2, ".intake-quota", new RegExp(`${limit} of ${limit} analyses left`));
    const ids = await Promise.all([page, tab2].map((p) => p.evaluate(() => sessionStorage.getItem("wtd.session"))));
    await tab2.close();
    if (!ids[0] || ids[0] === ids[1]) throw new Error(`session ids ${ids}`);
    return q;
  });

  await step("No token was ever sent and there were no page errors", async () => {
    if (tokenHeaders.length) throw new Error(`token sent to ${tokenHeaders.join(", ")}`);
    if (errors.length) throw new Error(errors.join(" | "));
  });
} catch {
  /* reported by step() */
} finally {
  await browser.close();
}
process.exit(summary("public-demo", { session_limit: limit }));
