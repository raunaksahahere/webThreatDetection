// Free-demonstration notice, in a real browser at desktop and mobile widths. The server decides which notice is true, so run it once per state:
//   pending: no registry deployed (e.g. WTD_DEPLOYMENT=/nonexistent.json) -> notice says Sepolia is pending, Register is disabled with its reason
//   local:   a local anvil chain with a deployed registry                 -> notice says "local", Register works (and is exercised)
// Needs a server with WTD_PUBLIC_DEMO=1 so that no token is involved: it also proves investigation works without a wallet or token.
// Usage: node e2e/free-demo.mjs --state pending|local [--base http://127.0.0.1:8000] [--shots <dir>]
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { launch, ROOT } from "./lib.mjs";
const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith("--") ? [...a, [v.slice(2), all[i + 1]]] : a), []));
const state = args.state;
if (!["pending", "local"].includes(state)) { console.error("usage: node e2e/free-demo.mjs --state pending|local [--base URL] [--shots DIR]"); process.exit(2); }
const out = resolve(ROOT, args.shots || "docs/screenshots/free-demo");
mkdirSync(out, { recursive: true });
const BASE = args.base || "http://127.0.0.1:8000";
const log = (ok, msg) => { console.log(`${ok ? "PASS" : "FAIL"} [${state}] ${msg}`); if (!ok) process.exitCode = 1; };
const browser = await launch();
try {
for (const [label, vp] of [["desktop", { width: 1280, height: 900 }], ["mobile", { width: 390, height: 844, isMobile: true, deviceScaleFactor: 2 }]]) {
  const page = await browser.newPage();
  await page.setViewport(vp);
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(`${BASE}/#/`, { waitUntil: "networkidle0" });
  await page.waitForSelector("#tab-msg");
  const line = await page.evaluate(() => document.querySelector(".no-wallet-line")?.textContent || "");
  log(/No wallet needed/.test(line), `${label}: intake shows the no-wallet line`);
  await page.screenshot({ path: `${out}/${state}-${label}-investigate.png` });
  await page.click("#tab-msg");
  await page.type("#panel-msg textarea", "Dear SBI customer, your YONO account will be BLOCKED today. Update KYC within 2 hours at https://sbi-kyc-update.top/login and share the OTP.");
  await page.click("button[type=submit]");
  await page.waitForFunction(() => location.hash.startsWith("#/r/"), { timeout: 20000 });
  log(!(await page.$("dialog[open]")), `${label}: investigation started with no token dialog and no wallet prompt`);
  await page.waitForSelector("#verdict-h", { timeout: 30000 });
  await page.waitForSelector("#registry", { timeout: 30000 });
  await page.$eval("#registry", (el) => el.scrollIntoView());
  await page.waitForFunction(() => /Free demonstration mode|Blockchain status/.test(document.querySelector("#registry")?.textContent || ""), { timeout: 15000 });
  const reg = await page.$eval("#registry", (el) => el.innerText);
  log(/You can investigate links and messages without connecting or funding a wallet/.test(reg), `${label}: demo notice text present`);
  log(/No purchase of real cryptocurrency is required/.test(reg), `${label}: no-real-crypto statement present`);
  log(!/0x[0-9a-fA-F]{40}|successfully (deployed|registered)|tx hash/i.test(reg) || state === "local", `${label}: no address/deployment claims in the panel`);
  const btn = await page.$$eval("#registry button", (bs) => bs.map((b) => ({ t: b.textContent.trim(), d: b.disabled, desc: b.getAttribute("aria-describedby") })));
  const reg_btn = btn.find((b) => /Register commitment on-chain/.test(b.t));
  if (state === "pending") {
    log(reg_btn && reg_btn.d && reg_btn.desc === "chain-reason", `${label}: Register is disabled and tied to its reason`);
    log(/Public on-chain registration is pending Sepolia setup\. You can still use the investigation features\./.test(reg), `${label}: reason text beside the disabled action`);
    log(/awaiting deployment and configuration/.test(reg) && /roles/.test(reg), `${label}: deployment/roles/ETH all named, not just ETH`);
  } else {
    log(reg_btn && !reg_btn.d, `${label}: Register is enabled on the local chain`);
    log(/local Anvil chain inside this server/.test(reg) && /not public/.test(reg), `${label}: clearly labelled local`);
    log(!/pending Sepolia setup\. You can still/.test(reg), `${label}: the 'pending' reason is not shown when actions work`);
  }
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  log(overflow <= 1, `${label}: no horizontal overflow (${overflow}px)`);
  await page.$eval("#registry", (el) => el.scrollIntoView());
  await page.screenshot({ path: `${out}/${state}-${label}-registry.png` });
  log(errors.length === 0, `${label}: no page errors ${errors.join("|").slice(0, 120)}`);
  if (state === "local" && label === "desktop") {
    await page.click("::-p-text(Register commitment on-chain)");
    await page.waitForSelector("::-p-text(Verify integrity (app))", { timeout: 60000 });
    await page.click("::-p-text(Verify integrity (app))");
    await page.waitForFunction(() => /Match: /.test(document.querySelector(".verify-result")?.textContent || ""), { timeout: 20000 });
    log(true, "desktop: local registration and app verification still work");
    await page.$eval("#registry", (el) => el.scrollIntoView());
    await page.screenshot({ path: `${out}/${state}-desktop-registered.png` });
  }
  await page.close();
}
} finally {
  await browser.close();
}
