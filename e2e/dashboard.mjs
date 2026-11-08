// End-to-end click-through of the investigation dashboard in a real Chrome:
// token dialog → message analysis → verdict → register on-chain → app verify → download envelope →
// independent verifier (MATCH) → publish revision → old envelope is superseded → tampered copy is NO MATCH.
// Usage: node e2e/dashboard.mjs [--base http://127.0.0.1:8000] [--shots docs/screenshots]
// Needs a running API + chain (scripts/chain.sh start; scripts/deploy.sh; scripts/api.sh start).
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { launch, ROOT, step, summary, waitForText } from "./lib.mjs";

const args = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, all) => (v.startsWith("--") ? [...a, [v.slice(2), all[i + 1]]] : a), []));
const BASE = args.base || "http://127.0.0.1:8000";
const SHOTS = resolve(ROOT, args.shots || "docs/screenshots");
mkdirSync(SHOTS, { recursive: true });
const TOKEN = readFileSync(join(ROOT, "data/api_token"), "utf8").trim();
const DL = mkdtempSync(join(tmpdir(), "wtd-e2e-"));

const MESSAGE =
  "Dear SBI customer, your YONO account will be BLOCKED today. Update KYC within 2 hours at https://sbi-kyc-update.top/login and share the OTP you receive with our officer.";

const browser = await launch();
const page = await browser.newPage();
await page.setViewport({ width: 1366, height: 900, deviceScaleFactor: 1 });
const cdp = await page.createCDPSession();
await cdp.send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: DL });
const consoleErrors = [];
page.on("console", (m) => m.type() === "error" && consoleErrors.push(m.text()));
page.on("pageerror", (e) => consoleErrors.push(String(e)));
// A 404 on /threat-report is the API's "not registered yet" answer; any other failed request is an error.
const badResponses = [];
page.on("response", (r) => r.status() >= 400 && !(r.status() === 404 && r.url().endsWith("/threat-report")) && badResponses.push(`${r.status()} ${r.url()}`));

const verifier = (envelope) =>
  spawnSync("node", ["verifier/verify.mjs", "--envelope", envelope, "--deployment", "deployments/local.json"], { cwd: ROOT, encoding: "utf8" });

let reportId;
try {
  await step("Investigate page loads", async () => {
    await page.goto(`${BASE}/#/`, { waitUntil: "networkidle0" });
    await page.waitForSelector("#tab-msg");
    await page.screenshot({ path: join(SHOTS, "01-investigate.png") });
  });

  await step("Submit a message; token dialog accepts the operator token", async () => {
    await page.click("#tab-msg");
    await page.type("#panel-msg textarea", MESSAGE);
    await page.click("button[type=submit]");
    await page.waitForSelector('dialog[open] input[placeholder="Paste the operator token"]', { timeout: 10000 });
    await page.type('dialog[open] input[placeholder="Paste the operator token"]', TOKEN);
    await page.click("::-p-text(Use token)");
    await page.waitForFunction(() => location.hash.startsWith("#/r/"), { timeout: 20000 });
    reportId = decodeURIComponent((await page.evaluate(() => location.hash)).slice(4));
    return `report ${reportId}`;
  });

  await step("Analysis completes with a verdict, findings and an AI explanation panel", async () => {
    await page.waitForSelector("#verdict-h", { timeout: 20000 });
    const cls = await waitForText(page, "#verdict-h", /High Risk|Suspicious|Confirmed Malicious|Low Risk|Inconclusive/, 150000);
    await page.waitForSelector("#findings", { timeout: 10000 });
    // Wait for the AI panel to settle (ok / rejected / unavailable), up to 2 minutes for the local model.
    await page.waitForFunction(() => !/Generating|Waiting for the AI/i.test(document.querySelector("#why")?.textContent || ""), { timeout: 120000 }).catch(() => {});
    await page.screenshot({ path: join(SHOTS, "02-report-verdict.png") });
    await page.screenshot({ path: join(SHOTS, "03-report-full.png"), fullPage: true });
    if (cls !== "High Risk") throw new Error(`expected High Risk for the KYC phish, got ${cls}`);
    return cls;
  });

  await step("Register the commitment on-chain from the dashboard", async () => {
    await page.$eval("#registry", (el) => el.scrollIntoView());
    await page.type('#registry input[placeholder="e.g. SOC analyst on duty"]', "e2e analyst");
    await page.click("::-p-text(Register commitment on-chain)");
    await page.waitForSelector("::-p-text(Verify integrity (app))", { timeout: 60000 });
    return "registered";
  });

  await step("App-side verification reports a match on revision 0", async () => {
    await page.click("::-p-text(Verify integrity (app))");
    await waitForText(page, ".verify-result", /Match: .*revision 0 \(latest\)/, 20000);
    const reg = await page.$("#registry");
    await reg.screenshot({ path: join(SHOTS, "04-registry-verified.png") });
  });

  let envelope1;
  await step("Download the envelope; independent verifier says MATCH (exit 0)", async () => {
    await page.click("::-p-text(Download report for independent verification)");
    envelope1 = join(DL, "revision0.envelope");
    renameSync(await waitForDownload(DL, 0), envelope1); // keep it; the next download reuses the file name
    const r = verifier(envelope1);
    if (r.status !== 0) throw new Error(`verifier exit ${r.status}: ${r.stdout}${r.stderr}`);
    return r.stdout.trim().split("\n").find((l) => /MATCH/.test(l)) || "exit 0";
  });

  await step("Tampered copy (classification edited) is NO MATCH (exit 1)", async () => {
    const env = JSON.parse(readFileSync(envelope1, "utf8"));
    const tampered = join(DL, "tampered.json");
    const s = JSON.stringify(env).replace(/"High Risk"/g, '"Low Risk"');
    if (s === JSON.stringify(env)) throw new Error("could not find the classification to tamper with");
    writeFileSync(tampered, s);
    const r = verifier(tampered);
    if (r.status !== 1) throw new Error(`expected exit 1, got ${r.status}: ${r.stdout}`);
    return "exit 1";
  });

  await step("Publish revision 1 from the dashboard", async () => {
    await page.click("::-p-text(Publish revision)");
    await page.type(".revise-form textarea", "e2e: re-reviewed by analyst");
    await page.click(".revise-form button[type=submit]");
    await page.waitForFunction(() => /Revision 1latest/.test(document.querySelector("#registry")?.textContent || ""), { timeout: 60000 });
    await page.click("::-p-text(Verify integrity (app))");
    await waitForText(page, ".verify-result", /Match: .*revision 1 \(latest\)/, 20000);
    const reg = await page.$("#registry");
    await reg.screenshot({ path: join(SHOTS, "05-registry-revised.png") });
  });

  await step("Old envelope now verifies as superseded (exit 2); new download is MATCH", async () => {
    const old = verifier(envelope1);
    if (old.status !== 2) throw new Error(`expected exit 2 for revision 0, got ${old.status}: ${old.stdout}`);
    await page.click("::-p-text(Download report for independent verification)");
    const envelope2 = await waitForDownload(DL, 0);
    const r = verifier(envelope2);
    if (r.status !== 0) throw new Error(`verifier exit ${r.status}: ${r.stdout}`);
    return "revision 0 → exit 2, revision 1 → exit 0";
  });

  await step("Reviewer records 'Disputed' with a note; on-chain status updates; independent verifier reads it", async () => {
    await page.$eval(".review-box", (el) => el.scrollIntoView());
    await page.click(".review-choice:nth-child(2)"); // Disputed
    await page.type(".review-form textarea", "e2e: second analyst disputes the severity");
    await page.click(".review-form button[type=submit]");
    await waitForText(page, ".review-box h3", /Disputed/, 60000);
    await (await page.$("#registry")).screenshot({ path: join(SHOTS, "05b-registry-reviewed.png") });
    await page.click("::-p-text(Download report for independent verification)");
    const env = join(DL, "reviewed.envelope");
    renameSync(await waitForDownload(DL, 0), env);
    const r = verifier(env);
    if (r.status !== 0 || !/Disputed/.test(r.stdout)) throw new Error(`verifier exit ${r.status}: ${r.stdout}`);
    return (r.stdout.match(/.*Disputed.*/) || [""])[0].trim();
  });

  await step("History and Incidents pages render", async () => {
    await page.goto(`${BASE}/#/history`, { waitUntil: "networkidle0" });
    await page.waitForFunction((id) => document.body.innerText.length > 200, {}, reportId);
    await page.screenshot({ path: join(SHOTS, "06-history.png") });
    await page.goto(`${BASE}/#/incidents`, { waitUntil: "networkidle0" });
    await new Promise((r) => setTimeout(r, 1500));
    await page.screenshot({ path: join(SHOTS, "07-incidents.png") });
  });

  await step("QR tab decodes a payment QR locally and flags a 'scan to receive refund' UPI code", async () => {
    await page.goto(`${BASE}/#/`, { waitUntil: "networkidle0" });
    await page.click("#tab-qr");
    const input = await page.waitForSelector('#panel-qr input[type=file]');
    await input.uploadFile(join(ROOT, "e2e/fixtures/upi-refund-qr.png")); // synthetic fixture
    await waitForText(page, ".qr-decoded", /UPI payment request/, 10000);
    await page.click("button[type=submit]");
    await page.waitForFunction(() => location.hash.startsWith("#/r/"), { timeout: 20000 });
    const cls = await waitForText(page, "#verdict-h", /High Risk|Suspicious|Low Risk|Inconclusive|Confirmed Malicious/, 150000);
    await page.waitForSelector("::-p-text(UPI payment request)", { timeout: 10000 });
    await page.screenshot({ path: join(SHOTS, "11-qr-upi-report.png") });
    if (cls !== "High Risk") throw new Error(`expected High Risk, got ${cls}`);
    return cls;
  });

  await step("No uncaught page errors", async () => {
    const real = consoleErrors.filter((e) => !/Failed to load resource/.test(e)); // HTTP failures are checked below with their URL
    if (real.length || badResponses.length) throw new Error([...real, ...badResponses].join("\n"));
  });
} finally {
  await browser.close();
}
process.exit(summary("dashboard", { report: reportId, screenshots: SHOTS }));

async function waitForDownload(dir, already) {
  for (let i = 0; i < 100; i++) {
    const files = readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "tampered.json" && !f.endsWith(".crdownload"));
    if (files.length > already) {
      const sorted = files.map((f) => join(dir, f)).sort((a, b) => statMtime(a) - statMtime(b));
      return sorted[sorted.length - 1];
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("download did not arrive");
}
function statMtime(p) {
  return statSync(p).mtimeMs;
}
