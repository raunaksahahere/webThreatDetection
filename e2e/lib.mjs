// Shared helpers for the browser end-to-end checks. Uses an installed Chromium-family browser
// (Brave by default; override with WTD_BROWSER=/path/to/chrome) through puppeteer-core — no browser download.
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer-core";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const CANDIDATES = ["/usr/bin/brave-browser", "/usr/bin/brave-browser-stable", "/opt/brave.com/brave/brave",
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser", "/usr/bin/google-chrome", "/usr/bin/chromium"];

export function browserPath() {
  const p = process.env.WTD_BROWSER || CANDIDATES.find((c) => existsSync(c));
  if (!p) throw new Error("No Chromium-family browser found; set WTD_BROWSER");
  return p;
}

export async function launch({ extension } = {}) {
  const opts = {
    executablePath: browserPath(),
    headless: process.env.WTD_HEADFUL ? false : true,
    userDataDir: mkdtempSync(join(tmpdir(), "wtd-profile-")), // fresh, throwaway profile
    args: ["--no-first-run", "--no-default-browser-check", "--disable-sync", "--disable-features=BraveRewards,BraveWallet"],
  };
  if (extension) {
    opts.pipe = true;
    opts.enableExtensions = [extension];
  }
  return puppeteer.launch(opts);
}

const results = [];
export async function step(name, fn) {
  const t = Date.now();
  try {
    const detail = await fn();
    results.push({ name, ok: true, ms: Date.now() - t, detail: detail ?? "" });
    console.log(`  PASS  ${name}${detail ? ` — ${detail}` : ""}`);
  } catch (e) {
    results.push({ name, ok: false, ms: Date.now() - t, detail: String(e.message || e).split("\n")[0] });
    console.log(`  FAIL  ${name} — ${String(e.message || e)}`);
    throw e;
  }
}

export function summary(suite, extra = {}) {
  const ok = results.every((r) => r.ok);
  console.log(`\n${suite}: ${results.filter((r) => r.ok).length}/${results.length} steps passed (browser: ${browserPath()})`);
  console.log(JSON.stringify({ suite, ok, at: new Date().toISOString(), browser: browserPath(), ...extra, steps: results }));
  return ok ? 0 : 1;
}

export async function waitForText(page, selector, re, timeout = 30000) {
  await page.waitForFunction(
    (sel, src, flags) => new RegExp(src, flags).test(document.querySelector(sel)?.textContent || ""),
    { timeout, polling: 250 }, selector, re.source, re.flags);
  return page.$eval(selector, (el, src, flags) => (el.textContent.match(new RegExp(src, flags)) || [""])[0], re.source, re.flags);
}
