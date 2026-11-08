// Pure-function tests for the extension (chrome API stubbed; no browser).
globalThis.chrome = { storage: { local: { _d: {}, async get(k) { return typeof k === "string" ? { [k]: this._d[k] } : { ...k, ...this._d }; }, async set(o) { Object.assign(this._d, o); } } } };
const m = await import(new URL("./common.js", import.meta.url));
const cases = [
  ["https://example.com/a#frag", "https://example.com/a"], ["http://x.test/", "http://x.test/"], ["chrome://settings", null], ["file:///etc/passwd", null],
  ["javascript:alert(1)", null], ["about:blank", null], ["data:text/html,hi", null], ["not a url", null],
];
let fail = 0;
for (const [i, exp] of cases) { const got = m.checkableUrl(i); if (got !== exp) { fail++; console.log("FAIL checkableUrl", i, got); } }
if (m.defang("https://evil.example.com/x.y") !== "hxxps://evil[.]example[.]com/x.y") { fail++; console.log("FAIL defang", m.defang("https://evil.example.com/x.y")); }
await m.remember({ id: "a", url: "u1", at: 1 }); await m.remember({ id: "b", url: "u2", at: 2 }); await m.remember({ id: "a", url: "u1", at: 3 });
const jobs = await m.recentJobs(); if (jobs.length !== 2 || jobs[0].id !== "a") { fail++; console.log("FAIL remember", jobs); }
const s = await m.settings(); if (s.base !== "http://127.0.0.1:8000") { fail++; console.log("FAIL base", s); }
chrome.storage.local._d.base = "http://evil.example:8000"; if ((await m.settings()).base !== "http://127.0.0.1:8000") { fail++; console.log("FAIL base pin"); }
try { await m.submitUrl("https://example.com/"); fail++; console.log("FAIL no-token should throw"); } catch (e) { if (!/token/i.test(e.message)) { fail++; console.log("FAIL msg", e.message); } }
console.log(fail ? `${fail} failure(s)` : "extension pure-function tests: all passed");
process.exit(fail ? 1 : 0);
