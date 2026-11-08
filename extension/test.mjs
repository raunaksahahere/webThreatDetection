// Pure-function tests for the extension (chrome API stubbed; no browser).
const area = () => ({ _d: {}, async get(k) { return typeof k === "string" ? { [k]: this._d[k] } : { ...k, ...this._d }; }, async set(o) { Object.assign(this._d, o); } });
globalThis.chrome = { storage: { local: area(), session: area() } };
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
// Token mode: the server answers 401 without a token → the user is told to set it.
const sent = [];
globalThis.fetch = async (url, opts) => { sent.push(opts.headers); return { status: 401, ok: false, json: async () => ({}) }; };
try { await m.submitUrl("https://example.com/"); fail++; console.log("FAIL no-token should throw"); } catch (e) { if (!/set the operator token/i.test(e.message)) { fail++; console.log("FAIL msg", e.message); } }
// Public demo: no token needed; no X-WTD-Token header is sent, a stable per-session id is.
globalThis.fetch = async (url, opts) => { sent.push(opts.headers); return { status: 202, ok: true, json: async () => ({ id: "0b6c8f3e-1d2a-4c5b-9e8f-7a6b5c4d3e2f", status: "queued" }) }; };
const id = await m.submitUrl("https://example.com/");
if (id !== "0b6c8f3e-1d2a-4c5b-9e8f-7a6b5c4d3e2f") { fail++; console.log("FAIL public submit", id); }
if (sent.some((h) => "X-WTD-Token" in h)) { fail++; console.log("FAIL token header sent without a token"); }
if (!/^[0-9a-f-]{36}$/.test(sent[0]["X-WTD-Session"] || "") || sent[0]["X-WTD-Session"] !== sent[1]["X-WTD-Session"]) { fail++; console.log("FAIL session id", sent); }
// 429 from the demo quota surfaces the server's explanation.
globalThis.fetch = async () => ({ status: 429, ok: false, json: async () => ({ detail: "This public demo allows 15 analyses per browser session" }) });
try { await m.submitUrl("https://example.com/"); fail++; console.log("FAIL 429 should throw"); } catch (e) { if (!/per browser session/.test(e.message)) { fail++; console.log("FAIL 429 msg", e.message); } }
console.log(fail ? `${fail} failure(s)` : "extension pure-function tests: all passed");
process.exit(fail ? 1 : 0);
