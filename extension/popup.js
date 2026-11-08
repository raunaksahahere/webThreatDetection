import { checkableUrl, defang, getReport, recentJobs, reportUrl, submitUrl } from "./common.js";

const $ = (id) => document.getElementById(id);
const CLASS = { "Low Risk": "low", Suspicious: "sus", "High Risk": "high", "Confirmed Malicious": "conf", Inconclusive: "inc" };

function showError(msg) {
  $("error").textContent = msg; // text only, never HTML
  $("error").hidden = false;
}

async function render(report) {
  const a = report.assessment;
  $("result").hidden = false;
  if (!a) {
    $("verdict").textContent = report.status === "failed" ? "Analysis failed" : "Investigating…";
    $("verdict").className = "verdict inc";
    return false;
  }
  $("verdict").textContent = a.classification;
  $("verdict").className = `verdict ${CLASS[a.classification] || "inc"}`;
  $("rule").textContent = `${a.rule_id}: ${a.rule_text}`;
  const ul = $("findings");
  ul.replaceChildren();
  for (const f of report.findings.filter((f) => !f.code.startsWith("web.") && f.severity !== "info").slice(0, 4)) {
    const li = document.createElement("li");
    li.textContent = `${f.severity.toUpperCase()}: ${f.title}`;
    ul.append(li);
  }
  $("open").href = await reportUrl(report.id);
  return true;
}

async function poll(id) {
  for (let i = 0; i < 80; i++) {
    try {
      const rep = await getReport(id);
      if (await render(rep)) return;
      if (rep.status === "failed" || rep.status === "interrupted") return;
    } catch (e) {
      showError(String(e.message || e));
      return;
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
}

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); // URL readable via activeTab after the user clicks the icon
  const url = checkableUrl(tab?.url || "");
  $("target").textContent = url ? defang(url) : "This page cannot be checked (only http/https pages).";
  $("check").disabled = !url;
  $("check").addEventListener("click", async () => {
    $("error").hidden = true;
    $("check").disabled = true;
    try {
      const id = await submitUrl(url);
      $("result").hidden = false;
      $("verdict").textContent = "Investigating…";
      await poll(id);
    } catch (e) {
      showError(String(e.message || e));
    } finally {
      $("check").disabled = false;
    }
  });
  // Resume the latest job for this page if the popup was closed mid-analysis.
  const jobs = await recentJobs();
  const last = jobs.find((j) => j.url === url && Date.now() - j.at < 15 * 60 * 1000);
  if (last) poll(last.id);
  for (const j of jobs) {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.textContent = defang(j.url).slice(0, 70);
    a.href = await reportUrl(j.id);
    a.target = "_blank";
    a.rel = "noopener";
    li.append(a);
    $("recent").append(li);
  }
  chrome.action.setBadgeText({ text: "" });
}

main().catch((e) => showError(String(e.message || e)));
