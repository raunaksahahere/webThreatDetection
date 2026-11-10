"""Reproducible evaluation of WTD's message analysis on public labelled SMS data. See docs/EVALUATION_MESSAGES.md.

Usage (from the repository root):
  backend/.venv/bin/python scripts/eval_messages.py --download          # fetch + verify the pinned datasets into data/eval-cache/, run, write docs
  backend/.venv/bin/python scripts/eval_messages.py --download --ai 36  # also assess AI explanations on 36 holdout messages (needs a provider)

The datasets are downloaded from their publishers, checked against the SHA-256 recorded in backend/wtd/evaluation.py, and are not
committed. Nothing is fetched or looked up for the messages themselves, and no rule is changed by this script.
Writes docs/evaluation-messages.json and docs/EVALUATION_MESSAGES.md.
"""
from __future__ import annotations

import argparse
import io
import json
import platform
import random
import subprocess
import sys
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from wtd import evaluation as ev  # noqa: E402

CACHE = ROOT / "data" / "eval-cache"
UA = "WTD-eval/0.2 (research; non-commercial)"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def ensure_data(download: bool) -> tuple[Path, Path]:
    CACHE.mkdir(parents=True, exist_ok=True)
    ss = CACHE / ev.SCAMSHIELD["file"]
    uci = CACHE / ev.UCI["file"]
    if download:
        if not ss.exists():
            ss.write_bytes(fetch(ev.SCAMSHIELD["download"]))
        if not uci.exists():
            raw = fetch(ev.UCI["download"])
            import hashlib
            if hashlib.sha256(raw).hexdigest() != ev.UCI["zip_sha256"]:
                sys.exit("UCI archive checksum differs from the recorded one; refusing to continue")
            uci.write_bytes(zipfile.ZipFile(io.BytesIO(raw)).read(ev.UCI["file"]))
    for p, want, name in ((ss, ev.SCAMSHIELD["sha256"], "ScamShield-IN"), (uci, ev.UCI["sha256"], "UCI SMS Spam Collection")):
        if not p.exists():
            sys.exit(f"{p} is missing; run with --download")
        got = ev.file_sha256(p)
        if got != want:
            sys.exit(f"{name} checksum mismatch: {got} != {want}")
    return ss, uci


def git_dirty() -> bool:
    try:
        out = subprocess.run(["git", "status", "--porcelain", "--", "backend", "frontend", "scripts", "contracts", "verifier", "extension"],
                             cwd=ROOT, capture_output=True, text=True, check=True).stdout
        return bool(out.strip())
    except Exception:
        return True


def git_head() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return "unknown"


def ai_sample(rows: list[ev.Row], n: int) -> list[ev.Row]:
    """Stratified, seeded sample of the holdout: a third scams, a third ScamShield legit, a third UCI ham."""
    rng = random.Random(7)
    out = []
    for stratum in (ev.POSITIVE, "legit_scamshield", "legit_uci_ham"):
        pool = [r for r in rows if r.stratum == stratum and r.split == "holdout"]
        out += rng.sample(pool, min(len(pool), n // 3))
    return out


def ai_grounding(rows: list[ev.Row]) -> dict:
    """Run the production explanation path (provider order and validator unchanged) and re-check its output independently."""
    from wtd.ai import explain
    from wtd.models import Report, iso

    results = []
    for i, row in enumerate(rows, 1):
        findings, assessment, _urls, facts, _ms = ev._assess(row.text)
        rep = Report(id=f"eval-{i}", kind="message", status="complete", created_at=iso(), input_display=ev.norm(row.text)[:160],
                     input_sha256=row.sha, subject={"redacted_text": facts["redacted_text"]}, findings=findings, assessment=assessment)
        t0 = time.monotonic()
        res = explain.explain_report(rep)
        d = res.model_dump()
        entry = {"stratum": row.stratum, "sha256": row.sha, "classification": assessment.classification, "ai_status": d["status"],
                 "provider": d.get("provider"), "model": d.get("model"), "latency_ms": int((time.monotonic() - t0) * 1000),
                 "validation_notes": d.get("validation_notes", []), "error": (d.get("error") or "")[:300] or None}
        if d["status"] in ("ok", "rejected"):
            entry["checks"] = ev.ai_checks(d, facts["redacted_text"], " ".join(f"{f.title} {f.observed}" for f in findings))
        results.append(entry)
        print(f"  AI {i}/{len(rows)} {row.stratum}: {d['status']} ({entry['latency_ms']} ms)", flush=True)
    done = [r for r in results if r["ai_status"] in ("ok", "rejected")]
    notes = [n for r in done for n in r["validation_notes"]]
    count = lambda word: sum(1 for r in done if any(word in n for n in r["validation_notes"]))
    obs = sum(r["checks"]["observations"] for r in done)
    return {
        "provider_note": "Assessed with the provider(s) configured when this ran (see 'providers'); results do not transfer to other models.",
        "providers": sorted({f"{r['provider']} / {r['model']}" for r in done}), "sample": len(results),
        "status_counts": {s: sum(1 for r in results if r["ai_status"] == s) for s in sorted({r["ai_status"] for r in results})},
        "median_latency_ms": sorted(r["latency_ms"] for r in results)[len(results) // 2] if results else None,
        "unavailable_reasons": sorted({(r.get("error") or "no detail")[:160] for r in results if r["ai_status"] not in ("ok", "rejected")}),
        "responses_scored": len(done),
        "validator_flagged": {
            "output_used_unknown_finding_ids": count("dropped unknown finding id"),
            "quote_not_verbatim_in_message": count("quote not found verbatim"),
            "asserted_a_different_classification": count("asserted a different classification"),
            "called_target_safe_when_not_low_risk": count("called the target safe"),
            "no_grounded_points": count("no grounded points"),
            "rejected_overall": sum(1 for r in done if r["ai_status"] == "rejected"),
        },
        "independent_recheck": {
            "observations_with_quote_not_in_message": sum(r["checks"]["unverified_quotes"] for r in done), "observations_total": obs,
            "responses_with_numbers_not_in_inputs": sum(1 for r in done if r["checks"]["unsupported_numbers"]),
            "responses_with_domains_not_in_inputs": sum(1 for r in done if r["checks"]["unsupported_domains"]),
        },
        "note": "The classifier result is deterministic and is passed to the model as fixed input; none of these figures describe detection accuracy.",
        "per_message": results,
    }


def annotate_ai(ai: dict, rows: list[ev.Row]) -> None:
    """Add how many findings each sampled message actually gave the model (recomputed deterministically from the message), so that
    'no grounded points' can be read correctly: with nothing to cite it is expected, with findings available it is a weak explanation."""
    by_sha = {r.sha: r for r in rows}
    for e in ai["per_message"]:
        row = by_sha.get(e["sha256"])
        if row is not None:
            e["findings_given"] = len(ev._assess(row.text)[0])
    done = [e for e in ai["per_message"] if e["ai_status"] in ("ok", "rejected")]
    none = lambda e: any("no grounded points" in n for n in e["validation_notes"])
    ai["no_grounded_points_breakdown"] = {
        "messages_with_zero_findings_given_to_the_model": sum(1 for e in done if e.get("findings_given") == 0),
        "no_grounded_points_when_there_were_no_findings_to_cite": sum(1 for e in done if none(e) and e.get("findings_given") == 0),
        "no_grounded_points_although_findings_were_available": sum(1 for e in done if none(e) and (e.get("findings_given") or 0) > 0),
        "messages_with_findings_given_to_the_model": sum(1 for e in done if (e.get("findings_given") or 0) > 0),
        "unknown_finding_ids_cited_among_messages_with_findings": sum(1 for e in done if (e.get("findings_given") or 0) > 0
                                                                       and any("dropped unknown finding id" in n for n in e["validation_notes"])),
    }


def pct(r: dict) -> str:
    if r["n"] == 0:
        return "n/a"
    lo, hi = r["ci95_pct"]
    return f"{r['k']}/{r['n']} = {r['pct']}% (95% CI {lo}–{hi}%)"


def render(doc: dict) -> str:
    S, cfg, o = doc["summary"], doc["config"], doc["observations"]
    h, d = S["holdout"], S["dev"]
    c = h["confusion"]
    L = ["# Message-analysis evaluation", "",
         f"Generated by `scripts/eval_messages.py` on {cfg['run_at']} (code from WTD commit `{cfg['wtd_commit'][:10]}`{', with uncommitted changes' if cfg['wtd_tree_dirty'] else ''}). Machine-readable results: "
         "[`evaluation-messages.json`](evaluation-messages.json) (every flagged legitimate message and every missed scam is listed there).", "",
         "**What this measures: the deterministic message rules plus the static URL rules for links in the message, classified by the production "
         "classifier. It is not the full system and not production accuracy.** No link is fetched, no threat-intelligence source or DNS is queried, "
         "no stored report is correlated and no AI is involved in these numbers. No rule was changed because of these results.", "",
         "## Data", "",
         "| Dataset | Version | Licence | Used for |", "|---|---|---|---|",
         f"| [{ev.SCAMSHIELD['name']}]({ev.SCAMSHIELD['url']}) | revision `{ev.SCAMSHIELD['revision'][:10]}`, file SHA-256 `{ev.SCAMSHIELD['sha256'][:16]}…` | {ev.SCAMSHIELD['licence']} | scam positives and legitimate negatives |",
         f"| [{ev.UCI['name']}]({ev.UCI['url']}) (DOI {ev.UCI['doi']}) | file SHA-256 `{ev.UCI['sha256'][:16]}…` | {ev.UCI['licence']} | a large set of ordinary legitimate messages |", "",
         f"Citation for the UCI corpus: {ev.UCI['citation']}. The datasets are downloaded from their publishers, verified against these checksums and not committed.", "",
         "### Labels and how they map", "", "| Stratum | Rows (after cleaning) | Meaning |", "|---|---|---|"]
    for s in [ev.POSITIVE] + ev.NEGATIVES + ev.INFORMATIONAL:
        L.append(f"| `{s}` | {doc['strata_counts'].get(s, 0)} | {ev.STRATUM_NOTE[s]} |")
    b = doc["build"]
    L += ["", f"Of {b['scamshield_labelled']} labelled ScamShield-IN rows (the file has {doc['scamshield_rows_total']} rows; the rest are unlabelled chat-style data and are unused) "
          f"and {b['uci']} UCI rows: {b['uci_removed_overlap_with_scamshield']} UCI rows removed because they also occur in ScamShield-IN, "
          f"{b['exact_duplicates_removed']} exact duplicates removed (after lower-casing and whitespace normalisation), {b['conflicting_labels_removed']} messages with contradictory labels removed; "
          f"{b['final_rows']} messages remain.", "",
          "**Positive class** = `scam_specific`. **Flagged** = Suspicious, High Risk or Confirmed Malicious; Low Risk = not flagged; Inconclusive = abstention (always 0 here, see above). "
          "`ambiguous_promo` and `uci_spam` are shown for information only because 'unsolicited promotion' and 'spam' are not the same label as 'scam'.", "",
          "### Splits", "", "Each message goes to a development or holdout split by the first byte of the SHA-256 of its normalised text (below 77 of 256: development, about 30%; the rest: holdout). "
          "The headline numbers below are the **holdout**. Nothing was tuned in this work, so the split is a safeguard for future rule changes: tune on development, report holdout.", "",
          "## Results (holdout)", "",
          f"Positives (scams): {c['tp'] + c['fn']}. Negatives (legitimate): {c['fp'] + c['tn']}.", "",
          "| | Predicted flagged | Predicted not flagged |", "|---|---|---|",
          f"| **Actual scam** | TP {c['tp']} | FN {c['fn']} |", f"| **Actual legitimate** | FP {c['fp']} | TN {c['tn']} |", "",
          f"- Recall on scams: {pct(c['recall'])}",
          f"- False-positive rate on legitimate messages: {pct(c['false_positive_rate'])}",
          f"- Precision on this mixture: {pct(c['precision_on_this_mixture'])}. **This depends on the ratio of scams to legitimate messages in the data (about 1:{round((c['fp'] + c['tn']) / max(1, c['tp'] + c['fn']))} here) and is not a deployment figure.**",
          f"- Abstentions (Inconclusive): {pct(c['abstentions'])}", ""]
    cs = h["confusion_scamshield_only"]
    L += [f"Against ScamShield-IN negatives only (so the large UCI set does not dominate): TP {cs['tp']}, FN {cs['fn']}, FP {cs['fp']}, TN {cs['tn']}; "
          f"recall {pct(cs['recall'])}; false-positive rate {pct(cs['false_positive_rate'])}; precision {pct(cs['precision_on_this_mixture'])}.", "",
          "### Per stratum (holdout)", "", "| Stratum | n | Low Risk | Suspicious | High Risk | Confirmed | Flagged | High or worse |", "|---|---|---|---|---|---|---|---|"]
    for s in [ev.POSITIVE] + ev.NEGATIVES + ev.INFORMATIONAL:
        x = h["strata"][s]
        bc = x["by_classification"]
        L.append(f"| `{s}` | {x['n']} | {bc['Low Risk']} | {bc['Suspicious']} | {bc['High Risk']} | {bc['Confirmed Malicious']} | {pct(x['flagged'])} | {x['high_or_confirmed']['k']} |")
    L += ["", "### Recall by fraud type (holdout)", "", "| Fraud type | Flagged |", "|---|---|"]
    for t, r in h["recall_by_fraud_type"].items():
        L.append(f"| {t} | {pct(r)} |")
    dc = d["confusion"]
    L += ["", "### Development split (for comparison)", "",
          f"TP {dc['tp']}, FN {dc['fn']}, FP {dc['fp']}, TN {dc['tn']}; recall {pct(dc['recall'])}; false-positive rate {pct(dc['false_positive_rate'])}.", "",
          "### Latency", "", f"Offline path, {S['latency_ms']['n']} messages on {cfg['machine']}: median {S['latency_ms']['median']} ms, 95th percentile {S['latency_ms']['p95']} ms, max {S['latency_ms']['max']} ms. "
          "This excludes network lookups, which dominate the real pipeline.", "",
          "### Where it goes wrong (all splits)", "",
          f"- **Flagged legitimate messages ({o['flagged_legitimate']}).** {o['flagged_legitimate_firing_payment_request']} fire the payment-request rule (bill reminders and promotions that say 'pay Rs…'), "
          f"{o['flagged_legitimate_firing_reward']} the reward rule, and {o['flagged_legitimate_from_url_rules_only']} are flagged by the URL rules alone. Rules that fired: {json.dumps(S['rules_firing_on_false_positives'])}. "
          f"{o['flagged_legitimate_high_or_worse']} reached High Risk or worse. Not fixed here: this is an evaluation.",
          f"- **Missed scams ({o['missed_scams']} of {o['positives']}).** By type: {json.dumps(S['rules_missing_on_false_negatives'])}. "
          f"{o['missed_with_romanised_hindi_words']} of the misses contain Romanised-Hindi words (a crude word-list match; {o['positives_with_romanised_hindi_words']} of all {o['positives']} positives do), "
          "and the message rules are written for English. Investment pitches are the largest group of misses.",
          "- Every flagged legitimate message and every missed scam is listed in the JSON file (identifiers, hashes and 90-character snippets).", ""]
    if doc.get("ai"):
        a = doc["ai"]
        rc = a.get("run_config") or {}
        L += ["## AI explanation grounding (separate from the classifier)", "",
              f"Run {rc.get('run_at', '?')} with code from commit `{str(rc.get('wtd_commit', '?'))[:10]}`{' plus uncommitted changes' if rc.get('wtd_tree_dirty') else ''}. "
              f"{a['provider_note']} Providers used: {', '.join(a['providers']) or 'none responded'}. Sample: {a['sample']} holdout messages (a third each from the three headline strata); "
              f"status counts {a['status_counts']}; median latency {a['median_latency_ms']} ms."
              + (f" Reasons a response was not scored: {'; '.join(a['unavailable_reasons'])}." if a['unavailable_reasons'] else ""), "",
              f"Of {a['responses_scored']} responses that were scored, the production validator flagged:", ""]
        for k, v in a["validator_flagged"].items():
            L.append(f"- {k.replace('_', ' ')}: {v}")
        nb = a.get("no_grounded_points_breakdown")
        if nb:
            L += ["", f"'No grounded points' needs context: {nb['messages_with_zero_findings_given_to_the_model']} of the scored messages produced no findings at all, so there was nothing to cite "
                  f"({nb['no_grounded_points_when_there_were_no_findings_to_cite']} of the 'no grounded points' notes are in that case). Among the {nb['messages_with_findings_given_to_the_model']} messages that did have findings, "
                  f"{nb['no_grounded_points_although_findings_were_available']} explanation(s) cited none of them, and {nb['unknown_finding_ids_cited_among_messages_with_findings']} cited at least one finding id that does not exist "
                  "(the validator drops such citations, so no invented id reaches the report). With so few messages that had findings, treat that proportion as indicative only."]
        ir = a["independent_recheck"]
        L += ["", f"Independent re-check (not the production validator's code): {ir['observations_with_quote_not_in_message']} of {ir['observations_total']} observation quotes were not in the message; "
              f"{ir['responses_with_numbers_not_in_inputs']} responses contained a number and {ir['responses_with_domains_not_in_inputs']} a domain that appears in neither the message nor the findings given to the model.", "",
              a["note"], ""]
    else:
        L += ["## AI explanation grounding", "", "Not run in this report. Run with `--ai N` and a configured provider.", ""]
    L += ["## Limitations", "",
          "- **Small positive class.** The positives are a few dozen messages; every rate above carries the confidence interval shown, and the intervals are wide.",
          "- **The positives look synthetic.** The specific-fraud rows in ScamShield-IN read as templated, generated messages (for example brand + fee + link), unlike the real, noisy promotional rows in the same file. A rule set written around such patterns finds them easily, so recall here is likely optimistic for real scams.",
          "- **Labels are the publishers' and were not independently re-checked.** `Generic Promo Fraud` is excluded precisely because it is not clearly fraud.",
          "- **Prevalence is artificial.** Real traffic is not 1:100 scams to legitimate messages; precision here must not be quoted as a deployment figure.",
          "- **The legitimate sets are dated and regional.** UCI ham is mostly 2000s English chat; ScamShield-IN legitimate rows include promotional spam. Modern bank, delivery and OTP notices are under-represented, so the false-positive rate for those is not measured here; the documented cases in `TESTING.md` cover a few.",
          "- **One layer only.** Linked pages, intelligence lookups and correlation are out of scope; they change real-world results in both directions.",
          "- **OpenRAIL licence.** ScamShield-IN carries use-based restrictions; read the dataset card before reuse. Only identifiers, hashes and 90-character snippets of misclassified rows are reproduced here.", "",
          "## Reproduce", "", "```bash", "backend/.venv/bin/python scripts/eval_messages.py --download", "```",
          "The checksums above must match; the script stops if they do not. Results are deterministic for the rule layer.", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--download", action="store_true", help="download the pinned datasets if they are not in data/eval-cache/")
    ap.add_argument("--ai", type=int, default=0, help="also assess AI explanations on this many holdout messages")
    ap.add_argument("--reuse-ai", default="", help="take the AI grounding block from an earlier evaluation-messages.json instead of rerunning the model")
    ap.add_argument("--out", default=str(ROOT / "docs"))
    args = ap.parse_args()
    ss_path, uci_path = ensure_data(args.download)
    ss_raw = json.loads(ss_path.read_text())
    rows, build_log = ev.build(ev.load_scamshield(ss_path), ev.load_uci(uci_path))
    print(f"{len(rows)} messages after cleaning; assessing…", flush=True)
    results = ev.run(rows)
    summary = ev.summarise(results)
    from collections import Counter
    doc = {"config": {"run_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "wtd_commit": git_head(), "wtd_tree_dirty": git_dirty(), "python": platform.python_version(),
                      "machine": f"{platform.system()} {platform.machine()}", "dev_share_threshold": ev.DEV_SHARE,
                      "flagged_classes": sorted(ev.FLAGGED), "evaluated": "message rules + static URL rules + production classifier; offline"},
           "datasets": {"scamshield_in": {k: ev.SCAMSHIELD[k] for k in ("name", "url", "revision", "sha256", "licence")},
                        "uci_sms_spam": {k: ev.UCI[k] for k in ("name", "url", "doi", "sha256", "licence", "citation")}},
           "scamshield_rows_total": len(ss_raw), "build": build_log, "strata_counts": dict(Counter(r.stratum for r in rows)),
           "split_counts": dict(Counter(r.split for r in rows)), "summary": summary, "observations": ev.observations(rows, results), "errors": ev.errors(results)}
    if args.reuse_ai:
        src = json.loads(Path(args.reuse_ai).read_text())
        doc["ai"] = src["ai"]
        doc["ai"].setdefault("run_config", {k: src["config"].get(k) for k in ("run_at", "wtd_commit", "wtd_tree_dirty")})
    elif args.ai:
        doc["ai"] = ai_grounding(ai_sample(rows, args.ai))
        doc["ai"]["run_config"] = {k: doc["config"][k] for k in ("run_at", "wtd_commit", "wtd_tree_dirty")}
    if doc.get("ai"):
        annotate_ai(doc["ai"], rows)
    out = Path(args.out)
    (out / "evaluation-messages.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    (out / "EVALUATION_MESSAGES.md").write_text(render(doc))
    c = summary["holdout"]["confusion"]
    print(f"holdout: TP {c['tp']} FN {c['fn']} FP {c['fp']} TN {c['tn']}  recall {c['recall']['pct']}%  FPR {c['false_positive_rate']['pct']}%")
    print(f"wrote {out / 'evaluation-messages.json'} and {out / 'EVALUATION_MESSAGES.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
