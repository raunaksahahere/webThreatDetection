"""Offline evaluation of the message-analysis layer on public labelled data. Measures; never tunes.

What is evaluated (and what is not):
- The deterministic message rules (`message.analyse.analyse_text`, plus the raw-e-mail checks when the text looks like an e-mail)
  and the static URL rules applied to links found in the message, classified by the production `classify()`.
- NOT evaluated here: fetching linked pages, TLS/DNS/RDAP, threat-intelligence lookups, correlation across reports, or AI.
  Those need the network or stored reports and would make the numbers depend on which sites are still online.
  AI explanations are assessed separately (`ai_grounding`), and never counted as classifier results.
- "Flagged" means Suspicious, High Risk or Confirmed Malicious. Low Risk is "not flagged". Inconclusive is an abstention and is
  reported separately; in this offline configuration the only essential check (message.rules) always completes, so no
  abstentions occur by construction. In the full pipeline an unavailable intelligence source can make a result Inconclusive.

`assess_message` mirrors the offline part of `message.analyse.analyse_message`; a test keeps the two in step.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from .checks import url_rules
from .classify import classify
from .message.analyse import analyse_text
from .message.email_checks import analyse_email, looks_like_email
from .models import CheckResult, CheckStatus, Finding, Module
from .netguard import UrlRejected, defang, parse_url

FLAGGED = {"Suspicious", "High Risk", "Confirmed Malicious"}
CLASSES = ["Low Risk", "Suspicious", "High Risk", "Confirmed Malicious", "Inconclusive"]
DEV_SHARE = 77  # first byte of SHA-256(normalised text) below this -> development split (30%); the rest is the untouched holdout

SCAMSHIELD = {
    "name": "ScamShield-IN", "url": "https://huggingface.co/datasets/haxrits/ScamShield-IN",
    "revision": "3009fb07af780f607e4c923ba6bda6b00d4672e8", "file": "sms_fraud_classification.json",
    "download": "https://huggingface.co/datasets/haxrits/ScamShield-IN/resolve/3009fb07af780f607e4c923ba6bda6b00d4672e8/sms_fraud_classification.json",
    "sha256": "cc714da9b73f11ee4433087b4b05fe43c502a0f7299898cb7956fa9c5f25cee9", "licence": "OpenRAIL (use-based restrictions; see the dataset card)",
}
UCI = {
    "name": "SMS Spam Collection v.1", "url": "https://archive.ics.uci.edu/dataset/228/sms+spam+collection", "doi": "10.24432/C5CC84",
    "file": "SMSSpamCollection", "download": "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
    "zip_sha256": "1587ea43e58e82b14ff1f5425c88e17f8496bfcdb67a583dbff9eefaf9963ce3",
    "sha256": "7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d", "licence": "CC BY 4.0",
    "citation": "Almeida, Gómez Hidalgo and Yamakami, 'Contributions to the Study of SMS Spam Filtering: New Collection and Results', ACM DocEng 2011",
}

# Strata. Only the first three enter the headline numbers; the other two are reported for information because their labels
# do not mean "scam".
POSITIVE = "scam_specific"
NEGATIVES = ["legit_scamshield", "legit_uci_ham"]
INFORMATIONAL = ["ambiguous_promo", "uci_spam"]
STRATUM_NOTE = {
    "scam_specific": "ScamShield-IN rows labelled fraud with a specific fraud type (KYC, OTP, UPI, lottery, job, loan, ...): the positive class",
    "legit_scamshield": "ScamShield-IN rows labelled legit: ordinary messages, bank/telecom notices and promotional spam without fraud markers",
    "legit_uci_ham": "UCI SMS Spam Collection ham: ordinary personal messages (2000s English SMS, mostly UK and Singapore)",
    "ambiguous_promo": "ScamShield-IN 'Generic Promo Fraud': unsolicited promotions its authors call 'low-confidence fraud-adjacent spam'; not clearly scams, so excluded from precision/recall",
    "uci_spam": "UCI spam: unsolicited commercial SMS (many premium-rate or prize offers); 'spam' is not the same label as 'scam', so excluded from recall",
}


@dataclass
class Row:
    dataset: str
    index: int
    stratum: str
    fraud_type: str | None
    text: str

    @property
    def sha(self) -> str:
        return hashlib.sha256(norm(self.text).encode()).hexdigest()

    @property
    def split(self) -> str:
        return "dev" if int(self.sha[:2], 16) < DEV_SHARE else "holdout"


def norm(t: str) -> str:
    return re.sub(r"\s+", " ", t.strip().lower())


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- data
def load_scamshield(path: Path) -> list[Row]:
    """Only rows with a fraud/legit label. The rest of the file (about 7,500 rows) is unlabelled instruction data and is not used."""
    out = []
    for i, r in enumerate(json.loads(path.read_text())):
        if not isinstance(r, dict) or r.get("label") not in ("fraud", "legit") or not isinstance(r.get("message"), str):
            continue
        if r["label"] == "legit":
            st = "legit_scamshield"
        elif r.get("fraud_type") == "Generic Promo Fraud":
            st = "ambiguous_promo"
        else:
            st = POSITIVE
        out.append(Row("ScamShield-IN", i, st, r.get("fraud_type"), r["message"]))
    return out


def load_uci(path: Path) -> list[Row]:
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        label, _, text = line.partition("\t")
        if label in ("ham", "spam") and text.strip():
            out.append(Row("UCI SMS Spam Collection", i, "legit_uci_ham" if label == "ham" else "uci_spam", None, text))
    return out


def build(scamshield: list[Row], uci: list[Row]) -> tuple[list[Row], dict]:
    """Deduplicate on normalised text, drop contradictory labels, and drop UCI rows that also occur in ScamShield-IN."""
    log = {"scamshield_labelled": len(scamshield), "uci": len(uci)}
    ss_keys = {norm(r.text) for r in scamshield}
    by: dict[str, list[Row]] = defaultdict(list)
    for r in scamshield + [u for u in uci if norm(u.text) not in ss_keys]:
        by[norm(r.text)].append(r)
    log["uci_removed_overlap_with_scamshield"] = sum(1 for u in uci if norm(u.text) in ss_keys)
    keep, conflicts, dups = [], 0, 0
    for rows in by.values():
        if len({r.stratum for r in rows}) > 1:
            conflicts += 1
            continue
        dups += len(rows) - 1
        keep.append(rows[0])
    log.update(conflicting_labels_removed=conflicts, exact_duplicates_removed=dups, final_rows=len(keep))
    return sorted(keep, key=lambda r: (r.dataset, r.index)), log


# --------------------------------------------------------------------------- assessment
def _assess(text: str):
    """(findings, assessment, extracted urls, facts, milliseconds) for one message, with no network access."""
    t0 = time.perf_counter()
    findings: list[Finding] = []
    if looks_like_email(text):
        ef, body, _facts, _items, hrefs = analyse_email(text)
        findings += ef
        text = body + ("\n" + "\n".join(dict.fromkeys(hrefs))[:4000] if hrefs else "")
    mf, _items, facts, urls = analyse_text(text)
    findings += mf
    for i, u in enumerate(urls):
        for f in url_rules.analyse_url(parse_url(u))[0]:
            if f.severity == "info" and f.code != "url.official_domain":
                continue
            f.id = f"link{i + 1}.{f.id}"
            findings.append(f)
    checks = [CheckResult(name="message.rules", module=Module.message, status=CheckStatus.succeeded, essential=True)]
    return findings, classify(findings, checks), urls, facts, (time.perf_counter() - t0) * 1000


def assess_message(text: str) -> dict:
    """Classify one message offline, the way the production pipeline does before any network lookup."""
    findings, a, urls, _facts, ms = _assess(text)
    return {"classification": a.classification, "rule": a.rule_id, "codes": sorted({f.code for f in findings if f.severity != "info"}),
            "links": len(urls), "ms": round(ms, 2)}


def run(rows: list[Row]) -> list[dict]:
    out = []
    for r in rows:
        try:
            res = assess_message(r.text)
        except UrlRejected as e:  # a malformed link must not abort the run; it is recorded
            res = {"classification": "error", "rule": "", "codes": [], "links": 0, "ms": 0.0, "error": str(e)[:80]}
        out.append({"dataset": r.dataset, "index": r.index, "stratum": r.stratum, "fraud_type": r.fraud_type, "split": r.split, "sha256": r.sha,
                    "snippet": r.text[:90].replace("\n", " "), **res})
    return out


# --------------------------------------------------------------------------- statistics
def wilson(k: int, n: int, z: float = 1.96) -> list[float | None]:
    """95% Wilson score interval for a proportion, as percentages with one decimal."""
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(100 * max(0.0, (c - m) / d), 1), round(100 * min(1.0, (c + m) / d), 1)]


def rate(k: int, n: int) -> dict:
    return {"k": k, "n": n, "pct": round(100 * k / n, 1) if n else None, "ci95_pct": wilson(k, n)}


def stratum_summary(rs: list[dict]) -> dict:
    c = Counter(r["classification"] for r in rs)
    flagged = sum(c[x] for x in FLAGGED)
    return {"n": len(rs), "by_classification": {k: c.get(k, 0) for k in CLASSES}, "flagged": rate(flagged, len(rs)),
            "high_or_confirmed": rate(c["High Risk"] + c["Confirmed Malicious"], len(rs)), "inconclusive": rate(c["Inconclusive"], len(rs))}


def confusion(rs: list[dict]) -> dict:
    pos = [r for r in rs if r["stratum"] == POSITIVE]
    neg = [r for r in rs if r["stratum"] in NEGATIVES]
    tp = sum(r["classification"] in FLAGGED for r in pos)
    fn = len(pos) - tp
    fp = sum(r["classification"] in FLAGGED for r in neg)
    tn = len(neg) - fp
    abst = sum(r["classification"] == "Inconclusive" for r in pos + neg)
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "recall": rate(tp, tp + fn), "false_positive_rate": rate(fp, fp + tn),
            "precision_on_this_mixture": rate(tp, tp + fp), "abstentions": rate(abst, len(pos) + len(neg))}


def summarise(results: list[dict]) -> dict:
    out: dict = {}
    for name, rs in (("holdout", [r for r in results if r["split"] == "holdout"]), ("dev", [r for r in results if r["split"] == "dev"]),
                     ("all", results)):
        block = {"n": len(rs), "strata": {s: stratum_summary([r for r in rs if r["stratum"] == s]) for s in [POSITIVE] + NEGATIVES + INFORMATIONAL},
                 "confusion": confusion(rs)}
        # precision against ScamShield negatives only, so it is not dominated by the (much larger) UCI ham set
        ss = [r for r in rs if r["stratum"] in (POSITIVE, "legit_scamshield")]
        block["confusion_scamshield_only"] = confusion(ss)
        pos = [r for r in rs if r["stratum"] == POSITIVE]
        block["recall_by_fraud_type"] = {t: rate(sum(r["classification"] in FLAGGED for r in pos if r["fraud_type"] == t), sum(1 for r in pos if r["fraud_type"] == t))
                                         for t in sorted({r["fraud_type"] for r in pos})}
        out[name] = block
    ms = [r["ms"] for r in results if r.get("ms")]
    out["latency_ms"] = {"n": len(ms), "median": round(statistics.median(ms), 2) if ms else None,
                         "p95": round(sorted(ms)[int(0.95 * (len(ms) - 1))], 2) if ms else None, "max": max(ms) if ms else None}
    out["rules_firing_on_false_positives"] = dict(Counter(c for r in results if r["stratum"] in NEGATIVES and r["classification"] in FLAGGED for c in r["codes"]).most_common(12))
    out["rules_missing_on_false_negatives"] = dict(Counter(r["fraud_type"] for r in results if r["stratum"] == POSITIVE and r["classification"] not in FLAGGED).most_common())
    return out


def errors(results: list[dict]) -> dict:
    """Every flagged legitimate message and every missed scam, so nothing is hidden behind an aggregate."""
    keep = ("dataset", "index", "split", "sha256", "classification", "rule", "codes", "snippet", "fraud_type", "stratum")
    return {"false_positives": [{k: r[k] for k in keep} for r in results if r["stratum"] in NEGATIVES and r["classification"] in FLAGGED],
            "missed_scams": [{k: r[k] for k in keep} for r in results if r["stratum"] == POSITIVE and r["classification"] not in FLAGGED]}


ROMANISED_HINDI_RX = re.compile(r"\b(aap|aapka|aapko|aapki|karein|karo|kar dijiye|hai|hain|ke saath|turant|abhi|mil sakta|raha hai|kijiye|batayein|bhej|kamayein)\b", re.I)


def observations(rows: list[Row], results: list[dict]) -> dict:
    """Counts behind the written discussion, computed so the prose cannot drift from the data.
    The Romanised-Hindi figure is a crude word-list match (the message rules are English), not a language detector."""
    text = {(r.dataset, r.index): r.text for r in rows}
    miss = [r for r in results if r["stratum"] == POSITIVE and r["classification"] not in FLAGGED]
    pos = [r for r in results if r["stratum"] == POSITIVE]
    fps = [r for r in results if r["stratum"] in NEGATIVES and r["classification"] in FLAGGED]
    hindi = lambda r: bool(ROMANISED_HINDI_RX.search(text[(r["dataset"], r["index"])]))
    return {"missed_scams": len(miss), "missed_with_romanised_hindi_words": sum(map(hindi, miss)), "positives": len(pos),
            "positives_with_romanised_hindi_words": sum(map(hindi, pos)), "flagged_legitimate": len(fps),
            "flagged_legitimate_firing_payment_request": sum("msg.payment_request" in r["codes"] for r in fps),
            "flagged_legitimate_firing_reward": sum("msg.reward" in r["codes"] for r in fps),
            "flagged_legitimate_high_or_worse": sum(r["classification"] in ("High Risk", "Confirmed Malicious") for r in fps),
            "flagged_legitimate_from_url_rules_only": sum(all(c.startswith("url.") for c in r["codes"]) for r in fps)}


# --------------------------------------------------------------------------- AI grounding (separate from the classifier)
NUM_RX = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?%?")
DOMAIN_RX = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b")


def _flat(*parts) -> str:
    return " ".join(str(p) for p in parts if p).lower()


def ai_checks(ai: dict, message: str, findings_text: str) -> dict:
    """Independent grounding checks on an AI explanation (they do not reuse the production validator's logic):
    - quotes: every observation quote must occur in the message after whitespace normalisation;
    - numbers and domains in the AI's prose must appear in the message or the findings it was given;
    - the explanation must not cite a finding id that is not in the report."""
    src = norm(message) + " " + norm(findings_text)
    prose = _flat(ai.get("summary"), *[p.get("explanation") for p in ai.get("points", [])], *[o.get("rationale") for o in ai.get("observations", [])],
                  *ai.get("recommended_actions", []))
    nums = {n.rstrip("%").replace(",", "") for n in NUM_RX.findall(prose) if len(n.rstrip("%").replace(",", "")) >= 2}
    src_nums = {n.rstrip("%").replace(",", "") for n in NUM_RX.findall(src)}
    doms = {d for d in DOMAIN_RX.findall(prose) if not d.endswith((".", "e.g", "i.e")) and len(d) > 5}
    bad_q = [o["quote"] for o in ai.get("observations", []) if norm(o.get("quote", "")) not in norm(message)]
    return {"unverified_quotes": len(bad_q), "observations": len(ai.get("observations", [])),
            "unsupported_numbers": sorted(nums - src_nums)[:5], "unsupported_domains": sorted(d for d in doms if d not in src)[:5],
            "points": len(ai.get("points", []))}
