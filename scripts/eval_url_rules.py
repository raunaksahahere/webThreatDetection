"""Offline evaluation of the URL rules alone (no fetch, no TLS, no DNS, no threat feeds).

It measures one layer honestly, not the whole system:
- False-positive side: the top-N registrable domains of a Tranco list (popular sites; popularity is a proxy for
  benign, not a guarantee). Reports how many would be Suspicious or worse from the URL alone, and lists them.
- Detection side: a random sample of the CERT Polska Warning List (phishing domains, focus on Poland), with the
  feed itself disabled, to show what URL heuristics catch without intelligence. Most phishing domains do not
  look like a brand, so a low number here is expected and is exactly why feeds, TLS and page checks exist.

Usage:
  backend/.venv/bin/python scripts/eval_url_rules.py --tranco top-1m.csv --tranco-id 94P72 [--top 1000] [--phish 1000]
Writes docs/evaluation-url-rules.json. Nothing is fetched; domains are only parsed.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from wtd.checks import url_rules  # noqa: E402
from wtd.classify import classify  # noqa: E402
from wtd.models import CheckResult  # noqa: E402
from wtd.netguard import UrlRejected, parse_url  # noqa: E402

CHECKS = [CheckResult(name="url.rules", module="url", status="succeeded", essential=True)]


def assess(domain: str) -> dict:
    try:
        p = parse_url(f"https://{domain}/")
    except UrlRejected as e:
        return {"domain": domain, "classification": "unparseable", "findings": [str(e)[:60]]}
    fs, _ = url_rules.analyse_url(p)
    a = classify(fs, CHECKS)
    return {"domain": domain, "classification": a.classification,
            "findings": [f"{f.code} ({f.severity}/{f.strength})" for f in fs if f.severity not in ("info",)]}


def summarise(rows: list[dict]) -> dict:
    c = Counter(r["classification"] for r in rows)
    flagged = [r for r in rows if r["classification"] in ("Suspicious", "High Risk", "Confirmed Malicious")]
    codes = Counter(code.split(" ")[0] for r in flagged for code in r["findings"])
    return {"n": len(rows), "by_classification": dict(c), "flagged": len(flagged),
            "flagged_rate": round(len(flagged) / max(1, len(rows)), 4), "flagged_by_rule": dict(codes.most_common()),
            "flagged_examples": flagged[:60]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tranco", required=True)
    ap.add_argument("--tranco-id", default="unknown")
    ap.add_argument("--top", type=int, default=1000)
    ap.add_argument("--phish", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=7, help="development sample seed (rules were tuned looking at this sample)")
    ap.add_argument("--holdout-seed", type=int, default=99)
    ap.add_argument("--holdout-ranks", default="20001-21000")
    a = ap.parse_args()

    with open(a.tranco, newline="") as fh:
        ranked = [row[1].strip().lower() for row in csv.reader(fh)]
    lo, hi = (int(x) for x in a.holdout_ranks.split("-"))
    top, holdout = ranked[: a.top], ranked[lo - 1: hi]
    certpl = sorted({ln.strip().lower() for ln in (ROOT / "data/certpl_domains.txt").read_text().splitlines() if ln.strip() and not ln.startswith("#")})
    dev = certpl[:]
    random.Random(a.seed).shuffle(dev)
    dev = dev[: a.phish]
    rest = sorted(set(certpl) - set(dev))
    random.Random(a.holdout_seed).shuffle(rest)
    held = rest[: a.phish]

    # The top-N run disables the popular-domain exception (those domains are IN the exception list), so it measures the rules.
    real_popular = url_rules.popular_domains
    url_rules.popular_domains = lambda: frozenset()
    top_rows = [assess(d) for d in top]
    url_rules.popular_domains = real_popular
    out = {
        "what": "URL rules only (no fetch, TLS, DNS/RDAP or feeds). Measures one layer, not the system.",
        "tranco_list": f"https://tranco-list.eu/list/{a.tranco_id}",
        "benign_top": {"source": f"Tranco {a.tranco_id} ranks 1-{a.top}; popular-domain exception DISABLED (measures the rules themselves)",
                       **summarise(top_rows)},
        "benign_holdout": {"source": f"Tranco {a.tranco_id} ranks {a.holdout_ranks}; shipped configuration; none of these are in the top-10k exception list",
                           **summarise([assess(d) for d in holdout])},
        "phish_dev": {"source": f"CERT Polska snapshot, random {a.phish} (seed {a.seed}); DEVELOPMENT sample: brand additions were informed by it; feed disabled",
                      **summarise([assess(d) for d in dev])},
        "phish_holdout": {"source": f"CERT Polska snapshot, random {a.phish} disjoint from the development sample (seed {a.holdout_seed}); feed disabled",
                          **summarise([assess(d) for d in held])},
    }
    dest = ROOT / "docs/evaluation-url-rules.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    for k in ("benign_top", "benign_holdout", "phish_dev", "phish_holdout"):
        s = out[k]
        print(f"{k:15} n={s['n']:5}  flagged={s['flagged']:4} ({s['flagged_rate']:.1%})  {s['by_classification']}")
        print(f"                by rule: {s['flagged_by_rule']}")
    for k in ("benign_top", "benign_holdout"):
        print(f"{k} flagged:", ", ".join(f"{r['domain']} [{'; '.join(r['findings'])}]" for r in out[k]["flagged_examples"][:40]))
    print(f"wrote {dest.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
