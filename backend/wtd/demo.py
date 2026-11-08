"""Offline demonstration fixtures (CLI only; never reachable through the public API).

  python -m wtd.demo tls-distrusted   # eMudhra-like scenario on a SYNTHETIC chain, stored as a labelled report

The chain is generated locally; no network connection is made. Every finding carries provenance
'synthetic' and the report says so in its input, subject, and limitations.
"""
from __future__ import annotations

import sys

from cryptography.x509.verification import Store

from .checks import tls_checks
from .classify import classify
from .models import CheckResult, CheckStatus, Module, Provenance
from .pipeline import STORE, _actions, new_report
from .tls_fixtures import build


def tls_distrusted() -> str:
    host = "demo-distrusted.wtd.test"
    chain, root = build("distrusted", host)
    findings, summary = tls_checks.analyse_chain(host, False, chain, "TLSv1.3", "TLS_AES_256_GCM_SHA384",
                                                 store=Store([root]), provenance=Provenance.synthetic)
    summary["host"] = host
    summary["trust_store"] = "SYNTHETIC test root (fixture), not a public trust store"
    r = new_report("url", f"SYNTHETIC FIXTURE (offline): https://{host}/", f"synthetic:{host}")
    r.subject = {"host": host, "registrable_domain": "wtd.test", "synthetic": True,
                 "note": "Generated locally to demonstrate distrusted-CA detection. No real site, CA or intelligence feed is involved."}
    r.tls = summary
    checks = [
        CheckResult(name="tls.certificate", module=Module.tls, status=CheckStatus.succeeded, essential=True, detail="synthetic chain analysed offline"),
        CheckResult(name="tls.distrust_lists", module=Module.tls, status=CheckStatus.succeeded, essential=False,
                    detail=f"{summary.get('distrust_hits')} hit(s); includes the SYNTHETIC demo list"),
        CheckResult(name="fetch.page", module=Module.web, status=CheckStatus.skipped, essential=False, detail="offline fixture: no network access"),
        CheckResult(name="intel.certpl", module=Module.intel, status=CheckStatus.skipped, essential=False, detail="offline fixture"),
    ]
    r.findings, r.checks = findings, checks
    r.assessment = classify(findings, checks)
    r.recommended_actions = _actions(findings, r.assessment.classification)
    r.limitations = [
        "SYNTHETIC demonstration: the certificate chain and the distrust entry were created for this demo and are not real intelligence.",
        "In real use the same matcher compares chains against Mozilla OneCRL, the Chromium SPKI blocklist and the curated eMudhra fingerprints (Bugzilla 2083449).",
        "The platform does not and cannot detect a CA's internal key-generation weakness from a URL; it detects certificates that trust authorities have listed as distrusted.",
    ]
    r.status, r.completed_at = "complete", r.created_at
    STORE.save(r)
    return r.id


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "tls-distrusted":
        print(tls_distrusted())
    else:
        print(__doc__)
        sys.exit(2)
