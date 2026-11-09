"""Analysis orchestration: submit → safely collect evidence → checks → correlation → classify → explain."""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from . import intel
from .checks import dns_checks, tls_checks, url_rules, web_checks
from .classify import classify
from .config import SETTINGS
from .inspector import run_inspection
from .models import (CheckResult, CheckStatus, CorrelationLink, Finding, Hop, Indicator, Module, Provenance, Report, Severity,
                     Strength, iso)
from .netguard import UrlRejected, defang, fetch_block_reason, parse_url
from .store import Store

log = logging.getLogger("wtd.pipeline")
STORE = Store(SETTINGS.db_path, SETTINGS.database_url)
EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="analysis")

URL_LIMITATIONS = [
    "Automated checks cannot prove a site is safe; a Low Risk result means no significant indicator was found in the checks listed.",
    "Only one page was fetched, without running scripts; sites that hide content from automated visitors (cloaking) can appear harmless.",
    "Threat-intelligence sources have limited scope (URLhaus: malware downloads; CERT Polska: phishing targeting Poland). Not being listed is not evidence of safety.",
    "The brand list is small and curated; impersonation of brands outside it is detected only through generic indicators.",
    "Revocation status is reported separately and may be unavailable; a valid certificate does not mean the site is legitimate.",
]


def hmac_key(value: str) -> str:
    return "hmac:" + hmac.new(SETTINGS.hmac_key, value.encode(), hashlib.sha256).hexdigest()[:32]


def new_report(kind: str, display: str, raw: str) -> Report:
    r = Report(id=str(uuid.uuid4()), kind=kind, status="queued", created_at=iso(), input_display=display[:300],
               input_sha256=hashlib.sha256(raw.encode()).hexdigest())
    STORE.save(r)
    return r


def _check(name, module, status, essential, detail="", ms=0) -> CheckResult:
    return CheckResult(name=name, module=module, status=status, essential=essential, detail=detail[:300], duration_ms=ms)


def _actions(findings: list[Finding], classification: str) -> list[str]:
    acts = []
    if classification in ("High Risk", "Confirmed Malicious"):
        acts.append("Do not open this link or enter any information. If you already entered credentials, change that password now and contact the organisation through its official channel.")
    elif classification == "Suspicious":
        acts.append("Do not enter passwords, OTPs or payment details here until you have verified the site through the organisation's official address.")
    elif classification == "Inconclusive":
        acts.append("Not enough evidence could be collected. Treat the link with caution and verify it another way.")
    else:
        acts.append("No significant indicators were found, but stay cautious: check the address before entering sensitive information.")
    sev = {"critical": 0, "high": 1, "medium": 2}
    for f in sorted([f for f in findings if f.severity in sev and not f.code.startswith("web.")], key=lambda f: sev[f.severity]):
        if f.recommendation and f.recommendation not in acts:
            acts.append(f.recommendation)
        if len(acts) >= 6:
            break
    return acts


def correlate(r: Report, items: list[tuple[str, str, str]], shingles: list[int] | None = None) -> list[CorrelationLink]:
    links: dict[str, CorrelationLink] = {}
    for other, t, _, display in STORE.matching_indicators(r.id, items):
        o = STORE.get(other)
        if not o:
            continue
        method = "infrastructure" if t in ("ip", "cert_spki") else "brand_pattern" if t == "brand" else "exact_indicator"
        if other not in links:
            links[other] = CorrelationLink(other_report_id=other, other_created_at=o.created_at,
                                           other_classification=o.assessment.classification if o.assessment else o.status, shared=[], method=method)
        if t != "brand" or len(links[other].shared) == 0:
            links[other].shared.append(f"{t}: {display}")
        if method == "infrastructure" or (method == "exact_indicator" and links[other].method == "brand_pattern"):
            links[other].method = method
    if shingles:
        a = set(shingles)
        for other, sh in STORE.all_shingles(r.id):
            b = set(sh)
            if not a or not b:
                continue
            score = int(100 * len(a & b) / len(a | b))
            if score >= 45:
                o = STORE.get(other)
                if not o:
                    continue
                link = links.setdefault(other, CorrelationLink(other_report_id=other, other_created_at=o.created_at,
                                                               other_classification=o.assessment.classification if o.assessment else o.status,
                                                               shared=[], method="message_similarity"))
                link.shared.append(f"message text {score}% similar (word shingles)")
                if link.method == "brand_pattern":
                    link.method, link.score = "message_similarity", score
                elif link.method == "message_similarity":
                    link.score = score
    # Brand-only links are weak; keep them only if nothing stronger exists and limit their number.
    out = sorted(links.values(), key=lambda l: (l.method == "brand_pattern", l.other_created_at), reverse=False)
    strong = [l for l in out if l.method != "brand_pattern"]
    return (strong + [l for l in out if l.method == "brand_pattern"][:3])[:15]


ESCALATING_TYPES = ("cert_spki:", "upi:", "crypto_wallet:", "phone:", "email:")


def correlation_findings(links: list[CorrelationLink]) -> list[Finding]:
    """Only campaign-specific links escalate: shared certificate keys, payment identifiers, contact details,
    or near-identical message text. Same domain/URL (a re-check of the same target), shared IPs (CDNs) and
    brand names are shown as context links but never raise the classification."""
    bad = [l for l in links if l.other_classification in ("High Risk", "Confirmed Malicious")
           and not any(s.startswith(("domain:", "url:")) for s in l.shared)  # same target re-checked: not campaign evidence
           and (l.method == "message_similarity" or any(s.startswith(ESCALATING_TYPES) for s in l.shared))]
    if not bad:
        return []
    return [Finding(id="correlation.prior_high_risk", code="correlation.prior_high_risk", module=Module.correlation,
                    title="Shares indicators with earlier high-risk reports",
                    observed=f"{len(bad)} earlier report(s) classified High Risk or Confirmed Malicious share: " + "; ".join(bad[0].shared[:3]) + ".",
                    evidence={"reports": [l.other_report_id for l in bad[:10]], "methods": sorted({l.method for l in bad})},
                    source="wtd.correlate v1 (deterministic indicator matching)", provenance=Provenance.live, observed_at=iso(),
                    severity=Severity.high, strength=Strength.moderate,
                    impact="Reuse of the same domains, addresses, certificates or payment identifiers suggests the same campaign.",
                    recommendation="Treat this as part of a known campaign.",
                    limitation="Shared hosting and CDNs can create coincidental matches; matches are against reports stored in this instance only.")]


QR_FINDING = dict(code="url.qr_delivery", title="Address was delivered in a QR code",
                  impact="QR codes hide the destination until scanned; 'quishing' uses them to bypass link filters.",
                  rec="Check the decoded address below before opening it, exactly as you would a link in a message.",
                  lim="Context only; it does not change the classification.")


def analyse_url(rid: str, url: str, via: str | None = None, urlhaus_key: str | None = None) -> None:
    r = STORE.get(rid)
    r.status = "running"
    STORE.save(r)
    findings: list[Finding] = []
    checks: list[CheckResult] = []
    try:
        t0 = time.monotonic()
        p = parse_url(url)
        f, facts = url_rules.analyse_url(p)
        findings += f
        if via == "qr":
            facts["delivered_via"] = "QR code"
            findings.append(Finding(id="url.qr_delivery", code=QR_FINDING["code"], module=Module.url, title=QR_FINDING["title"],
                                    observed="Submitted from a QR code decoded in the investigator's browser.", source="WTD intake",
                                    provenance=Provenance.live, observed_at=iso(), severity=Severity.info, strength=Strength.weak,
                                    impact=QR_FINDING["impact"], recommendation=QR_FINDING["rec"], limitation=QR_FINDING["lim"]))
        r.subject = facts
        checks.append(_check("url.static", Module.url, CheckStatus.succeeded, True, f"{len(f)} indicator(s)", int((time.monotonic() - t0) * 1000)))
        reason = fetch_block_reason(p)
        registrable = facts.get("registrable_domain") or ""
        fetch, upgrade = None, None
        shared = set(url_rules.brand_data()["shared_hosting"])
        # Intelligence first: never fetch a destination an authoritative source already lists as malicious.
        io = intel.lookup(p.href, [p.host], shared, user_urlhaus_key=urlhaus_key)
        findings += io.findings
        checks += io.checks
        if not reason and any(f.strength == "authoritative" for f in io.findings):
            reason = "already listed as malicious by threat intelligence; not visited (static and intelligence analysis only)"
        if reason:
            for n, m in (("fetch.page", Module.web), ("tls.certificate", Module.tls), ("dns.records", Module.dns)):
                checks.append(_check(n, m, CheckStatus.skipped, False, f"blocked by request policy: {reason}"))
            findings.append(Finding(id="url.not_fetched", code="url.not_fetched", module=Module.url, title="Destination was not contacted",
                                    observed=f"The request policy blocked network access: {reason}.", evidence={"reason": reason},
                                    source="wtd.netguard (request boundary)", observed_at=iso(), severity=Severity.info, strength=Strength.weak,
                                    impact="Only static analysis was possible.", recommendation="Verify the link by other means.",
                                    limitation="Blocking is a safety measure, not a verdict."))
        else:
            t0 = time.monotonic()
            insp = run_inspection(p.href)
            ms = int((time.monotonic() - t0) * 1000)
            if not insp.get("ok"):
                checks.append(_check("fetch.page", Module.web, CheckStatus.failed, True, insp.get("error", "inspector failed"), ms))
            else:
                fetch = insp["fetch"]
                upgrade = insp.get("http_upgrade")
                r.redirects = [Hop(index=h["index"], url=h["url"][:2048], host=h["host"], ip=h.get("ip"), status=h.get("status"),
                                   location=h.get("location"), blocked_reason=h.get("blocked_reason") or h.get("error"),
                                   tls_version=(h.get("tls") or {}).get("version"), duration_ms=h.get("duration_ms", 0)) for h in fetch["hops"]]
                stop = fetch.get("stop_reason") or ""
                if fetch.get("final_status"):
                    checks.append(_check("fetch.page", Module.web, CheckStatus.succeeded, True,
                                         f"HTTP {fetch['final_status']} after {len(fetch['hops']) - 1} redirect(s), {fetch.get('body_bytes', 0)} bytes", ms))
                elif "NXDOMAIN" in stop:
                    checks.append(_check("fetch.page", Module.web, CheckStatus.succeeded, True, "domain does not exist (NXDOMAIN)", ms))
                    findings.append(Finding(id="dns.nxdomain", code="dns.nxdomain", module=Module.dns, title="Domain does not exist",
                                            observed=f"DNS returned NXDOMAIN for {p.host}.", evidence={"host": p.host}, source="dnspython via system resolver",
                                            observed_at=iso(), severity=Severity.low, strength=Strength.weak,
                                            impact="The link is dead; phishing domains are often taken down quickly.",
                                            recommendation="Do not trust messages that point to non-existent sites.",
                                            limitation="The domain may have existed when the link was sent."))
                elif "blocked by policy" in stop:
                    checks.append(_check("fetch.page", Module.web, CheckStatus.skipped, False, stop, ms))
                else:
                    checks.append(_check("fetch.page", Module.web, CheckStatus.failed, True, stop or "no response", ms))
                # TLS on the final https hop that completed a handshake
                tls_hop = next((h for h in reversed(fetch["hops"]) if (h.get("tls") or {}).get("chain_der_b64")), None)
                if tls_hop:
                    chain = [base64.b64decode(c) for c in tls_hop["tls"]["chain_der_b64"]]
                    tf, tsum = tls_checks.analyse_chain(tls_hop["host"], ":" in tls_hop["host"] or tls_hop["host"].replace(".", "").isdigit(),
                                                        chain, tls_hop["tls"].get("version"), tls_hop["tls"].get("cipher"))
                    findings += tf
                    tsum["host"] = tls_hop["host"]
                    r.tls = tsum
                    checks.append(_check("tls.certificate", Module.tls, CheckStatus.succeeded, True, f"chain of {len(chain)} from {tls_hop['host']}: {tsum.get('verification')}"))
                    checks.append(_check("tls.distrust_lists", Module.tls, CheckStatus.succeeded, False,
                                         f"{tsum.get('distrust_hits', 0)} hit(s) across: {', '.join(tsum.get('distrust_sources', []))}"))
                    oc = insp.get("ocsp") or {}
                    if tsum.get("ocsp_urls") and oc.get("body_b64") and oc.get("host") == tls_hop["host"]:
                        rv = tls_checks.interpret_ocsp(chain, base64.b64decode(oc["body_b64"]))
                        tsum["revocation"] = rv
                        if rv["status"] in ("good", "revoked", "unknown"):
                            checks.append(_check("tls.revocation", Module.tls, CheckStatus.succeeded, False,
                                                 f"OCSP ({oc.get('responder')}): {rv['status']}, signed and fresh until {rv.get('next_update')}"))
                            findings += tls_checks.revocation_findings(rv)
                        else:
                            checks.append(_check("tls.revocation", Module.tls, CheckStatus.unavailable, False,
                                                 f"OCSP response not usable: {rv.get('detail')}. Status unknown, not a risk signal."))
                    elif tsum.get("ocsp_urls"):
                        checks.append(_check("tls.revocation", Module.tls, CheckStatus.unavailable, False,
                                             f"OCSP responder did not answer within limits ({(oc.get('error') or 'no response')[:120]}). Status unknown, not a risk signal."))
                    else:
                        checks.append(_check("tls.revocation", Module.tls, CheckStatus.unavailable, False,
                                             "No OCSP responder in the certificate (common since OCSP became optional in 2024); CRL checking not enabled. Status unknown, not a risk signal."))
                elif any(h["url"].startswith("https://") for h in fetch["hops"]):
                    checks.append(_check("tls.certificate", Module.tls, CheckStatus.failed, True,
                                         next((h.get("error") for h in fetch["hops"] if h["url"].startswith("https://") and h.get("error")), "TLS handshake failed")))
                else:
                    checks.append(_check("tls.certificate", Module.tls, CheckStatus.skipped, False, "site served over plain HTTP"))
                wf, wsum = web_checks.posture(fetch, upgrade)
                findings += wf
                findings += web_checks.content_indicators(fetch, registrable)
                r.web = {**wsum, "title": (fetch.get("features") or {}).get("title"), "forms": len((fetch.get("features") or {}).get("forms") or []),
                         "password_fields": (fetch.get("features") or {}).get("password_fields"), "body_truncated": fetch.get("body_truncated"),
                         "final_url_defanged": defang(fetch.get("final_url") or "")}
                checks.append(_check("web.passive_assessment", Module.web,
                                     CheckStatus.succeeded if fetch.get("final_status") else CheckStatus.skipped, False,
                                     f"{len(wf)} posture finding(s) from the final response"))
            if registrable:
                drec, dchk = dns_checks.dns_records(registrable)
                checks.append(dchk)
                r.subject = {**r.subject, "dns": drec}
                af, afacts, achk = dns_checks.domain_age(registrable)
                findings += af
                checks.append(achk)
                if afacts:
                    r.subject = {**r.subject, "domain_age": afacts}
        # Intelligence for redirect destinations discovered during the fetch
        extra = [h.host for h in r.redirects if h.host and h.host != p.host]
        if extra:
            io2 = intel.lookup(None, extra, shared, user_urlhaus_key=urlhaus_key)
            findings += [f for f in io2.findings if f.code != "intel.no_listing"]
            checks += [c.model_copy(update={"name": c.name + ".redirects", "essential": False}) for c in io2.checks]
        # Indicators and correlation
        items: list[tuple[str, str, str]] = []
        if registrable:
            items.append(("domain", registrable, registrable.replace(".", "[.]")))
        items.append(("url", p.href, defang(p.href)))
        for h in r.redirects:
            if h.ip:
                items.append(("ip", h.ip, h.ip))
        if r.tls and r.tls.get("chain"):
            leaf_spki = r.tls["chain"][0]["spki_sha256"]
            items.append(("cert_spki", leaf_spki, f"leaf key {leaf_spki[:16]}…"))
        brands = sorted({str(f.evidence.get("brand") or "") for f in findings if f.evidence.get("brand")} |
                        {f.title.split(" imitates ")[-1] for f in findings if " imitates " in f.title})
        items += [("brand", b.lower(), b) for b in brands if b and not facts.get("official_brand")]
        r.indicators = [Indicator(type=t, display=d, match_key=k) for t, k, d in items]
        links = correlate(r, items)
        r.correlations = links
        findings += correlation_findings(links)
        checks.append(_check("correlation.indicators", Module.correlation, CheckStatus.succeeded, False, f"{len(links)} related report(s)"))
        STORE.add_indicators(r.id, r.created_at, items)
        _finish(r, findings, checks, URL_LIMITATIONS)
    except UrlRejected as e:
        r.status, r.error, r.completed_at = "failed", str(e), iso()
        STORE.save(r)
    except Exception as e:  # never leave a report stuck in "running"
        log.exception("analysis failed")
        r.status, r.error, r.completed_at = "failed", f"internal error: {type(e).__name__}", iso()
        r.findings, r.checks = findings, checks
        STORE.save(r)


def _finish(r: Report, findings: list[Finding], checks: list[CheckResult], limitations: list[str]) -> None:
    # de-duplicate finding ids
    seen: dict[str, int] = {}
    for f in findings:
        if f.id in seen:
            seen[f.id] += 1
            f.id = f"{f.id}#{seen[f.id]}"
        else:
            seen[f.id] = 1
    r.findings = findings
    r.checks = checks
    r.assessment = classify(findings, checks)
    r.recommended_actions = _actions(findings, r.assessment.classification)
    r.limitations = limitations
    r.status = "complete"
    r.completed_at = iso()
    STORE.save(r)
    try:
        from .ai.explain import explain_report

        r.ai = explain_report(r)
        STORE.save(r)
    except ImportError:
        pass
    except Exception as e:  # AI failure never affects the deterministic result
        log.warning("AI explanation failed: %s", type(e).__name__)


def submit_url(url: str, via: str | None = None, urlhaus_key: str | None = None) -> Report:
    """urlhaus_key: optional investigator-supplied key, held in memory for this analysis only (never saved)."""
    p = parse_url(url)  # raises UrlRejected → 422
    r = new_report("url", defang(p.href), p.href)
    EXECUTOR.submit(analyse_url, r.id, p.href, via, urlhaus_key)
    return r
