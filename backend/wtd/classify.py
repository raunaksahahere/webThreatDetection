"""Auditable risk classification. Deterministic; the AI never changes the outcome.

Rules (applied in order; first match wins):
  R-CONF-1  Confirmed Malicious  an authoritative intelligence listing (severity >= high)
  R-HIGH-1  High Risk            >= 1 strong finding with severity >= high, or >= 2 independent moderate findings with severity >= high
  R-INC-1   Inconclusive         no moderate-or-stronger finding AND an essential check failed or was unavailable
  R-SUS-1   Suspicious           >= 1 moderate finding with severity >= medium, or >= 3 weak findings with severity >= low
  R-LOW-1   Low Risk             none of the above and all essential checks succeeded

Excluded from the calculation: posture findings (code 'web.*': configuration hygiene, not threat
evidence), and severity 'info' findings (context such as "valid certificate" or "not listed").
Certificate configuration problems count as one independent signal group.
Weak evidence alone (language cues, AI observations, keywords) can never exceed Suspicious.
"""
from __future__ import annotations

from .models import Assessment, CheckResult, CheckStatus, Classification, Coverage, Finding

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TLS_CONFIG = {"tls.expired", "tls.not_yet_valid", "tls.hostname_mismatch", "tls.self_signed", "tls.untrusted_chain", "tls.policy_failure",
              "tls.weak_key", "tls.unusual_curve", "tls.weak_signature", "tls.excess_lifetime", "tls.old_protocol", "tls.no_sct"}
RULE_TEXT = {
    "R-CONF-1": "Confirmed Malicious: at least one authoritative threat-intelligence listing matches this target.",
    "R-HIGH-1": "High Risk: one strong high-severity indicator, or two independent moderate high-severity indicators.",
    "R-INC-1": "Inconclusive: no significant indicator was found, but essential checks could not be completed.",
    "R-SUS-1": "Suspicious: at least one moderate indicator, or three or more weak indicators, need further investigation.",
    "R-LOW-1": "Low Risk: no significant malicious indicators within the checks that ran. This is not proof of safety.",
}


def _group(f: Finding) -> str:
    return "tls-config" if f.code in TLS_CONFIG else f.code


def coverage(checks: list[CheckResult]) -> Coverage:
    applicable = [c for c in checks if c.status != CheckStatus.not_implemented]
    cnt = lambda s: sum(1 for c in applicable if c.status == s)
    missing = [c.name for c in checks if c.essential and c.status in (CheckStatus.failed, CheckStatus.unavailable)]
    return Coverage(applicable=len(applicable), succeeded=cnt(CheckStatus.succeeded), failed=cnt(CheckStatus.failed),
                    unavailable=cnt(CheckStatus.unavailable), skipped=cnt(CheckStatus.skipped), essential_missing=missing)


def classify(findings: list[Finding], checks: list[CheckResult]) -> Assessment:
    cov = coverage(checks)
    rel = [f for f in findings if not f.code.startswith("web.") and f.severity != "info"]
    ge = lambda f, s: SEV_RANK[f.severity] >= SEV_RANK[s]
    authoritative = [f for f in rel if f.strength == "authoritative" and ge(f, "high")]
    strong_high = [f for f in rel if f.strength == "strong" and ge(f, "high")]
    moderate_high = [f for f in rel if f.strength == "moderate" and ge(f, "high")]
    moderate_groups = {_group(f): f for f in moderate_high}
    moderate_med = [f for f in rel if f.strength in ("moderate", "strong") and ge(f, "medium")]
    weak = [f for f in rel if f.strength == "weak" and ge(f, "low")]
    contradictions: list[str] = []
    codes = {f.code for f in findings}
    if "url.official_domain" in codes and (authoritative or strong_high):
        contradictions.append("The domain is on our official-domain list, yet strong or authoritative indicators exist: the official site may be compromised, or a listing may be wrong. The stronger evidence is kept.")
    if "tls.valid" in codes and (authoritative or strong_high or len(moderate_groups) >= 2):
        contradictions.append("The certificate is valid, but that only shows the connection is encrypted to this domain; phishing sites routinely have valid certificates.")
    if any(f.code == "intel.no_listing" for f in findings) and (strong_high or moderate_groups):
        contradictions.append("Threat-intelligence sources had no listing, which means unknown, not clean; other indicators still apply.")
    if any(f.code == "intel.urlhaus_host_listed" and f.strength != "authoritative" for f in findings):
        contradictions.append("A URLhaus host listing on shared hosting or older than 30 days was treated as strong, not authoritative.")

    def done(cls: Classification, rule: str, basis: list[Finding], rationale: list[str]) -> Assessment:
        return Assessment(classification=cls, rule_id=rule, rule_text=RULE_TEXT[rule], basis_finding_ids=[f.id for f in basis][:12],
                          rationale=rationale, contradictions=contradictions, coverage=cov)

    if authoritative:
        return done(Classification.confirmed, "R-CONF-1", authoritative,
                    [f"{f.title} (source: {f.source})." for f in authoritative[:3]])
    if strong_high or len(moderate_groups) >= 2:
        basis = strong_high + list(moderate_groups.values())
        why = [f"Strong indicator: {f.title}." for f in strong_high[:3]] + [f"Indicator: {f.title}." for f in list(moderate_groups.values())[:3]]
        return done(Classification.high, "R-HIGH-1", basis, why)
    if not moderate_med and cov.essential_missing:
        return done(Classification.inconclusive, "R-INC-1", [],
                    [f"Essential check not completed: {n}." for n in cov.essential_missing] + ([f"{len(weak)} weak indicator(s) noted." ] if weak else []))
    if moderate_med or len(weak) >= 3:
        basis = moderate_med or weak
        why = [f"Indicator needing investigation: {f.title}." for f in moderate_med[:4]] or [f"Weak indicators combined ({len(weak)}): " + "; ".join(f.title for f in weak[:4]) + "."]
        if not moderate_med:
            why.append("Weak indicators alone cannot raise the classification above Suspicious.")
        return done(Classification.suspicious, "R-SUS-1", basis, why)
    why = ["No moderate or strong indicator was found in the checks that ran."]
    if weak:
        why.append(f"{len(weak)} weak signal(s) noted, below the threshold: " + "; ".join(f.title for f in weak[:3]) + ".")
    return done(Classification.low, "R-LOW-1", weak, why)
