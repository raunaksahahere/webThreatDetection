"""DNS characteristics and domain age (RDAP). Queries go to the system resolver and to RDAP
servers listed in IANA's bootstrap file (never to user-supplied addresses)."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.resolver
import httpx

from ..models import CheckResult, CheckStatus, Finding, Module, Provenance, Severity, Strength, iso

PROJECT_DATA = Path(__file__).resolve().parents[3] / "data"
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
SOURCE_DNS = "wtd.dns_checks v1 (dnspython via system resolver)"
SOURCE_RDAP = "RDAP (registry server from IANA bootstrap)"
_bootstrap: dict | None = None
_rdap_cache: dict[str, tuple[float, dict]] = {}


def _f(code, module, title, observed, sev, strength, impact, rec, lim, ev, source) -> Finding:
    return Finding(id=code, code=code, module=module, title=title, observed=observed, evidence=ev, source=source,
                   provenance=Provenance.live, observed_at=iso(), severity=sev, strength=strength, impact=impact,
                   recommendation=rec, limitation=lim)


def dns_records(registrable: str, timeout: float = 4.0) -> tuple[dict, CheckResult]:
    t0 = time.monotonic()
    res = dns.resolver.Resolver()
    res.lifetime = timeout
    out: dict = {}
    errors = 0
    for rtype in ("NS", "MX", "TXT"):
        try:
            ans = res.resolve(registrable, rtype, raise_on_no_answer=False)
            vals = [r.to_text()[:200] for r in ans.rrset] if ans.rrset is not None else []
            if rtype == "TXT":
                vals = [v for v in vals if "spf" in v.lower() or "dmarc" in v.lower()][:3]
            out[rtype.lower()] = vals[:8]
        except dns.resolver.NXDOMAIN:
            return {"nxdomain": True}, CheckResult(name="dns.records", module=Module.dns, status=CheckStatus.succeeded, essential=True,
                                                   detail="NXDOMAIN", duration_ms=int((time.monotonic() - t0) * 1000))
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
            errors += 1
            out[rtype.lower()] = None
    try:
        ans = res.resolve("_dmarc." + registrable, "TXT", raise_on_no_answer=False)
        out["dmarc"] = bool(ans.rrset and any("v=dmarc1" in r.to_text().lower() for r in ans.rrset))
    except Exception:
        out["dmarc"] = None
    status = CheckStatus.succeeded if errors < 3 else CheckStatus.failed
    return out, CheckResult(name="dns.records", module=Module.dns, status=status, essential=True,
                            detail=f"NS/MX/TXT for {registrable}" + (f"; {errors} lookup(s) failed" if errors else ""),
                            duration_ms=int((time.monotonic() - t0) * 1000))


def _rdap_base(tld: str) -> str | None:
    global _bootstrap
    if _bootstrap is None:
        cache = PROJECT_DATA / "rdap_dns.json"
        try:
            if cache.exists() and time.time() - cache.stat().st_mtime < 86400:
                _bootstrap = json.loads(cache.read_text())
            else:
                r = httpx.get(BOOTSTRAP_URL, timeout=10)
                r.raise_for_status()
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(r.text)
                _bootstrap = r.json()
        except Exception:
            if cache.exists():
                _bootstrap = json.loads(cache.read_text())
            else:
                return None
    for tlds, urls in _bootstrap.get("services", []):
        if tld in tlds:
            https = [u for u in urls if u.startswith("https://")]
            return (https or urls)[0]
    return None


def domain_age(registrable: str) -> tuple[list[Finding], dict, CheckResult]:
    t0 = time.monotonic()
    tld = registrable.rsplit(".", 1)[-1]
    if registrable in _rdap_cache and time.time() - _rdap_cache[registrable][0] < 3600:
        data = _rdap_cache[registrable][1]
    else:
        base = _rdap_base(tld)
        if not base:
            return [], {}, CheckResult(name="dns.rdap_age", module=Module.dns, status=CheckStatus.unavailable, essential=False,
                                       detail=f"no RDAP server listed for .{tld} in the IANA bootstrap")
        try:
            r = httpx.get(base.rstrip("/") + "/domain/" + registrable, timeout=10, follow_redirects=True,
                          headers={"Accept": "application/rdap+json", "User-Agent": "WTD/0.1"})
        except Exception as e:
            return [], {}, CheckResult(name="dns.rdap_age", module=Module.dns, status=CheckStatus.failed, essential=False,
                                       detail=f"{type(e).__name__}", duration_ms=int((time.monotonic() - t0) * 1000))
        if r.status_code == 404:
            return [], {"rdap": "not found"}, CheckResult(name="dns.rdap_age", module=Module.dns, status=CheckStatus.succeeded, essential=False,
                                                          detail="registry has no record (404)")
        if r.status_code != 200:
            return [], {}, CheckResult(name="dns.rdap_age", module=Module.dns, status=CheckStatus.failed, essential=False,
                                       detail=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return [], {}, CheckResult(name="dns.rdap_age", module=Module.dns, status=CheckStatus.failed, essential=False, detail="invalid JSON")
        _rdap_cache[registrable] = (time.time(), data)
    reg_date = next((e.get("eventDate") for e in data.get("events", []) if e.get("eventAction") == "registration"), None)
    registrar = next((ent.get("vcardArray", [None, []])[1] for ent in data.get("entities", []) if "registrar" in (ent.get("roles") or [])), None)
    registrar_name = None
    if registrar:
        registrar_name = next((v[3] for v in registrar if v and v[0] == "fn"), None)
    facts = {"registered": reg_date, "registrar": registrar_name}
    findings: list[Finding] = []
    chk = CheckResult(name="dns.rdap_age", module=Module.dns, status=CheckStatus.succeeded, essential=False,
                      detail=f"registration date {reg_date or 'not published'}", duration_ms=int((time.monotonic() - t0) * 1000))
    if reg_date:
        try:
            d = datetime.fromisoformat(reg_date.replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - d).days
            facts["age_days"] = days
            if days < 30:
                findings.append(_f("dns.new_domain", Module.dns, f"Domain was registered {days} day(s) ago",
                                   f"RDAP registration date {reg_date[:10]} ({days} days old).",
                                   Severity.high if days < 7 else Severity.medium, Strength.moderate,
                                   "Most phishing domains are used within days of registration.",
                                   "Be very cautious with brand-new domains that ask for personal or payment details.",
                                   "New legitimate sites exist; age is one signal among several.", {"registered": reg_date, "age_days": days}, SOURCE_RDAP))
        except ValueError:
            pass
    return findings, facts, chk
