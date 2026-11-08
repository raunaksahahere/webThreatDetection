"""Threat-intelligence lookups (fixed, trusted endpoints; never user-controlled URLs).

Sources and their actual scope (shown in every finding):
- URLhaus (abuse.ch): malware-download URLs only. Needs URLHAUS_AUTH_KEY. Not-for-profit use.
  Data is never stored beyond a short cache and never committed to the repository.
- CERT Polska Warning List: phishing/fraud domains targeting users in Poland. "Any purpose,
  including commercial"; no key. Local copy refreshed every 30 minutes.
A no-hit means "not listed in that source" (unknown), never "clean".
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from .checks.url_rules import official_brand_for, split_domain
from .models import CheckResult, CheckStatus, Finding, Module, Provenance, Severity, Strength, iso

PROJECT_DATA = Path(__file__).resolve().parents[2] / "data"
CERTPL_URL = "https://hole.cert.pl/domains/v2/domains.txt"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
CACHE_TTL = 30 * 60
FRESH_DAYS = 30
UA = "WTD-Intel/0.1 (hackathon prototype; non-commercial)"


@dataclass
class IntelOutcome:
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    matches: list[dict] = field(default_factory=list)


class CertPolskaList:
    def __init__(self, path: Path | None = None):
        self.path = path or PROJECT_DATA / "certpl_domains.txt"
        self.domains: set[str] = set()
        self.loaded_at: float = 0.0
        self.source_time: str | None = None
        self.lock = threading.Lock()
        self.error: str | None = None

    def refresh(self, force: bool = False) -> None:
        with self.lock:
            if not force and self.domains and time.time() - self.loaded_at < CACHE_TTL:
                return
            try:
                r = httpx.get(CERTPL_URL, timeout=20, headers={"User-Agent": UA})
                r.raise_for_status()
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.write_text(r.text)
                self.source_time = r.headers.get("last-modified")
                self.error = None
            except Exception as e:  # network failure: fall back to local copy
                self.error = f"refresh failed: {type(e).__name__}"
            if self.path.exists():
                self.domains = {ln.strip().lower().rstrip(".") for ln in self.path.read_text().splitlines() if ln.strip() and not ln.startswith("#")}
                self.loaded_at = time.time()
                if not self.source_time:
                    self.source_time = datetime.fromtimestamp(self.path.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") + " (local copy)"

    def load_local(self) -> None:
        """Load the on-disk copy without any network access (analysis never waits for a download)."""
        if self.domains or not self.path.exists():
            return
        self.domains = {ln.strip().lower().rstrip(".") for ln in self.path.read_text().splitlines() if ln.strip() and not ln.startswith("#")}
        self.loaded_at = self.path.stat().st_mtime
        self.source_time = datetime.fromtimestamp(self.loaded_at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") + " (local copy)"

    def refresh_async(self) -> None:
        """Start a background download if the copy is stale. The list is ~2.5 MB and the host is slow."""
        if time.time() - self.loaded_at < CACHE_TTL or getattr(self, "_refreshing", False):
            return
        self._refreshing = True

        def run():
            try:
                r = httpx.get(CERTPL_URL, timeout=httpx.Timeout(30, read=300), headers={"User-Agent": UA})
                r.raise_for_status()
                tmp = self.path.with_suffix(".tmp")
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp.write_text(r.text)
                tmp.replace(self.path)
                with self.lock:
                    self.domains = set()
                    self.load_local()
                    self.source_time = r.headers.get("last-modified") or self.source_time
                    self.error = None
            except Exception as e:
                self.error = f"background refresh failed: {type(e).__name__}"
            finally:
                self._refreshing = False

        threading.Thread(target=run, daemon=True, name="certpl-refresh").start()

    def lookup(self, host: str) -> str | None:
        h = host.lower().rstrip(".")
        parts = h.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in self.domains:
                return cand
        return None


CERTPL = CertPolskaList()
_cache: dict[tuple[str, str], tuple[float, dict]] = {}


def urlhaus_key() -> str | None:
    k = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    return k or None


def _urlhaus(kind: str, value: str, key: str) -> dict:
    ck = (kind, value)
    hit = _cache.get(ck)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return {**hit[1], "_cached_at": hit[0]}
    r = httpx.post(f"{URLHAUS_API}/{kind}/", data={kind: value}, timeout=12, headers={"Auth-Key": key, "User-Agent": UA})
    if r.status_code in (401, 403):
        raise PermissionError(f"URLhaus rejected the Auth-Key (HTTP {r.status_code})")
    r.raise_for_status()
    data = r.json()
    _cache[ck] = (time.time(), data)
    return data


def _recent(date_str: str | None) -> bool:
    if not date_str:
        return False
    try:
        d = datetime.strptime(date_str[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return datetime.now(timezone.utc) - d < timedelta(days=FRESH_DAYS)


def lookup(url: str | None, hosts: list[str], shared_hosting: set[str] | None = None, remote: bool = True) -> IntelOutcome:
    """Look up the submitted URL and up to 5 distinct hosts (submitted, redirects, final).

    remote=False uses only local data (CERT Polska snapshot) so nothing about the lookup leaves this machine;
    used by the real-time quick check, where every visited address would otherwise be sent to a third party."""
    out = IntelOutcome()
    shared_hosting = shared_hosting or set()
    hosts = list(dict.fromkeys(h for h in hosts if h))[:5]

    # CERT Polska
    t0 = time.monotonic()
    CERTPL.load_local()
    CERTPL.refresh_async()
    if CERTPL.domains:
        listed = [(h, m) for h in hosts if (m := CERTPL.lookup(h))]
        out.checks.append(CheckResult(name="intel.certpl", module=Module.intel, status=CheckStatus.succeeded, essential=True,
                                      detail=f"{len(CERTPL.domains)} domains, list time {CERTPL.source_time}" + (f"; {CERTPL.error}" if CERTPL.error else ""),
                                      duration_ms=int((time.monotonic() - t0) * 1000)))
        for h, m in listed:
            out.matches.append({"source": "CERT Polska", "host": h, "listed": m})
            out.findings.append(Finding(
                id=f"intel.certpl:{m}", code="intel.certpl_listed", module=Module.intel,
                title="Domain is on the CERT Polska phishing/fraud warning list",
                observed=f"'{m}' (matching host '{h}') is listed in the CERT Polska Warning List (list time {CERTPL.source_time}).",
                evidence={"host": h, "listed_domain": m, "list_time": CERTPL.source_time},
                source="CERT Polska Warning List (hole.cert.pl)", provenance=Provenance.dataset if CERTPL.error else Provenance.live,
                observed_at=iso(), severity=Severity.critical, strength=Strength.authoritative,
                impact="A national CERT has identified this domain as used for phishing or fraud.",
                recommendation="Do not visit or enter any information. Report the message or link that led you here.",
                limitation="The list targets threats to users in Poland and is published without warranty of completeness or accuracy; domain-level match."))
        if not listed:
            out.findings.append(Finding(
                id="intel.certpl_nohit", code="intel.no_listing", module=Module.intel, title="Not on the CERT Polska warning list (unknown, not clean)",
                observed=f"None of {len(hosts)} checked host(s) is listed.", evidence={"hosts": hosts}, source="CERT Polska Warning List (hole.cert.pl)",
                provenance=Provenance.live, observed_at=iso(), severity=Severity.info, strength=Strength.weak,
                impact="No conclusion: the list mostly covers threats to users in Poland.",
                recommendation="Absence from a list is not evidence of safety.", limitation="Regional, domain-level list."))
    else:
        out.checks.append(CheckResult(name="intel.certpl", module=Module.intel, status=CheckStatus.unavailable, essential=True,
                                      detail=CERTPL.error or "list not available"))

    # URLhaus
    key = urlhaus_key()
    if not remote:
        out.checks.append(CheckResult(name="intel.urlhaus", module=Module.intel, status=CheckStatus.skipped, essential=False,
                                      detail="not queried in quick-check mode (no third-party lookups for browsing)"))
        return out
    if not key:
        out.checks.append(CheckResult(name="intel.urlhaus", module=Module.intel, status=CheckStatus.unavailable, essential=False,
                                      detail="URLHAUS_AUTH_KEY not configured"))
        return out
    t0 = time.monotonic()
    try:
        any_hit = False
        if url:
            d = _urlhaus("url", url, key)
            if d.get("query_status") == "ok":
                any_hit = True
                fresh = d.get("url_status") == "online" or _recent(d.get("date_added")) or _recent(d.get("last_online"))
                out.matches.append({"source": "URLhaus", "url_status": d.get("url_status"), "threat": d.get("threat")})
                out.findings.append(Finding(
                    id="intel.urlhaus_url", code="intel.urlhaus_url_listed", module=Module.intel,
                    title="Exact URL is listed by URLhaus as a malware-distribution URL",
                    observed=f"URLhaus status '{d.get('url_status')}', threat '{d.get('threat')}', added {d.get('date_added')}, tags {', '.join(d.get('tags') or [])[:80]}.",
                    evidence={"url_status": d.get("url_status"), "threat": d.get("threat"), "date_added": d.get("date_added"),
                              "last_online": d.get("last_online"), "tags": (d.get("tags") or [])[:10], "reference": d.get("urlhaus_reference"),
                              "cached": "_cached_at" in d},
                    source="URLhaus (abuse.ch)", provenance=Provenance.cached if "_cached_at" in d else Provenance.live, observed_at=iso(),
                    severity=Severity.critical, strength=Strength.authoritative if fresh else Strength.strong,
                    impact="This exact address has been used to distribute malware.",
                    recommendation="Do not open or download anything from this link.",
                    limitation="URLhaus tracks malware-download URLs only, not phishing." + ("" if fresh else f" Listing is older than {FRESH_DAYS} days and offline (stale).")))
        for h in hosts:
            d = _urlhaus("host", h, key)
            if d.get("query_status") != "ok":
                continue
            any_hit = True
            urls = d.get("urls") or []
            online = sum(1 for u in urls if u.get("url_status") == "online")
            reg = split_domain(h).registrable
            count = int(d.get("url_count") or 0)
            bl = d.get("blacklists") or {}
            # Domain-level verdicts from Spamhaus DBL / SURBL (as reported by URLhaus). "abused_legit_*" means a legitimate domain was abused.
            dbl_bad = [f"{k}: {v}" for k, v in bl.items() if v and v != "not listed" and not str(v).startswith("abused_legit")]
            platform = h in shared_hosting or reg in shared_hosting or count >= 1000 or official_brand_for(reg) is not None \
                or any(str(v).startswith("abused_legit") for v in bl.values())
            if dbl_bad:
                sev, strength, why = Severity.critical, Strength.authoritative, f"the domain itself is listed ({'; '.join(dbl_bad)})"
            elif platform:
                sev, strength, why = Severity.info, Strength.weak, "a widely used platform where users upload content; listings concern specific uploaded files, not this domain"
            elif online:
                sev, strength, why = Severity.high, Strength.strong, f"{online} listed malware URL(s) on this host are currently online"
            else:
                sev, strength, why = Severity.low, Strength.weak, "historical listing only; no listed URL on this host is currently online"
            out.matches.append({"source": "URLhaus", "host": h, "url_count": count, "online": online, "blacklists": bl})
            out.findings.append(Finding(
                id=f"intel.urlhaus_host:{h}", code="intel.urlhaus_host_listed", module=Module.intel,
                title="URLhaus has malware URLs on this host" if not platform else "Platform hosts some user-uploaded malware (URLhaus context)",
                observed=f"URLhaus lists {count} malware URL(s) on '{h}' ({online} online, first seen {d.get('firstseen')}); assessed as {why}.",
                evidence={"host": h, "url_count": count, "online": online, "firstseen": d.get("firstseen"), "blacklists": bl,
                          "reference": d.get("urlhaus_reference"), "platform": platform},
                source="URLhaus (abuse.ch)", provenance=Provenance.live, observed_at=iso(), severity=sev, strength=strength,
                impact="Files downloaded from this host may be malicious." if not platform else "Only specific uploaded files are implicated, not the whole site.",
                recommendation="Avoid downloading files from this host." if not platform else "Be careful with downloads from links on this platform.",
                limitation="A host-level listing does not show that the submitted page is malicious unless the exact URL is listed. "
                           "URLhaus tracks malware-download URLs only, not phishing."))
        if not any_hit:
            out.findings.append(Finding(
                id="intel.urlhaus_nohit", code="intel.no_listing", module=Module.intel, title="Not listed by URLhaus (unknown, not clean)",
                observed=f"No URLhaus record for the URL or {len(hosts)} host(s).", evidence={"hosts": hosts}, source="URLhaus (abuse.ch)",
                provenance=Provenance.live, observed_at=iso(), severity=Severity.info, strength=Strength.weak,
                impact="No conclusion: URLhaus only tracks malware-download URLs.",
                recommendation="Absence from a list is not evidence of safety.", limitation="Malware-download scope only."))
        out.checks.append(CheckResult(name="intel.urlhaus", module=Module.intel, status=CheckStatus.succeeded, essential=False,
                                      detail=f"URL + {len(hosts)} host lookup(s)", duration_ms=int((time.monotonic() - t0) * 1000)))
    except PermissionError as e:
        out.checks.append(CheckResult(name="intel.urlhaus", module=Module.intel, status=CheckStatus.unavailable, essential=False, detail=str(e)))
    except Exception as e:
        out.checks.append(CheckResult(name="intel.urlhaus", module=Module.intel, status=CheckStatus.failed, essential=False,
                                      detail=f"{type(e).__name__}: {str(e)[:120]}", duration_ms=int((time.monotonic() - t0) * 1000)))
    return out
