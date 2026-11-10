"""Certificate Transparency record lookup (an aggregator query, not log verification).

What this does: asks a public CT-monitoring service which publicly logged certificates it holds for the
site's hostname, and whether the certificate the server actually presented is among them.
Sources, in order: Cert Spotter (SSLMate) issuance API, then crt.sh (Sectigo) as a fallback.

What this does NOT do: verify an SCT signature, check a Merkle inclusion proof, or talk to a CT log. The
aggregators' own indexes are trusted as a source of records, and they can lag behind the logs. The embedded
SCTs in the certificate are inspected separately in `tls_checks.py`.

Evidence handling:
- Only the hostname of a site that was actually contacted is sent (no URL, path or query), to the two fixed
  hosts below. Nothing user-controlled selects the endpoint.
- Network time, response size, pages followed and result count are bounded; results are cached; an hourly request
  budget keeps us under the providers' anonymous rate limits. Cert Spotter's terms allow anonymous queries for personal or
  evaluation use; set CERTSPOTTER_API_KEY to use an account instead.
- Duplicates (a precertificate and its final certificate, or the same certificate from several logs) are merged.
- A wildcard certificate counts as covering a host only when the wildcard matches exactly one label.
- Outcomes are explicit: succeeded, inconclusive (partial or contradictory data), unavailable (could not be
  reached or rate limited), failed (a response could not be parsed), skipped (disabled or not applicable).
- No outcome of this check alone raises a site's risk class: absence of records, several certificates or a recent
  issue date are context, and the one weak signal is described in `_leaf_not_listed`.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

import httpx

from ..models import CheckResult, CheckStatus, Finding, Module, Provenance, Severity, Strength, iso

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CRTSH_URL = "https://crt.sh/"
UA = "WTD-CT/0.2 (non-commercial prototype)"
TIMEOUT = httpx.Timeout(connect=3.0, read=5.0, write=3.0, pool=3.0)
MAX_BYTES = 2_000_000  # per response
MAX_ENTRIES = 100  # per response; parsing stops here
MAX_PAGES = 3  # Cert Spotter pages followed per name; still more data after this means the picture is partial
PAGE_FULL_MIN = 60  # Cert Spotter does not document its page size; a response observed with 65 entries means a page with fewer is the last one
CACHE_OK_S = 6 * 3600
CACHE_EMPTY_S = 30 * 60  # new certificates appear in the aggregators within minutes to hours
HOURLY_BUDGET = 60  # Cert Spotter allows 100 anonymous requests per hour; keep headroom
LAG_GRACE = timedelta(hours=72)  # a certificate younger than this may simply not be indexed yet
RECENT_DAYS = 14
NAME_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


class CtUnavailable(Exception):
    """The source could not be used right now (timeout, 5xx, rate limit, budget)."""


class CtMalformed(Exception):
    """The source answered, but the answer could not be parsed or was too large."""


@dataclass
class CtEntry:
    source: str
    dns_names: list[str]
    issuer: str
    not_before: datetime
    not_after: datetime
    cert_sha256: str | None = None
    tbs_sha256: str | None = None
    spki_sha256: str | None = None
    serial: str | None = None
    ref: str | None = None  # provider's record id (used only for pagination)

    def key(self) -> tuple:
        # A precertificate and its final certificate share the TBS hash (Cert Spotter) or serial + issuer + validity (crt.sh).
        if self.tbs_sha256:
            return ("tbs", self.tbs_sha256)
        if self.serial:
            return ("serial", self.serial, self.issuer, self.not_before, self.not_after)
        return ("sha", self.cert_sha256, self.spki_sha256, self.not_before, self.not_after)


@dataclass
class CtResult:
    source: str
    entries: list[CtEntry]
    queried: list[str]
    partial: bool
    fetched_at: float
    cached: bool = False
    notes: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ parsing
def _dt(v: object) -> datetime:
    if not isinstance(v, str) or not v:
        raise CtMalformed("missing timestamp")
    t = v.strip().replace(" ", "T")
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        d = datetime.fromisoformat(t)
    except ValueError as e:
        raise CtMalformed(f"bad timestamp {v[:30]!r}") from e
    return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)


def _hex(v: object, n: int) -> str | None:
    if isinstance(v, str) and len(v) == n and re.fullmatch(r"[0-9a-fA-F]+", v):
        return v.lower()
    return None


def _names(raw: object) -> list[str]:
    out = []
    for n in raw if isinstance(raw, list) else str(raw or "").split("\n"):
        if isinstance(n, str):
            n = n.strip().lower().rstrip(".")
            if NAME_RE.match(n):
                out.append(n)
    return list(dict.fromkeys(out))[:200]


def _norm_serial(v: object) -> str | None:
    if isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F]+", v):
        return v.lower().lstrip("0") or "0"
    return None


def parse_certspotter(body: bytes) -> list[CtEntry]:
    try:
        data = json.loads(body)
    except ValueError as e:
        raise CtMalformed("Cert Spotter response is not JSON") from e
    if not isinstance(data, list):
        raise CtMalformed("Cert Spotter response is not a list")
    out = []
    for e in data[:MAX_ENTRIES]:
        if not isinstance(e, dict):
            raise CtMalformed("Cert Spotter entry is not an object")
        issuer = e.get("issuer") if isinstance(e.get("issuer"), dict) else {}
        out.append(CtEntry(source="Cert Spotter", ref=str(e.get("id") or "")[:40] or None, dns_names=_names(e.get("dns_names")), issuer=str(issuer.get("name") or "")[:200],
                           not_before=_dt(e.get("not_before")), not_after=_dt(e.get("not_after")),
                           cert_sha256=_hex(e.get("cert_sha256"), 64), tbs_sha256=_hex(e.get("tbs_sha256"), 64),
                           spki_sha256=_hex(e.get("pubkey_sha256"), 64)))
    return out


def parse_crtsh(body: bytes) -> list[CtEntry]:
    try:
        data = json.loads(body)
    except ValueError as e:
        raise CtMalformed("crt.sh response is not JSON (possibly truncated)") from e
    if not isinstance(data, list):
        raise CtMalformed("crt.sh response is not a list")
    out = []
    for e in data[:MAX_ENTRIES]:
        if not isinstance(e, dict):
            raise CtMalformed("crt.sh entry is not an object")
        out.append(CtEntry(source="crt.sh", dns_names=_names(e.get("name_value")) or _names([e.get("common_name")]),
                           issuer=str(e.get("issuer_name") or "")[:200], not_before=_dt(e.get("not_before")),
                           not_after=_dt(e.get("not_after")), serial=_norm_serial(e.get("serial_number"))))
    return out


def dedupe(entries: list[CtEntry]) -> list[CtEntry]:
    seen: dict[tuple, CtEntry] = {}
    for e in entries:
        k = e.key()
        if k not in seen:
            seen[k] = e
        else:  # keep the richer record (one that has a hash we can match on)
            old = seen[k]
            for attr in ("cert_sha256", "spki_sha256", "serial"):
                if not getattr(old, attr) and getattr(e, attr):
                    setattr(old, attr, getattr(e, attr))
    return sorted(seen.values(), key=lambda e: e.not_before)


def covers(host: str, names: list[str]) -> bool:
    """True when one of the certificate names covers the host. A wildcard covers exactly one label."""
    host = host.lower().rstrip(".")
    for n in names:
        if n == host:
            return True
        if n.startswith("*."):
            suffix = n[1:]  # ".example.com"
            if host.endswith(suffix) and "." not in host[: -len(suffix)] and host[: -len(suffix)]:
                return True
    return False


# ------------------------------------------------------------------ client
class CtClient:
    def __init__(self, transport: httpx.BaseTransport | None = None, clock: Callable[[], float] = time.time,
                 hourly_budget: int = HOURLY_BUDGET):
        self.transport = transport
        self.clock = clock
        self.hourly_budget = hourly_budget
        self.cache: dict[str, tuple[float, float, CtResult]] = {}  # name -> (stored, ttl, result)
        self.calls: list[float] = []
        self.blocked_until: dict[str, float] = {}
        self.lock = threading.Lock()

    def _spend(self, source: str) -> None:
        now = self.clock()
        with self.lock:
            if self.blocked_until.get(source, 0) > now:
                raise CtUnavailable(f"{source} asked us to wait (rate limited)")
            self.calls = [t for t in self.calls if now - t < 3600]
            if len(self.calls) >= self.hourly_budget:
                raise CtUnavailable("hourly request budget for CT lookups is used up")
            self.calls.append(now)

    def _get(self, source: str, url: str, params: dict[str, str], headers: dict[str, str] | None = None) -> tuple[bytes, httpx.Headers]:
        self._spend(source)
        try:
            with httpx.Client(timeout=TIMEOUT, transport=self.transport, follow_redirects=False, headers={"User-Agent": UA, **(headers or {})}) as c:
                with c.stream("GET", url, params=params) as r:
                    if r.status_code == 429:
                        wait = r.headers.get("retry-after", "")
                        with self.lock:
                            self.blocked_until[source] = self.clock() + (int(wait) if wait.isdigit() else 900)
                        raise CtUnavailable(f"{source} rate limit (HTTP 429)")
                    if r.status_code >= 500 or r.status_code in (401, 403, 408):
                        raise CtUnavailable(f"{source} unavailable (HTTP {r.status_code})")
                    if r.status_code != 200:
                        raise CtMalformed(f"{source} returned HTTP {r.status_code}")
                    buf = bytearray()
                    for chunk in r.iter_bytes():
                        buf += chunk
                        if len(buf) > MAX_BYTES:
                            raise CtMalformed(f"{source} response larger than {MAX_BYTES // 1000} KB")
                    return bytes(buf), r.headers
        except httpx.TimeoutException as e:
            raise CtUnavailable(f"{source} timed out") from e
        except httpx.HTTPError as e:
            raise CtUnavailable(f"{source} unreachable ({type(e).__name__})") from e

    def _certspotter(self, name: str) -> CtResult:
        """Cert Spotter returns wildcard certificates matching `name` itself (match_wildcards). Pages are followed until a
        short page (the last one) or MAX_PAGES; a still-full last page means the history is partial."""
        key = os.environ.get("CERTSPOTTER_API_KEY", "").strip()
        headers = {"Authorization": f"Bearer {key}"} if key else None
        entries: list[CtEntry] = []
        after = ""
        partial = False
        for page in range(MAX_PAGES):
            params = {"domain": name, "include_subdomains": "false", "match_wildcards": "true", "expand": "dns_names"}
            if after:
                params["after"] = after
            body, _ = self._get("Cert Spotter", CERTSPOTTER_URL, params, headers)
            got = parse_certspotter(body)
            entries += got
            if len(got) < PAGE_FULL_MIN or not got[-1].ref:
                break
            after = got[-1].ref
            partial = page == MAX_PAGES - 1  # a full page at the page cap: there may be more
        return CtResult("Cert Spotter", entries, [name], partial, self.clock())

    def _crtsh(self, name: str, wildcard_base: str | None = None) -> CtResult:
        """crt.sh does not match wildcards for a name, so the wildcard's base name is queried too when the presented certificate needs it."""
        entries: list[CtEntry] = []
        queried = [name] + ([wildcard_base] if wildcard_base else [])
        for q in queried:
            body, _ = self._get("crt.sh", CRTSH_URL, {"q": q, "output": "json", "deduplicate": "Y"})
            entries += parse_crtsh(body)
        return CtResult("crt.sh", entries, queried, len(entries) >= MAX_ENTRIES, self.clock())

    def lookup(self, name: str, wildcard_base: str | None = None) -> CtResult:
        """Records covering one exact name. Tries Cert Spotter, then crt.sh. Raises CtUnavailable or CtMalformed."""
        now = self.clock()
        ck = f"{name}|{wildcard_base or ''}"
        with self.lock:
            hit = self.cache.get(ck)
        if hit and now - hit[0] < hit[1]:
            return CtResult(hit[2].source, hit[2].entries, hit[2].queried, hit[2].partial, hit[2].fetched_at, cached=True, notes=hit[2].notes)
        errors: list[Exception] = []
        for fn in (lambda: self._certspotter(name), lambda: self._crtsh(name, wildcard_base)):
            try:
                res = fn()
            except (CtUnavailable, CtMalformed) as e:
                errors.append(e)
                continue
            if errors:
                res.notes.append(f"fell back after: {errors[0]}")
            with self.lock:
                self.cache[ck] = (now, CACHE_OK_S if res.entries else CACHE_EMPTY_S, res)
                if len(self.cache) > 500:
                    self.cache.pop(next(iter(self.cache)))
            return res
        if all(isinstance(e, CtMalformed) for e in errors):
            raise errors[0]
        raise CtUnavailable("; ".join(str(e) for e in errors)[:240])


CT = CtClient()


def enabled() -> bool:
    return os.environ.get("WTD_CT", "1") != "0"


# ------------------------------------------------------------------ analysis
@dataclass
class Leaf:
    sha256: str
    spki_sha256: str
    serial: str
    not_before: datetime
    not_after: datetime
    dns_names: list[str]
    sct_count: int
    publicly_trusted: bool


def leaf_from_chain(leaf_der: bytes, tls_summary: dict) -> Leaf:
    """Identifiers of the presented certificate, from the DER captured on the pinned connection and the TLS summary."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    from .tls_checks import spki_sha256

    c = x509.load_der_x509_certificate(leaf_der)
    names = [str(n).lower() for n in (tls_summary.get("leaf_dns_names") or [])]
    return Leaf(sha256=c.fingerprint(hashes.SHA256()).hex(), spki_sha256=spki_sha256(c), serial=format(c.serial_number, "x"),
                not_before=c.not_valid_before_utc, not_after=c.not_valid_after_utc, dns_names=names,
                sct_count=int(tls_summary.get("embedded_scts") or 0), publicly_trusted=tls_summary.get("chain_trusted") is True)


def matches_leaf(e: CtEntry, leaf: Leaf) -> bool:
    if e.cert_sha256 and e.cert_sha256 == leaf.sha256:
        return True
    same_validity = e.not_before.date() == leaf.not_before.date() and e.not_after.date() == leaf.not_after.date()
    if e.spki_sha256 and e.spki_sha256 == leaf.spki_sha256 and same_validity:
        return True
    return bool(e.serial and e.serial == leaf.serial and same_validity)


def _f(code: str, title: str, observed: str, sev: Severity, strength: Strength, impact: str, rec: str, limit: str, ev: dict,
       cached: bool) -> Finding:
    return Finding(id=code, code=code, module=Module.tls, title=title, observed=observed, evidence=ev,
                   source="Certificate Transparency record lookup (" + str(ev.get("source", "")) + ")",
                   provenance=Provenance.cached if cached else Provenance.live, observed_at=iso(), severity=sev, strength=strength,
                   impact=impact, recommendation=rec, limitation=limit)


LIMIT = ("This queries a CT-monitoring service's index of logged certificates. It does not verify SCT signatures or log inclusion "
         "proofs, and the index can lag the logs.")


def analyse(host: str, leaf: Leaf, client: CtClient | None = None, now: datetime | None = None) -> tuple[list[Finding], CheckResult, dict]:
    """Look up CT records for `host` and relate them to the certificate the server presented."""
    client = client or CT
    now = now or datetime.now(timezone.utc)
    t0 = time.monotonic()
    ms = lambda: int((time.monotonic() - t0) * 1000)
    name = "tls.ct_lookup"

    def done(status: CheckStatus, detail: str, findings=None, summary=None):
        return findings or [], CheckResult(name=name, module=Module.tls, status=status, essential=False, detail=detail, duration_ms=ms()), summary or {}

    if not enabled():
        return done(CheckStatus.skipped, "disabled by WTD_CT=0")
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return done(CheckStatus.skipped, "not applicable: the site was reached by IP address, not a hostname")
    except ValueError:
        pass
    if not NAME_RE.match(host):
        return done(CheckStatus.skipped, "not applicable: not a public DNS hostname")

    # Cert Spotter matches wildcard certificates by itself; for crt.sh the base name of the covering wildcard is queried as well.
    base = None
    if host not in leaf.dns_names:
        base = next((n[2:] for n in leaf.dns_names if n.startswith("*.") and covers(host, [n])), None)
    results: list[CtResult] = []
    problems: list[str] = []
    try:
        results.append(client.lookup(host, base))
    except CtUnavailable as e:
        problems.append(str(e))
    except CtMalformed as e:
        problems.append(f"malformed ({e})")
    if not results:
        status = CheckStatus.failed if problems and all("malformed" in p for p in problems) else CheckStatus.unavailable
        return done(status, "no CT records obtained (" + "; ".join(problems)[:240] + "). Status unknown, not a risk signal.")
    names = results[0].queried

    entries = dedupe([e for r in results for e in r.entries])
    covering = [e for e in entries if covers(host, e.dns_names)]
    partial = any(r.partial for r in results) or bool(problems)
    cached = all(r.cached for r in results)
    sources = sorted({r.source for r in results})
    fetched = iso(datetime.fromtimestamp(min(r.fetched_at for r in results), timezone.utc))
    match = next((e for e in covering if matches_leaf(e, leaf)), None)
    issuers: dict[str, int] = {}
    for e in covering:
        issuers[e.issuer] = issuers.get(e.issuer, 0) + 1
    top_issuers = [{"issuer": k, "certificates": v} for k, v in sorted(issuers.items(), key=lambda kv: -kv[1])[:5]]
    first = covering[0].not_before if covering else None
    last = covering[-1].not_before if covering else None
    summary = {"sources": sources, "queried_names": names, "lookup_time": fetched, "certificates": len(covering), "partial": partial,
               "presented_certificate_listed": bool(match), "first_not_before": iso(first) if first else None,
               "last_not_before": iso(last) if last else None, "cached": cached}
    ev = {"source": " + ".join(sources), "queried_names": names, "lookup_time": fetched, "certificates_covering_host": len(covering),
          "distinct_issuers": top_issuers, "earliest_not_before": iso(first) if first else None,
          "latest_not_before": iso(last) if last else None, "presented_certificate_listed": bool(match),
          "partial": partial, "cached": cached, "wildcard_certificates": sum(1 for e in covering if any(n.startswith("*.") for n in e.dns_names)),
          "presented_spki_sha256": leaf.spki_sha256, "notes": [n for r in results for n in r.notes][:3] + problems[:2]}
    findings: list[Finding] = []

    if not covering:
        # Zero records is explained by a private CA (never logged) but contradicts a publicly trusted certificate with embedded SCTs.
        if leaf.publicly_trusted and leaf.sct_count:
            findings.append(_f("tls.ct_no_records", "No CT records found for a certificate that carries CT proofs",
                               f"{' + '.join(sources)} returned no certificates for '{host}', although the presented certificate has {leaf.sct_count} embedded SCT(s).",
                               Severity.info, Strength.weak, "Either the index lags the logs or has no coverage of this name; no conclusion is drawn.",
                               "No action needed from this alone.", LIMIT, ev, cached))
            return findings, CheckResult(name=name, module=Module.tls, status=CheckStatus.inconclusive, essential=False,
                                         detail=f"{' + '.join(sources)}: no records for a name covered by a certificate with SCTs; index may lag. Not a risk signal.",
                                         duration_ms=ms()), summary
        findings.append(_f("tls.ct_no_records", "No public CT records for this name",
                           f"{' + '.join(sources)} holds no certificates for '{host}'.", Severity.info, Strength.weak,
                           "Expected for certificates from private CAs; unusual for a publicly trusted site.",
                           "No action needed from this alone.", LIMIT, ev, cached))
        return findings, CheckResult(name=name, module=Module.tls, status=CheckStatus.succeeded, essential=False,
                                     detail=f"{' + '.join(sources)}: 0 certificates for {host}", duration_ms=ms()), summary

    age = f"; first certificate on record started {first.date()} ({(now - first).days} days ago)" if first else ""
    recent = bool(first and (now - first).days < RECENT_DAYS and not partial)
    findings.append(_f("tls.ct_records", "Certificate Transparency records for this name",
                       f"{' + '.join(sources)} lists {len(covering)} certificate(s) covering '{host}' from {len(issuers)} issuer(s){age}. "
                       f"The presented certificate was {'found' if match else 'not found'} among them"
                       f"{' (results are partial)' if partial else ''}.",
                       Severity.info, Strength.weak,
                       "Shows how long certificates have been issued for this name and by whom; a name with no history is newer than most legitimate services."
                       if recent else "Shows how long certificates have been issued for this name and by whom.",
                       "Use as context only: many certificates, a recent first issue or several issuers are all common for legitimate sites.",
                       LIMIT, ev, cached))

    # The single weak signal: the aggregator has records for this name and a complete picture, the certificate claims to be
    # logged (embedded SCTs) and is old enough to be indexed, yet it is absent. Skipped when there are no embedded SCTs
    # (tls.no_sct already reports that) so correlated evidence is not counted twice.
    old_enough = now - leaf.not_before > LAG_GRACE
    if not match and not partial and leaf.publicly_trusted and leaf.sct_count and old_enough:
        findings.append(_f("tls.ct_leaf_not_listed", "Presented certificate is missing from the CT records",
                           f"'{host}' has {len(covering)} logged certificate(s) in {' + '.join(sources)}, but the one the server presented "
                           f"(public key {leaf.spki_sha256[:16]}…, valid {leaf.not_before.date()} to {leaf.not_after.date()}) is not among them.",
                           Severity.low, Strength.weak,
                           "A certificate that carries CT proofs should normally be indexed within hours; its absence can mean the index lags, or that the certificate "
                           "was issued outside the usual process.",
                           "Treat the site's identity as unverified if other indicators are present.",
                           LIMIT + " Aggregator gaps also cause this.", ev, cached))
        status, detail = CheckStatus.succeeded, f"{len(covering)} certificate(s); presented certificate NOT listed"
    elif partial:
        status, detail = CheckStatus.inconclusive, (f"{len(covering)} certificate(s) retrieved; results are partial ({'; '.join(problems)[:120] or 'more records exist than were retrieved'}), "
                                                    "so absence of the presented certificate and the earliest date cannot be concluded")
    else:
        status = CheckStatus.succeeded
        detail = f"{len(covering)} certificate(s); presented certificate {'listed' if match else 'not listed (too new, or no embedded SCTs; not treated as a signal)'}"
    if cached:
        detail += " (cached)"
    return findings, CheckResult(name=name, module=Module.tls, status=status, essential=False, detail=f"{' + '.join(sources)}: {detail}",
                                 duration_ms=ms()), summary
