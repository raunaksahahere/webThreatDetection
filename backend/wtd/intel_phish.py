"""Two additional phishing/malware intelligence sources behind `intel.lookup`: Google Safe Browsing and OpenPhish.

Google Safe Browsing (Lookup API v4), https://developers.google.com/safe-browsing/v4/lookup-api
- Needs the server's GSB_API_KEY (sent in the X-Goog-Api-Key header, never in a URL, so it cannot leak through an error message).
- Terms (https://developers.google.com/safe-browsing/v4/usage-limits): non-commercial use only; warnings derived from Google data
  must use qualifying language and carry the line "Advisory provided by Google" linking to the Safe Browsing Advisory; the
  user must be told the protection is not perfect. The report UI adds the attribution to these findings only.
- Privacy: Google receives scheme, host and path of the submitted address and of redirect hosts; never the query string,
  fragment or credentials. A hostname-only entry is sent for redirect destinations.
- Responses are cached for the `cacheDuration` Google returns (positive matches) or a short fixed time (no match).

OpenPhish Community Feed, https://github.com/openphish/public_feed (https://openphish.com/terms.html)
- OFF BY DEFAULT. The terms restrict the feed to personal, non-commercial research and forbid disclosing the data to third
  parties and using it for detection or automation inside an organisation. A public demo that shows listings to visitors does
  not clearly fit, so an operator must set WTD_OPENPHISH=1 after confirming their own use qualifies. When off, the check is
  recorded as skipped ("not checked"), never as "no match".
- Matching is local against a snapshot (nothing about a lookup leaves this machine). The snapshot is fetched in the
  background at most once an hour with a conditional request, kept under data/ (gitignored) and never redistributed.

A no-match from either source means "not listed" (unknown), never "clean".
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import httpx

from .checks.url_rules import official_brand_for, split_domain
from .models import CheckResult, CheckStatus, Finding, Module, Provenance, Severity, Strength, iso
from .netguard import defang

PROJECT_DATA = Path(__file__).resolve().parents[2] / "data"
UA = "WTD-Intel/0.2 (non-commercial prototype)"

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GSB_ADVISORY = "https://developers.google.com/safe-browsing/v4/advisory"
GSB_SOURCE = "Google Safe Browsing (Lookup API v4)"
GSB_TIMEOUT = httpx.Timeout(connect=3.0, read=5.0, write=3.0, pool=3.0)
GSB_MAX_BYTES = 256_000
GSB_NEG_TTL = 300
GSB_POS_TTL_MIN, GSB_POS_TTL_MAX = 60, 1800
GSB_MAX_ENTRIES = 7
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
THREAT_INFO = {  # threat type -> (qualified description, severity, strength)
    "SOCIAL_ENGINEERING": ("a suspected phishing or deceptive page", Severity.critical, Strength.authoritative),
    "MALWARE": ("a suspected malware-distribution page", Severity.critical, Strength.authoritative),
    "UNWANTED_SOFTWARE": ("a page suspected of distributing unwanted software", Severity.high, Strength.strong),
    "POTENTIALLY_HARMFUL_APPLICATION": ("a page potentially distributing harmful applications", Severity.high, Strength.strong),
}

OP_DEFAULT_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
OP_MIN_REFRESH_S = 3600
OP_FRESH_H = 36  # the feed updates every 12 hours; three missed cycles is stale
OP_MAX_AGE_H = 7 * 24  # beyond this the snapshot is not used at all
OP_MAX_BYTES = 10_000_000
OP_MAX_LINES = 200_000


class SourceUnavailable(Exception):
    """Could not be used now: not configured, rate limited, provider down or key rejected."""


class SourceMalformed(Exception):
    """The provider answered with something we cannot parse or attribute."""


@dataclass
class PhishOutcome:
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    matches: list[dict] = field(default_factory=list)


def _finding(id_: str, code: str, title: str, observed: str, evidence: dict, source: str, prov: Provenance, sev: Severity,
             strength: Strength, impact: str, rec: str, limit: str) -> Finding:
    return Finding(id=id_, code=code, module=Module.intel, title=title, observed=observed, evidence=evidence, source=source,
                   provenance=prov, observed_at=iso(), severity=sev, strength=strength, impact=impact, recommendation=rec, limitation=limit)


# =========================================================================== Safe Browsing
def gsb_key() -> str | None:
    return os.environ.get("GSB_API_KEY", "").strip() or None


def lookup_entry(href: str) -> str | None:
    """What Google may see for a full address: scheme, host and path. No query, fragment or credentials."""
    s = urlsplit(href)
    if s.scheme not in ("http", "https") or not s.hostname:
        return None
    host = s.hostname.lower()
    host = f"[{host}]" if ":" in host else host
    path = s.path or "/"
    if len(path) > 512:
        return None
    return f"{s.scheme}://{host}{':%d' % s.port if s.port else ''}{path}"


def _host_entry(host: str) -> str:
    return f"http://{host}/"


class SafeBrowsing:
    def __init__(self, transport: httpx.BaseTransport | None = None, clock: Callable[[], float] = time.time):
        self.transport, self.clock = transport, clock
        self.cache: dict[str, tuple[float, list[dict]]] = {}  # entry -> (expires, matches)
        self.calls: list[float] = []
        self.blocked_until = 0.0
        self.lock = threading.Lock()

    @staticmethod
    def limits() -> tuple[int, int]:
        return int(os.environ.get("GSB_MAX_PER_MIN", "30")), int(os.environ.get("GSB_DAILY_BUDGET", "2000"))

    def _spend(self) -> None:
        now = self.clock()
        per_min, per_day = self.limits()
        with self.lock:
            if self.blocked_until > now:
                raise SourceUnavailable("Safe Browsing asked us to back off (HTTP 429); will retry later")
            self.calls = [t for t in self.calls if now - t < 86400]
            if len(self.calls) >= per_day:
                raise SourceUnavailable(f"local daily budget of {per_day} Safe Browsing requests is used up")
            if sum(1 for t in self.calls if now - t < 60) >= per_min:
                raise SourceUnavailable(f"local limit of {per_min} Safe Browsing requests per minute reached")
            self.calls.append(now)

    def check(self, entries: list[str], key: str) -> dict[str, list[dict]]:
        """Matches per entry. Raises SourceUnavailable or SourceMalformed."""
        entries = list(dict.fromkeys(entries))[:GSB_MAX_ENTRIES]
        now = self.clock()
        out: dict[str, list[dict]] = {}
        todo = []
        with self.lock:
            for e in entries:
                hit = self.cache.get(e)
                if hit and hit[0] > now:
                    out[e] = [{**m, "cached": True} for m in hit[1]]
                else:
                    todo.append(e)
        if not todo:
            return out
        self._spend()
        body = {"client": {"clientId": "wtd-prototype", "clientVersion": "0.2"},
                "threatInfo": {"threatTypes": THREAT_TYPES, "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                               "threatEntries": [{"url": e} for e in todo]}}
        try:
            with httpx.Client(timeout=GSB_TIMEOUT, transport=self.transport, follow_redirects=False,
                              headers={"User-Agent": UA, "X-Goog-Api-Key": key}) as c:
                with c.stream("POST", GSB_URL, json=body) as r:
                    if r.status_code == 429:
                        with self.lock:
                            self.blocked_until = self.clock() + 60
                        raise SourceUnavailable("Safe Browsing rate limit (HTTP 429)")
                    if r.status_code in (400, 401, 403):
                        raise SourceUnavailable(f"Safe Browsing rejected the server's API key or request (HTTP {r.status_code})")
                    if r.status_code >= 500:
                        raise SourceUnavailable(f"Safe Browsing unavailable (HTTP {r.status_code})")
                    if r.status_code != 200:
                        raise SourceMalformed(f"unexpected HTTP {r.status_code}")
                    raw = bytearray()
                    for chunk in r.iter_bytes():
                        raw += chunk
                        if len(raw) > GSB_MAX_BYTES:
                            raise SourceMalformed("response too large")
        except httpx.TimeoutException as e:
            raise SourceUnavailable("Safe Browsing timed out") from e
        except httpx.HTTPError as e:
            raise SourceUnavailable(f"Safe Browsing unreachable ({type(e).__name__})") from e
        try:
            data = json.loads(bytes(raw))
        except ValueError as e:
            raise SourceMalformed("response is not JSON") from e
        if not isinstance(data, dict):
            raise SourceMalformed("response is not an object")
        found: dict[str, list[dict]] = {e: [] for e in todo}
        ttl: dict[str, int] = {}
        for m in data.get("matches") or []:
            if not isinstance(m, dict) or not isinstance(m.get("threat"), dict):
                raise SourceMalformed("match without a threat entry")
            url, tt = m["threat"].get("url"), m.get("threatType")
            if url not in found or tt not in THREAT_INFO:
                raise SourceMalformed("match for an address we did not ask about, or an unknown threat type")
            dur = str(m.get("cacheDuration") or "")
            secs = int(float(dur[:-1])) if dur.endswith("s") and dur[:-1].replace(".", "", 1).isdigit() else GSB_POS_TTL_MIN
            ttl[url] = min(max(ttl.get(url, GSB_POS_TTL_MIN), secs), GSB_POS_TTL_MAX)
            found[url].append({"threat_type": tt, "platform": str(m.get("platformType") or "")[:40], "entry_type": str(m.get("threatEntryType") or "")[:20],
                               "cache_duration_s": secs})
        with self.lock:
            for e, ms in found.items():
                self.cache[e] = (now + (ttl.get(e, GSB_POS_TTL_MIN) if ms else GSB_NEG_TTL), ms)
            if len(self.cache) > 2000:
                self.cache.clear()
        out.update(found)
        return out


GSB = SafeBrowsing()


def lookup_gsb(url: str | None, hosts: list[str], remote: bool, client: SafeBrowsing | None = None) -> PhishOutcome:
    client = client or GSB
    out = PhishOutcome()
    name = "intel.gsb"
    if not remote:
        out.checks.append(CheckResult(name=name, module=Module.intel, status=CheckStatus.skipped, essential=False,
                                      detail="not queried in quick-check mode (no third-party lookups for browsing)"))
        return out
    key = gsb_key()
    if not key:
        out.checks.append(CheckResult(name=name, module=Module.intel, status=CheckStatus.unavailable, essential=False,
                                      detail="GSB_API_KEY not configured on the server; not checked"))
        return out
    entries: list[tuple[str, str, str]] = []  # (kind, host, entry)
    if url and (e := lookup_entry(url)):
        entries.append(("url", urlsplit(url).hostname or "", e))
    url_host = (urlsplit(url).hostname or "").lower() if url else ""
    # A URL lookup already covers the host-level expression of that URL, so only other hosts (e.g. redirect destinations) are added.
    entries += [("host", h, _host_entry(h)) for h in hosts[:GSB_MAX_ENTRIES - 1] if h and h.lower() != url_host]
    t0 = time.monotonic()
    ms = lambda: int((time.monotonic() - t0) * 1000)
    if not entries:
        out.checks.append(CheckResult(name=name, module=Module.intel, status=CheckStatus.skipped, essential=False, detail="nothing to look up"))
        return out
    try:
        res = client.check([e for _, _, e in entries], key)
    except SourceUnavailable as e:
        out.checks.append(CheckResult(name=name, module=Module.intel, status=CheckStatus.unavailable, essential=False,
                                      detail=f"{e}. Not checked; status unknown, not a risk signal.", duration_ms=ms()))
        return out
    except SourceMalformed as e:
        out.checks.append(CheckResult(name=name, module=Module.intel, status=CheckStatus.failed, essential=False,
                                      detail=f"unusable response: {e}", duration_ms=ms()))
        return out
    any_hit = False
    for kind, host, entry in entries:
        for m in res.get(entry, []):
            any_hit = True
            desc, sev, strength = THREAT_INFO[m["threat_type"]]
            scope = "this exact address" if kind == "url" else f"the host '{host}'"
            out.matches.append({"source": "Google Safe Browsing", "host": host, "threat_type": m["threat_type"]})
            out.findings.append(_finding(
                f"intel.gsb:{kind}:{host}:{m['threat_type']}", "intel.gsb_listed", f"Google Safe Browsing flags {scope} as {desc}",
                f"Google Safe Browsing reports a match for {scope} ({defang(entry)}), threat type {m['threat_type']} "
                f"({'platform ' + m['platform'] if m['platform'] else 'any platform'}). Advisory provided by Google.",
                {"entry": defang(entry), "scope": kind, "threat_type": m["threat_type"], "platform": m["platform"],
                 "cache_duration_s": m["cache_duration_s"], "cached": bool(m.get("cached")), "advisory": "Advisory provided by Google",
                 "advisory_url": GSB_ADVISORY},
                GSB_SOURCE, Provenance.cached if m.get("cached") else Provenance.live, sev, strength,
                "Google's Safe Browsing service currently lists this destination as unsafe.",
                "Do not visit or enter any information. Report it if it reached you in a message.",
                "Safe Browsing is not perfect: some unsafe sites are missed and some safe sites are listed in error. "
                "Only scheme, host and path were sent to Google. The result is valid as of the lookup time."))
    if not any_hit:
        out.findings.append(_finding(
            "intel.gsb_nohit", "intel.no_listing", "Not listed by Google Safe Browsing (unknown, not clean)",
            f"Safe Browsing has no match for {len(entries)} checked address(es).", {"checked": len(entries)}, GSB_SOURCE, Provenance.live,
            Severity.info, Strength.weak, "No conclusion: absence from a blocklist is not evidence of safety.",
            "Absence from a list is not evidence of safety.", "Not perfect: unsafe sites can be missing, and brand-new pages are listed with a delay."))
    out.checks.append(CheckResult(name=name, module=Module.intel, status=CheckStatus.succeeded, essential=False,
                                  detail=f"{len(entries)} address(es) checked", duration_ms=ms()))
    return out


# =========================================================================== OpenPhish
def openphish_enabled() -> bool:
    return os.environ.get("WTD_OPENPHISH", "") == "1"


def feed_key(href: str) -> str | None:
    """Scheme-insensitive exact-URL key: host (lowercase), port, path and query; no fragment, userinfo or trailing-slash difference."""
    try:
        s = urlsplit(href.strip())
    except ValueError:
        return None
    if s.scheme.lower() not in ("http", "https") or not s.hostname:
        return None
    path = s.path.rstrip("/") or ""
    return f"{s.hostname.lower().rstrip('.')}{':%d' % s.port if s.port else ''}{path}{'?' + s.query if s.query else ''}"


def parse_feed(text: str) -> tuple[set[str], dict[str, int], int]:
    """(exact-URL keys, host -> listed URL count, number of malformed lines). Unparseable lines are counted, never trusted."""
    keys: set[str] = set()
    hosts: dict[str, int] = {}
    bad = 0
    for i, line in enumerate(text.splitlines()):
        if i >= OP_MAX_LINES:
            break
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k = feed_key(line)
        if not k or len(line) > 2048:
            bad += 1
            continue
        keys.add(k)
        h = urlsplit(line).hostname.lower().rstrip(".")  # type: ignore[union-attr]
        hosts[h] = hosts.get(h, 0) + 1
    return keys, hosts, bad


class OpenPhishFeed:
    def __init__(self, path: Path | None = None, url: str | None = None, transport: httpx.BaseTransport | None = None,
                 clock: Callable[[], float] = time.time):
        self.path = path or PROJECT_DATA / "openphish_feed.txt"
        self.meta_path = self.path.with_suffix(".json")
        self.url = url or os.environ.get("OPENPHISH_FEED_URL", OP_DEFAULT_URL)
        self.transport, self.clock = transport, clock
        self.keys: set[str] = set()
        self.hosts: dict[str, int] = {}
        self.bad_lines = 0
        self.fetched_at: float | None = None
        self.error: str | None = None
        self.last_attempt = 0.0
        self.lock = threading.Lock()
        self._busy = False

    def load_local(self) -> None:
        with self.lock:
            if self.keys or not self.path.exists():
                return
            try:
                self.keys, self.hosts, self.bad_lines = parse_feed(self.path.read_text(errors="ignore"))
                meta = json.loads(self.meta_path.read_text()) if self.meta_path.exists() else {}
                self.fetched_at = float(meta.get("fetched_at") or self.path.stat().st_mtime)
            except (OSError, ValueError):
                self.keys, self.hosts = set(), {}
                self.error = "local snapshot unreadable"

    def refresh(self) -> bool:
        """Conditional fetch, at most once per OP_MIN_REFRESH_S. Returns True when the snapshot changed or was confirmed current."""
        now = self.clock()
        with self.lock:
            if now - self.last_attempt < OP_MIN_REFRESH_S:
                return False
            self.last_attempt = now
        etag = None
        try:
            etag = json.loads(self.meta_path.read_text()).get("etag") if self.meta_path.exists() else None
        except (OSError, ValueError):
            pass
        headers = {"User-Agent": UA, **({"If-None-Match": etag} if etag else {})}
        try:
            with httpx.Client(timeout=httpx.Timeout(10, read=30), transport=self.transport, headers=headers, follow_redirects=True) as c:
                with c.stream("GET", self.url) as r:
                    if r.status_code == 304:
                        self._touch(etag)
                        return True
                    if r.status_code != 200:
                        raise SourceUnavailable(f"HTTP {r.status_code}")
                    raw = bytearray()
                    for chunk in r.iter_bytes():
                        raw += chunk
                        if len(raw) > OP_MAX_BYTES:
                            raise SourceMalformed("feed larger than limit")
                    new_etag = r.headers.get("etag")
            keys, hosts, bad = parse_feed(bytes(raw).decode("utf-8", "ignore"))
            if not keys:
                raise SourceMalformed("feed contained no usable URLs")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_bytes(bytes(raw))
            tmp.replace(self.path)
            with self.lock:
                self.keys, self.hosts, self.bad_lines, self.error = keys, hosts, bad, None
            self._touch(new_etag)
            return True
        except (SourceUnavailable, SourceMalformed, httpx.HTTPError, OSError) as e:
            with self.lock:
                self.error = f"refresh failed: {type(e).__name__}: {str(e)[:80]}"
            return False

    def _touch(self, etag: str | None) -> None:
        with self.lock:
            self.fetched_at = self.clock()
        try:
            self.meta_path.write_text(json.dumps({"fetched_at": self.fetched_at, "etag": etag}))
        except OSError:
            pass

    def refresh_async(self) -> None:
        if self._busy or self.clock() - self.last_attempt < OP_MIN_REFRESH_S:
            return
        self._busy = True

        def run():
            try:
                self.refresh()
            finally:
                self._busy = False

        threading.Thread(target=run, daemon=True, name="openphish-refresh").start()

    def age_hours(self) -> float | None:
        return None if self.fetched_at is None else (self.clock() - self.fetched_at) / 3600


OPENPHISH = OpenPhishFeed()


def lookup_openphish(url: str | None, hosts: list[str], shared_hosting: set[str], feed: OpenPhishFeed | None = None) -> PhishOutcome:
    feed = feed or OPENPHISH
    out = PhishOutcome()
    name = "intel.openphish"
    if not openphish_enabled():
        out.checks.append(CheckResult(
            name=name, module=Module.intel, status=CheckStatus.skipped, essential=False,
            detail="not checked: disabled (the OpenPhish Community Feed terms restrict use to personal, non-commercial research; "
                   "an operator must set WTD_OPENPHISH=1 after confirming that their use qualifies)"))
        return out
    feed.load_local()
    feed.refresh_async()
    age = feed.age_hours()
    if not feed.keys or age is None:
        out.checks.append(CheckResult(name=name, module=Module.intel, status=CheckStatus.unavailable, essential=False,
                                      detail=(feed.error or "feed snapshot not downloaded yet") + ". Not checked; status unknown, not a risk signal."))
        return out
    if age > OP_MAX_AGE_H:
        out.checks.append(CheckResult(name=name, module=Module.intel, status=CheckStatus.unavailable, essential=False,
                                      detail=f"snapshot is {int(age // 24)} days old, too old to use. Not checked."))
        return out
    stale = age > OP_FRESH_H
    snap = iso(datetime.fromtimestamp(feed.fetched_at or 0, timezone.utc))
    prov = Provenance.dataset
    ev_base = {"snapshot_time": snap, "snapshot_age_hours": int(age), "stale": stale, "feed_urls": len(feed.keys)}
    src = "OpenPhish Community Feed (openphish.com)"
    limit = ("The community feed is a limited, delayed subset of OpenPhish data, refreshed about every 12 hours; matching is against a local snapshot. "
             "Not being listed is not evidence of safety." + (f" The snapshot is {int(age)} hours old (stale), so a match is treated as strong, not authoritative." if stale else ""))
    hit = False
    exact = feed_key(url) if url else None
    if exact and exact in feed.keys:
        hit = True
        out.matches.append({"source": "OpenPhish", "exact": True})
        out.findings.append(_finding(
            "intel.openphish_url", "intel.openphish_url_listed", "Exact URL is listed in the OpenPhish community phishing feed",
            f"The submitted address is in the OpenPhish community feed snapshot taken {snap}{' (stale)' if stale else ''}.",
            {**ev_base, "match": "exact URL", "category": "phishing"}, src, prov, Severity.critical,
            Strength.strong if stale else Strength.authoritative, "This address has been reported as a phishing page.",
            "Do not visit or enter any information.", limit))
    for h in hosts:
        n = feed.hosts.get(h)
        if not n or (exact and exact in feed.keys and h == (urlsplit(url).hostname or "").lower()):
            continue  # an exact URL match already covers its own host: do not count the same listing twice
        reg = split_domain(h).registrable
        platform = h in shared_hosting or reg in shared_hosting or official_brand_for(reg) is not None or n >= 1000
        hit = True
        sev, strength = (Severity.info, Strength.weak) if platform else (Severity.high, Strength.strong)
        out.matches.append({"source": "OpenPhish", "host": h, "listed_urls": n})
        out.findings.append(_finding(
            f"intel.openphish_host:{h}", "intel.openphish_host_listed",
            "Other phishing URLs on this host are listed by OpenPhish" if not platform else "A shared platform hosts some listed phishing pages (OpenPhish context)",
            f"The OpenPhish community feed lists {n} phishing URL(s) on '{h}'" + ("; this exact URL is not among them." if url else "."),
            {**ev_base, "match": "host", "host": h, "listed_urls": n, "platform": platform, "category": "phishing"}, src, prov, sev, strength,
            "The host has been used for phishing." if not platform else "Only specific pages on this platform are implicated, not the platform itself.",
            "Treat other pages on this host with suspicion." if not platform else "Be careful with links on this platform.",
            limit + " A host-level match does not show that this page is phishing."))
    if not hit:
        out.findings.append(_finding(
            "intel.openphish_nohit", "intel.no_listing", "Not in the OpenPhish community feed (unknown, not clean)",
            f"No match in the snapshot of {len(feed.keys)} URLs taken {snap}{' (stale)' if stale else ''}.", ev_base, src, prov, Severity.info,
            Strength.weak, "No conclusion: the community feed is a limited subset.", "Absence from a list is not evidence of safety.", limit))
    status = CheckStatus.inconclusive if stale and not hit else CheckStatus.succeeded
    out.checks.append(CheckResult(
        name=name, module=Module.intel, status=status, essential=False,
        detail=f"{len(feed.keys)} URLs, snapshot {snap}" + (f"; STALE ({int(age)} h old)" + ("; a no-match cannot be concluded" if not hit else "") if stale else "")
               + (f"; {feed.error}" if feed.error else "")))
    return out


def lookup(url: str | None, hosts: list[str], shared_hosting: set[str], remote: bool) -> PhishOutcome:
    """Both sources. OpenPhish is local-only so it also runs in quick-check mode; Safe Browsing needs a third-party request."""
    a = lookup_gsb(url, hosts, remote)
    b = lookup_openphish(url, hosts, shared_hosting)
    return PhishOutcome(a.findings + b.findings, a.checks + b.checks, a.matches + b.matches)
