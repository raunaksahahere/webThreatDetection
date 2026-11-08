"""Static URL and domain indicators (no network).

Each rule emits a Finding with an explicit strength. Brand-related rules use the curated list in
wtd/data/brands.json; absence of a brand match means "not checked against that brand", not "safe".
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, unquote

import tldextract

from ..models import Finding, Module, Provenance, Severity, Strength, iso
from ..netguard import ParsedUrl, defang

DATA = Path(__file__).resolve().parent.parent / "data"
SOURCE = "wtd.url_rules v1 (static analysis)"
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled PSL snapshot, no network

# Minimal confusable map for Latin lookalikes (Cyrillic, Greek, fullwidth, common digit swaps).
# Extended at runtime by data/confusables_min.json if present.
_CONFUSABLE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "χ": "x", "ε": "e", "υ": "u",
    "ɡ": "g", "ɑ": "a", "ı": "i", "ȷ": "j", "ł": "l", "ø": "o", "ß": "ss",
}
_DIGIT_SWAPS = {"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "8": "b"}
SUSPICIOUS_WORDS = ["login", "signin", "verify", "verification", "secure", "update", "kyc", "account", "wallet", "reward",
                    "bonus", "refund", "unlock", "suspend", "confirm", "billing", "support", "helpdesk", "recover", "claim", "prize"]
# Low-weight signal only. Source for the idea that some TLDs are disproportionately abused:
# Spamhaus "most abused TLDs" statistics and Interisle phishing landscape reports (see RESEARCH.md).
RISKY_TLDS = {"top", "xyz", "icu", "cyou", "rest", "buzz", "monster", "sbs", "cfd", "click", "link", "live", "shop", "online", "site",
              "store", "work", "fit", "gq", "tk", "ml", "cf", "ga", "zip", "mov", "lol", "quest", "bond"}


@lru_cache(maxsize=1)
def brand_data() -> dict:
    return json.loads((DATA / "brands.json").read_text(encoding="utf-8"))


@dataclass(frozen=True)
class DomainParts:
    subdomain: str
    domain: str  # registrable label, e.g. 'example'
    suffix: str  # public suffix, e.g. 'co.in'
    registrable: str  # 'example.co.in' ('' for IPs / unknown suffix)


def split_domain(host: str) -> DomainParts:
    r = _EXTRACT(host)
    reg = f"{r.domain}.{r.suffix}" if r.domain and r.suffix else ""
    return DomainParts(r.subdomain, r.domain, r.suffix, reg)


def skeleton(s: str) -> str:
    """Approximate UTS#39 skeleton for Latin lookalikes: NFKD, strip marks, map confusables."""
    s = unicodedata.normalize("NFKD", s.lower())
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = "".join(_CONFUSABLE.get(c, c) for c in s)
    return s.replace("rn", "m").replace("vv", "w")


def _digit_fold(s: str) -> str:
    return "".join(_DIGIT_SWAPS.get(c, c) for c in s)


def damerau(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def official_brand_for(registrable: str) -> dict | None:
    for b in brand_data()["brands"]:
        if registrable in b["official"]:
            return b
    return None


def _f(code: str, title: str, observed: str, sev: Severity, strength: Strength, impact: str, rec: str, lim: str, ev: dict, n: int = 0) -> Finding:
    return Finding(
        id=code if n == 0 else f"{code}#{n + 1}", code=code, module=Module.url, title=title, observed=observed, evidence=ev,
        source=SOURCE, provenance=Provenance.live, observed_at=iso(), severity=sev, strength=strength, impact=impact,
        recommendation=rec, limitation=lim,
    )


def analyse_url(p: ParsedUrl) -> tuple[list[Finding], dict]:
    """Return (findings, subject facts) for a parsed URL."""
    out: list[Finding] = []
    host = p.host
    facts: dict = {"host": host, "host_unicode": p.host_unicode, "scheme": p.scheme, "port": p.port, "defanged": defang(p.href)}
    if p.is_ip:
        facts.update(registrable_domain="", is_ip=True)
        out.append(_f("url.ip_literal", "URL uses a raw IP address instead of a domain name",
                      f"The host is the IP address {host}.", Severity.medium, Strength.moderate,
                      "Legitimate public services almost always use domain names; raw IPs hide ownership and are common in phishing and malware links.",
                      "Do not enter credentials or payment details on pages reached through an IP-address link.",
                      "Some internal tools and devices legitimately use IP addresses.", {"ip": host}))
    parts = split_domain(host) if not p.is_ip else DomainParts("", "", "", "")
    facts.update(registrable_domain=parts.registrable, subdomain=parts.subdomain, public_suffix=parts.suffix)
    official = official_brand_for(parts.registrable) if parts.registrable else None
    facts["official_brand"] = official["name"] if official else None

    if p.username_present:
        out.append(_f("url.userinfo", "URL hides its real destination behind an '@' (user-info) section",
                      "The URL contains a user-info part before '@'; browsers ignore it and connect to the host after it.",
                      Severity.high, Strength.strong,
                      "Attackers place a trusted name before '@' so the link looks like it goes to that site.",
                      "Treat the link as deceptive. Navigate to the organisation's site by typing its address.",
                      "Rare legitimate uses exist (e.g. FTP-style credentials), but not for public websites.", {"defanged": defang(p.href)}))

    # Homograph / IDN
    is_idn = "xn--" in host
    if is_idn:
        skel_host = skeleton(p.host_unicode or host)
        hit = None
        for b in brand_data()["brands"]:
            for od in b["official"]:
                if skeleton(od) == skel_host or skel_host.endswith("." + skeleton(od)):
                    hit = (b, od)
                    break
            if hit:
                break
            if not hit:
                for t in b["tokens"]:
                    if len(t) >= 4 and t in skeleton(split_domain(p.host_unicode or host).domain) and t not in split_domain(host).domain:
                        hit = (b, t)
                        break
            if hit:
                break
        if hit:
            out.append(_f("url.homograph", f"Internationalised domain imitates {hit[0]['name']}",
                          f"'{p.host_unicode}' (encoded as {host}) uses look-alike Unicode characters that render like '{hit[1]}'.",
                          Severity.critical, Strength.strong,
                          "Homograph domains are visually indistinguishable from the real site and are used for credential theft.",
                          f"Do not use this link. Reach {hit[0]['name']} through its official domain ({', '.join(hit[0]['official'][:2])}).",
                          "Confusable mapping covers common Latin look-alikes, not the full Unicode confusables table.",
                          {"unicode_host": p.host_unicode, "ascii_host": host, "imitates": hit[1]}))
        else:
            scripts = sorted({unicodedata.name(c, "?").split(" ")[0] for c in (p.host_unicode or "") if ord(c) > 127})
            out.append(_f("url.idn", "Domain uses internationalised (non-ASCII) characters",
                          f"Host '{p.host_unicode}' is encoded as {host}.", Severity.low, Strength.weak,
                          "IDNs are legitimate for many languages but can be used to imitate familiar names.",
                          "Check the address carefully against the organisation's known domain.",
                          "No match against the protected brand list; other brands were not checked.", {"unicode_host": p.host_unicode, "scripts": scripts}))

    if parts.registrable and not official:
        label = parts.domain.lower()
        label_skel = _digit_fold(skeleton(label))
        n = 0
        for b in brand_data()["brands"]:
            matched = False
            for od in b["official"]:
                od_label = split_domain(od).domain.lower()
                if len(od_label) < 5 or label == od_label:
                    if label == od_label and parts.registrable not in b["official"]:
                        out.append(_f("url.brand_wrong_suffix", f"Brand name on an unofficial domain ending: imitates {b['name']}",
                                      f"'{parts.registrable}' uses the name '{od_label}' with a different suffix than the official {od}.",
                                      Severity.high, Strength.moderate,
                                      "Same-name domains on other suffixes are a common impersonation technique.",
                                      f"Use {b['name']}'s official domain ({', '.join(b['official'][:2])}).",
                                      "Some brands own many suffixes not in our list; verify before concluding.", {"official": od, "observed": parts.registrable}, n))
                        n += 1
                        matched = True
                        break
                    continue
                dist = damerau(label_skel, od_label)
                if dist <= (1 if len(od_label) < 7 else 2):
                    out.append(_f("url.typosquat", f"Domain is a near-miss spelling of {b['name']}",
                                  f"'{parts.registrable}' differs from the official '{od}' by {dist} character edit(s).",
                                  Severity.high, Strength.strong if dist == 1 else Strength.moderate,
                                  "Typosquatting domains catch users who mistype or misread the real address.",
                                  f"Use {b['name']}'s official domain ({od}).",
                                  "Edit distance can match unrelated legitimate names; the protected-brand list is small.",
                                  {"official": od, "observed": parts.registrable, "edit_distance": dist}, n))
                    n += 1
                    matched = True
                    break
            if matched:
                continue
            tokens_in_label = [t for t in b["tokens"] if len(t) >= 3 and re.search(rf"(^|[^a-z]){re.escape(t)}([^a-z]|$)", label_skel)]
            tokens_in_sub = [t for t in b["tokens"] if len(t) >= 3 and re.search(rf"(^|[^a-z]){re.escape(t)}([^a-z]|$)", parts.subdomain.lower())]
            path_l = unquote(p.path_query).lower()
            tokens_in_path = [t for t in b["tokens"] if len(t) >= 4 and re.search(rf"(^|[^a-z]){re.escape(t)}([^a-z]|$)", path_l)]
            if tokens_in_label:
                out.append(_f("url.brand_in_domain", f"Domain combines the {b['name']} name with other words",
                              f"Registrable domain '{parts.registrable}' contains '{tokens_in_label[0]}' but is not an official {b['name']} domain.",
                              Severity.high, Strength.moderate,
                              "Combo-squatting (brand + 'kyc', 'login', 'update', etc.) is a common phishing pattern.",
                              f"Do not trust the page because it shows {b['name']}'s name; use the official domain.",
                              "Short tokens can match unrelated names; resellers and partners sometimes use brand names legitimately.",
                              {"token": tokens_in_label[0], "official": b["official"][:3]}, n))
                n += 1
            elif tokens_in_sub:
                out.append(_f("url.brand_in_subdomain", f"{b['name']} name used as a subdomain of an unrelated domain",
                              f"Subdomain '{parts.subdomain}' contains '{tokens_in_sub[0]}', but the site actually belongs to '{parts.registrable}'.",
                              Severity.high, Strength.moderate,
                              "Placing a trusted name at the left of a long hostname makes the real owner easy to miss.",
                              f"The site is controlled by {parts.registrable}, not {b['name']}.",
                              "Hosting platforms sometimes give customers brand-like subdomains legitimately.",
                              {"token": tokens_in_sub[0], "registrable": parts.registrable}, n))
                n += 1
            elif tokens_in_path:
                out.append(_f("url.brand_in_path", f"{b['name']} name appears in the path of an unrelated site",
                              f"The path mentions '{tokens_in_path[0]}' while the site belongs to '{parts.registrable}'.",
                              Severity.medium, Strength.weak,
                              "Brand names in paths are used to make links look related to the brand.",
                              "Check who actually owns the domain before entering details.",
                              "Many legitimate pages (news, reviews) mention brands in their paths.",
                              {"token": tokens_in_path[0]}, n))
                n += 1

    bd = brand_data()
    if parts.registrable in bd["shorteners"]:
        out.append(_f("url.shortener", "Link uses a URL shortener", f"'{parts.registrable}' is a link-shortening service.",
                      Severity.low, Strength.weak, "Shorteners hide the final destination; the redirect chain below shows where it leads.",
                      "Check the final destination before trusting the link.", "Shorteners are widely used legitimately.", {"service": parts.registrable}))
    shared = next((s for s in bd["shared_hosting"] if host == s or host.endswith("." + s)), None)
    if shared:
        facts["shared_hosting"] = shared
        out.append(_f("url.shared_hosting", "Site is hosted on a shared platform where anyone can publish",
                      f"The host is under '{shared}'.", Severity.info, Strength.weak,
                      "The platform's reputation says nothing about this particular page; phishing pages are often hosted on such platforms.",
                      "Judge the page by its content and owner, not by the platform's name.",
                      "Most pages on these platforms are legitimate.", {"platform": shared}))

    redirect_params = [k for k, v in parse_qsl(p.path_query.split("?", 1)[1] if "?" in p.path_query else "", keep_blank_values=True)
                       if re.match(r"^(https?:)?//|^https?%3a", v, re.I)]
    if redirect_params:
        out.append(_f("url.embedded_redirect", "URL carries another URL in its parameters",
                      f"Parameter(s) {', '.join(redirect_params[:3])} contain a URL.", Severity.medium, Strength.weak,
                      "Open-redirect parameters let attackers start a link on a trusted domain and end on a malicious one.",
                      "Look at the final destination in the redirect chain.", "Login and tracking flows use such parameters legitimately.",
                      {"params": redirect_params[:5]}))
    hay = (parts.subdomain + "." + parts.domain + " " + unquote(p.path_query)).lower()
    words = [w for w in SUSPICIOUS_WORDS if w in hay]
    if words:
        out.append(_f("url.keywords", "URL contains words common in credential-phishing links",
                      f"Found: {', '.join(words[:6])}.", Severity.low, Strength.weak,
                      "Phishing links often promise verification, refunds, or account recovery.",
                      "Be cautious if the page asks for passwords, OTPs, or card details.",
                      "These words are also common on legitimate login and support pages.", {"words": words[:10]}))
    if parts.subdomain and parts.subdomain.count(".") >= 3:
        out.append(_f("url.deep_subdomains", "Unusually deep subdomain nesting", f"Subdomain part '{parts.subdomain}' has {parts.subdomain.count('.') + 1} levels.",
                      Severity.low, Strength.weak, "Long hostnames push the real domain out of view on mobile screens.",
                      "Read the hostname from the right: the real owner is the registrable domain.", "CDNs and cloud services use deep names legitimately.",
                      {"levels": parts.subdomain.count(".") + 1}))
    if len(p.href) > 200 or host.count("-") >= 4:
        out.append(_f("url.obfuscated_shape", "Long or heavily hyphenated URL", f"Length {len(p.href)} characters; {host.count('-')} hyphens in the host.",
                      Severity.low, Strength.weak, "Long and hyphenated URLs are used to look official and hide the real domain.",
                      "Check the registrable domain.", "Many tracking links are long and legitimate.", {"length": len(p.href), "host_hyphens": host.count("-")}))
    if parts.suffix and parts.suffix.split(".")[-1] in RISKY_TLDS and not official:
        out.append(_f("url.risky_tld", f"Domain uses the '.{parts.suffix}' ending, which is frequently abused",
                      f"Suffix '.{parts.suffix}'.", Severity.low, Strength.weak,
                      "Some low-cost domain endings are disproportionately used for abuse.", "Treat as a minor signal only.",
                      "Most domains under any ending are legitimate; this is a statistical signal, not evidence.", {"suffix": parts.suffix}))
    if p.explicit_port and p.port not in (80, 443):
        out.append(_f("url.nonstandard_port", "Website runs on a non-standard port", f"Port {p.port}.", Severity.low, Strength.weak,
                      "Public sites rarely use non-standard ports.", "Be cautious.", "Some applications use such ports legitimately.", {"port": p.port}))
    if p.scheme == "http":
        out.append(_f("url.no_tls", "Link uses unencrypted HTTP", "Scheme is http://.", Severity.low, Strength.weak,
                      "Anything typed on an HTTP page can be read or changed in transit.", "Never enter credentials on an http:// page.",
                      "The site may still redirect to HTTPS; see the redirect chain.", {}))
    if official:
        out.append(_f("url.official_domain", f"Domain is listed as an official {official['name']} domain",
                      f"'{parts.registrable}' is in the curated official-domain list for {official['name']}.", Severity.info, Strength.moderate,
                      "This lowers impersonation concern for this domain.",
                      "Still check the full address; compromised pages and open redirects on official domains exist.",
                      "Official-domain lists are curated manually and may be incomplete or outdated.", {"brand": official["name"]}))
    return out, facts
