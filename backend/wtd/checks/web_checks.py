"""Passive website security assessment (posture) and page-content phishing indicators.

Inputs come only from the isolated inspector's single permitted fetch (plus one http:// probe).
No extra paths are requested, nothing is exploited, no scripts run.

Posture findings (codes starting 'web.') describe configuration weaknesses; they are reported in
the security assessment but are excluded from the threat classification, because missing headers
are common on legitimate sites and are not evidence of phishing.
Content findings (codes starting 'content.') are threat indicators.
"""
from __future__ import annotations

import re

from ..models import Finding, Module, Provenance, Severity, Strength, iso
from .url_rules import brand_data, official_brand_for, split_domain

SOURCE_WEB = "wtd.web_checks v1 (passive HTTP response inspection)"
SOURCE_CONTENT = "wtd.web_checks v1 (static HTML features; no script execution)"
POSTURE_PREFIX = "web."


def _f(code, module, title, observed, sev, strength, impact, rec, lim, ev, source) -> Finding:
    return Finding(id=code, code=code, module=module, title=title, observed=observed, evidence=ev, source=source,
                   provenance=Provenance.live, observed_at=iso(), severity=sev, strength=strength, impact=impact,
                   recommendation=rec, limitation=lim)


def posture(fetch: dict, http_upgrade: dict | None) -> tuple[list[Finding], dict]:
    out: list[Finding] = []
    hops = fetch.get("hops") or []
    final = next((h for h in reversed(hops) if h.get("status") and not (300 <= h["status"] < 400)), None)
    summary: dict = {"final_status": fetch.get("final_status"), "content_type": fetch.get("content_type")}
    if not final:
        return out, summary
    hdr: dict[str, str] = {}
    cookies: list[str] = []
    for k, v in final.get("headers") or []:
        if k == "set-cookie":
            cookies.append(v)
        else:
            hdr[k] = v
    https = final["url"].startswith("https://")
    present = {h: (h in hdr) for h in ("strict-transport-security", "content-security-policy", "x-content-type-options",
                                       "x-frame-options", "referrer-policy", "permissions-policy")}
    summary["security_headers"] = present
    summary["server"] = hdr.get("server")
    W = lambda *a: out.append(_f(*a, source=SOURCE_WEB))
    lim_hdr = "Header checks describe security hygiene, not maliciousness; only the final response was inspected."
    if https:
        hsts = hdr.get("strict-transport-security", "")
        if not hsts:
            W("web.hdr.hsts_missing", Module.web, "HSTS header missing", "No Strict-Transport-Security header on the HTTPS response.",
              Severity.low, Strength.weak, "Browsers may be downgraded to HTTP on first visit or via typed links.",
              "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.", lim_hdr, {})
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 15552000:
                W("web.hdr.hsts_short", Module.web, "HSTS max-age is short", f"max-age={m.group(1)} seconds.", Severity.info, Strength.weak,
                  "Short HSTS lifetimes protect less.", "Use at least 6 months (15552000 s).", lim_hdr, {"value": hsts[:200]})
    csp = hdr.get("content-security-policy", "")
    if not csp:
        W("web.hdr.csp_missing", Module.web, "Content-Security-Policy missing", "No CSP header.", Severity.low, Strength.weak,
          "Without CSP, injected scripts (XSS) run with full page privileges.", "Deploy a CSP, starting with default-src 'self'.", lim_hdr, {})
    elif "'unsafe-inline'" in csp and "script-src" in csp or ("default-src" in csp and "'unsafe-inline'" in csp and "script-src" not in csp):
        W("web.hdr.csp_unsafe_inline", Module.web, "CSP allows inline scripts", "CSP contains 'unsafe-inline' for scripts.", Severity.info, Strength.weak,
          "Inline-script allowance weakens XSS protection.", "Use nonces or hashes instead of 'unsafe-inline'.", lim_hdr, {"csp": csp[:300]})
    if hdr.get("x-content-type-options", "").lower() != "nosniff":
        W("web.hdr.xcto_missing", Module.web, "X-Content-Type-Options not set to nosniff", "Header missing or not 'nosniff'.", Severity.info, Strength.weak,
          "Browsers may MIME-sniff responses into executable types.", "Send 'X-Content-Type-Options: nosniff'.", lim_hdr, {})
    if "x-frame-options" not in hdr and "frame-ancestors" not in csp:
        W("web.hdr.framing", Module.web, "No clickjacking protection", "Neither X-Frame-Options nor CSP frame-ancestors is set.", Severity.low, Strength.weak,
          "The page can be framed by other sites to trick users into clicks.", "Send CSP 'frame-ancestors' or X-Frame-Options: DENY.", lim_hdr, {})
    if "referrer-policy" not in hdr:
        W("web.hdr.referrer", Module.web, "Referrer-Policy missing", "No Referrer-Policy header.", Severity.info, Strength.weak,
          "Full URLs (possibly with tokens) may leak to third parties.", "Send 'Referrer-Policy: strict-origin-when-cross-origin'.", lim_hdr, {})
    weak_cookies = []
    for c in cookies[:30]:
        name = c.split("=", 1)[0].strip()[:40]
        low = c.lower()
        flags = []
        if https and "secure" not in low:
            flags.append("Secure")
        if "httponly" not in low:
            flags.append("HttpOnly")
        if "samesite" not in low:
            flags.append("SameSite")
        if flags:
            weak_cookies.append(f"{name} (missing {', '.join(flags)})")
    if weak_cookies:
        W("web.cookie.flags", Module.web, "Cookies set without recommended flags", f"{len(weak_cookies)} cookie(s): {'; '.join(weak_cookies[:4])}.",
          Severity.low, Strength.weak, "Session cookies without Secure/HttpOnly/SameSite are easier to steal or misuse.",
          "Set Secure, HttpOnly and SameSite on session cookies.", "Some cookies (e.g. analytics) do not need all flags.", {"cookies": weak_cookies[:10]})
    acao = hdr.get("access-control-allow-origin")
    if acao == "*" and hdr.get("access-control-allow-credentials", "").lower() == "true":
        W("web.cors.wildcard_credentials", Module.web, "CORS allows any origin with credentials", "ACAO '*' with credentials.", Severity.medium, Strength.weak,
          "Misconfigured CORS can expose authenticated data.", "Restrict allowed origins.", lim_hdr, {})
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        v = hdr.get(h, "")
        if re.search(r"\d+\.\d+", v):
            W(f"web.disclosure.{h}", Module.web, f"Software version disclosed in '{h}' header", f"{h}: {v[:80]}", Severity.info, Strength.weak,
              "Version details help attackers find known vulnerabilities.", "Remove version numbers from response headers.",
              "No vulnerability lookup was performed; versions can be spoofed or backported.", {"header": h, "value": v[:120]})
    if http_upgrade and https:
        summary["http_redirects_to_https"] = http_upgrade.get("redirects_to_https")
        if http_upgrade.get("status") and not http_upgrade.get("redirects_to_https"):
            W("web.no_https_redirect", Module.web, "Plain HTTP is not redirected to HTTPS", f"http:// returned status {http_upgrade.get('status')} without redirecting to https.",
              Severity.medium, Strength.weak, "Visitors typing the address may use an unencrypted connection.", "Redirect all HTTP requests to HTTPS and enable HSTS.",
              "Only the site root was probed.", {"status": http_upgrade.get("status"), "location": http_upgrade.get("location")})
    feats = fetch.get("features") or {}
    if feats.get("mixed_active"):
        W("web.mixed_active", Module.web, "HTTPS page loads scripts or styles over HTTP", f"{len(feats['mixed_active'])} active mixed-content resource(s).",
          Severity.medium, Strength.weak, "Network attackers can replace these resources and take over the page.", "Load all resources over HTTPS.",
          "Browsers block most active mixed content.", {"examples": feats["mixed_active"][:5]})
    elif feats.get("mixed_passive"):
        W("web.mixed_passive", Module.web, "HTTPS page loads images or media over HTTP", f"{len(feats['mixed_passive'])} passive mixed-content resource(s).",
          Severity.low, Strength.weak, "Content can be observed or altered in transit.", "Load all resources over HTTPS.", "", {"examples": feats["mixed_passive"][:5]})
    if feats.get("sri_missing_external_scripts"):
        W("web.sri_missing", Module.web, "Third-party scripts loaded without integrity checks", f"{feats['sri_missing_external_scripts']} external script(s) without SRI.",
          Severity.info, Strength.weak, "A compromised CDN could inject code.", "Add integrity= attributes to third-party scripts.", "Many sites legitimately omit SRI.", {})
    if feats.get("directory_listing"):
        W("web.directory_listing", Module.web, "Directory listing exposed", "The page is an auto-generated 'Index of /' listing.", Severity.medium, Strength.weak,
          "Files not meant to be public may be exposed.", "Disable directory listing.", "Detected only on the fetched page; no other paths were requested.", {})
    return out, summary


def content_indicators(fetch: dict, submitted_registrable: str) -> list[Finding]:
    out: list[Finding] = []
    C = lambda *a: out.append(_f(*a, source=SOURCE_CONTENT))
    hops = fetch.get("hops") or []
    final_url = fetch.get("final_url") or ""
    final_host = next((h["host"] for h in reversed(hops) if h.get("status")), "")
    final_reg = split_domain(final_host).registrable if final_host else ""
    official = official_brand_for(final_reg) if final_reg else None
    feats = fetch.get("features") or {}

    # Redirect analysis
    blocked = next((h for h in hops if h.get("blocked_reason")), None)
    if blocked and blocked["index"] > 0:
        C("content.redirect_blocked", Module.content, "Redirect chain points to a blocked destination",
          f"Hop {blocked['index']} ({blocked['url'][:120]}) was not followed: {blocked['blocked_reason']}.", Severity.medium, Strength.moderate,
          "Redirecting visitors to internal or reserved addresses is abnormal for public sites.", "Do not trust this link.",
          "Can also result from broken redirects.", {"hop": blocked["index"], "reason": blocked["blocked_reason"]})
    regs = [split_domain(h["host"]).registrable for h in hops if h.get("host")]
    distinct = list(dict.fromkeys(r for r in regs if r))
    if len(distinct) > 1 and final_reg and final_reg != submitted_registrable:
        C("content.cross_domain_redirect", Module.content, "Link redirects to a different domain",
          f"Started at '{submitted_registrable}', ended at '{final_reg}' via {len(hops) - 1} redirect(s).", Severity.medium, Strength.weak,
          "Redirects to unrelated domains are common in phishing and malvertising chains.", "Judge the final destination, not the original link.",
          "Shorteners, login flows and marketing links redirect legitimately.", {"domains": distinct[:8]})
    if fetch.get("body_note", "") and "non-text content" in (fetch.get("body_note") or ""):
        C("content.download", Module.content, "Link serves a file download", fetch["body_note"], Severity.medium, Strength.moderate,
          "Unexpected downloads from links in messages are a common malware delivery method.", "Do not open the file unless you expected it from a trusted sender.",
          "The file was not downloaded or scanned.", {"content_type": fetch.get("content_type")})
    if not feats or feats.get("kind") != "html":
        return out

    forms = feats.get("forms") or []
    cred_forms = [f for f in forms if f.get("has_password") or f.get("sensitive")]
    ext_cred = [f for f in cred_forms if f.get("external")]
    if ext_cred:
        f0 = ext_cred[0]
        C("content.credential_form_external", Module.content, "Login/sensitive form sends data to another domain",
          f"A form with {', '.join(f0.get('sensitive') or ['password'])} fields submits to '{f0.get('action_host')}', not to '{final_host}'.",
          Severity.high, Strength.strong, "Credentials typed here go to a third party: the defining behaviour of phishing kits.",
          "Do not enter credentials.", "Some legitimate single-sign-on setups post to a separate identity domain.",
          {"action_host": f0.get("action_host"), "fields": f0.get("sensitive") or []})
    if cred_forms and final_url.startswith("http://"):
        C("content.credential_form_http", Module.content, "Password or sensitive form on an unencrypted page", "Sensitive input fields on an http:// page.",
          Severity.high, Strength.moderate, "Anything typed is sent in clear text.", "Never enter credentials on this page.", "", {})
    sens = set(feats.get("sensitive_fields") or [])
    high_value = {s for s in sens if re.search(r"otp|cvv|cvc|card|aadhaar|aadhar|pan|upi|mpin|pin|seed|mnemonic|private", s)}

    # Brand impersonation in content
    title = (feats.get("title") or "").lower()
    text = feats.get("text_for_brands") or ""
    if not official:
        for b in brand_data()["brands"]:
            names = [n.strip() for n in b.get("text", []) if len(n.strip()) >= 4]
            in_title = [n for n in names if n in title]
            in_text = [n for n in names if n in text]
            hot = [h for h in (feats.get("icon_hosts") or []) + (feats.get("resource_hosts") or []) if split_domain(h).registrable in b["official"]]
            if in_title or (in_text and (cred_forms or hot)):
                strong = bool(cred_forms) and bool(in_title or hot)
                C("content.brand_impersonation", Module.content, f"Page presents itself as {b['name']} on an unofficial domain",
                  f"{'Title' if in_title else 'Page text'} mentions '{(in_title or in_text)[0]}' but the site is '{final_reg}'"
                  + (" and it asks for credentials" if cred_forms else "") + ".",
                  Severity.high, Strength.strong if strong else Strength.moderate,
                  "Pages that claim a brand's identity on another domain are the core of phishing.",
                  f"Use {b['name']}'s official site ({', '.join(b['official'][:2])}).",
                  "News, reviews and resellers mention brands legitimately; no visual comparison was performed.",
                  {"brand": b["name"], "where": "title" if in_title else "text", "credential_form": bool(cred_forms)})
                if hot:
                    C("content.brand_assets_hotlinked", Module.content, f"Page loads {b['name']} assets from the brand's own servers",
                      f"Resources/icons come from {', '.join(sorted(set(hot))[:3])} while the page is hosted on '{final_reg}'.",
                      Severity.high, Strength.moderate, "Phishing kits often hot-link the real brand's logo and styles to look authentic.",
                      "Treat as impersonation.", "Embedding brand widgets can be legitimate.", {"hosts": sorted(set(hot))[:5]})
                break
    if high_value and not official:
        C("content.high_value_fields", Module.content, "Page asks for high-value secrets", f"Input fields for: {', '.join(sorted(high_value))[:120]}.",
          Severity.medium, Strength.moderate, "Requests for OTPs, card security codes, PINs or ID numbers are the targets of fraud.",
          "Legitimate services never ask for OTPs or PINs on a page you reached from a message.", "Field detection is name-based.", {"fields": sorted(high_value)[:10]})
    if feats.get("meta_refresh"):
        C("content.meta_refresh", Module.content, "Page auto-redirects with meta refresh", f"meta refresh: {feats['meta_refresh'][:120]}", Severity.low, Strength.weak,
          "Used to bounce visitors through redirect chains.", "Check where it leads.", "Also used legitimately.", {"value": feats["meta_refresh"][:200]})
    js = feats.get("js_risk_counts") or {}
    obf = sum(js.get(k, 0) for k in ("eval", "atob", "unescape", "fromcharcode"))
    if obf >= 3:
        C("content.obfuscated_js", Module.content, "Inline scripts use obfuscation patterns", f"{obf} occurrence(s) of eval/atob/unescape/fromCharCode.",
          Severity.low, Strength.weak, "Obfuscation hides what the page does; common in phishing kits.", "Be cautious.",
          "Scripts were not executed; minified legitimate code can match.", {"counts": js})
    hidden = [i for i in feats.get("iframes") or [] if i.get("hidden")]
    if hidden:
        C("content.hidden_iframe", Module.content, "Hidden iframe present", f"{len(hidden)} hidden iframe(s).", Severity.medium, Strength.weak,
          "Hidden frames can load tracking or malicious content invisibly.", "Be cautious.", "Analytics tools sometimes use hidden frames.",
          {"srcs": [i.get("src", "")[:120] for i in hidden[:3]]})
    return out
