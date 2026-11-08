"""Raw e-mail (.eml / "show original") analysis: sender authentication, spoofing and attachment indicators.

Pasted e-mail source is parsed with the standard library only. Nothing is executed or opened: attachments are
listed by name, declared type and size; their bytes are hashed, never decoded further. The body text then goes
through the normal message rules (analyse_text), so links, payment requests and credential requests are covered.

What can and cannot be trusted:
- Authentication-Results is written by the *receiving* mail server. Only the topmost one (the last hop, your
  provider) is used; lower ones could have been inserted by the sender. A pasted message can still be edited
  by whoever pasted it, so results are reported as "as recorded by the receiving server".
- A missing or partial header block means sender authenticity is unknown, not good.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import re
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

from ..checks import url_rules
from ..models import Finding, Module, Severity, Strength
from ..netguard import UrlRejected, defang, parse_url

HEADER_RX = re.compile(r"^(from|subject|received|message-id|date|to|return-path|authentication-results|mime-version|dkim-signature):", re.I | re.M)
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com", "proton.me", "protonmail.com", "icloud.com",
            "gmx.com", "mail.com", "yandex.com", "zoho.com", "rediffmail.com", "yahoo.co.in"}
DANGEROUS_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "msi", "ps1", "jar", "lnk", "cpl",
                 "reg", "dll", "apk", "xll", "one", "svg"}
HTML_EXT = {"htm", "html", "shtml", "xhtml", "mht", "mhtml"}
CONTAINER_EXT = {"zip", "rar", "7z", "iso", "img", "vhd", "cab", "gz", "tar", "ace"}
MACRO_EXT = {"docm", "xlsm", "pptm", "xlsb", "dotm", "xlam"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "csv", "odt"}
SOURCE = "WTD e-mail header and structure rules"


def looks_like_email(text: str) -> bool:
    head = text.lstrip()[:8000].split("\n\n", 1)[0].split("\r\n\r\n", 1)[0]
    names = {m.group(1).lower() for m in HEADER_RX.finditer(head)}
    return "from" in names and len(names) >= 3


def _f(code, title, observed, sev, strength, impact, rec, lim, ev) -> Finding:
    from .analyse import _f as base

    f = base(code, title, observed, sev, strength, impact, rec, lim, ev, module=Module.message)
    f.source = SOURCE
    return f


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._buf = []
        if tag in ("br", "p", "div", "tr", "li"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._buf).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)


def _registrable(host: str) -> str:
    return url_rules.split_domain(host).registrable or host


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">").strip() if "@" in addr else ""


def _auth_results(msg) -> dict:
    """Parse the topmost Authentication-Results (added by the final receiving server)."""
    ar = msg.get_all("Authentication-Results") or msg.get_all("ARC-Authentication-Results") or []
    if not ar:
        return {}
    top = " ".join(str(ar[0]).split())
    out = {"raw": top[:400], "authserv": top.split(";", 1)[0].strip()[:80]}
    for mech in ("spf", "dkim", "dmarc"):
        vals = re.findall(rf"\b{mech}=(\w+)", top, re.I)
        if vals:
            out[mech] = "pass" if "pass" in [v.lower() for v in vals] else vals[0].lower()
    m = re.search(r"header\.from=([^\s;]+)", top, re.I)
    if m:
        out["header_from"] = m.group(1).lower()
    out["dkim_domains"] = sorted({d.lower() for d in re.findall(r"header\.(?:d|i)=@?([^\s;]+)", top, re.I)})[:5]
    return out


def _attachments(msg) -> list[dict]:
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fn = part.get_filename()
        disp = (part.get_content_disposition() or "").lower()
        if not fn and disp != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        name = (fn or "(unnamed)").strip()[:120]
        exts = [e.lower() for e in name.split(".")[1:]][-2:]
        out.append({"name": name, "declared_type": part.get_content_type(), "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(), "extensions": exts})
    return out[:20]


def analyse_email(raw: str) -> tuple[list[Finding], str, dict, list[tuple[str, str, str]], list[str]]:
    """Return findings, body text (for the message rules), facts, extra indicators (type, plain value, display), html hrefs."""
    from .analyse import mask

    msg = email.message_from_string(raw.lstrip(), policy=email.policy.default)
    findings: list[Finding] = []
    indicators: list[tuple[str, str, str]] = []
    display, from_addr = parseaddr(str(msg.get("From", "")))
    from_addr = from_addr.lower()
    from_dom = _domain_of(from_addr)
    from_reg = _registrable(from_dom) if from_dom else ""
    reply_to = [a.lower() for _, a in getaddresses([str(x) for x in (msg.get_all("Reply-To") or [])]) if a]
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1].lower()
    subject = " ".join(str(msg.get("Subject", "")).split())[:300]
    received = msg.get_all("Received") or []
    auth = _auth_results(msg)

    # --- body (prefer text/plain; fall back to HTML text) and HTML links
    plain, html = "", ""
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            continue
        if ctype == "text/plain" and not plain and isinstance(content, str):
            plain = content
        elif ctype == "text/html" and not html and isinstance(content, str):
            html = content
    lp = _Links()
    if html:
        try:
            lp.feed(html[:400_000])
        except Exception:
            pass
    body = plain or "".join(lp.text)
    body = re.sub(r"\n{3,}", "\n\n", body)[:20_000]

    # --- sender authentication
    if not auth:
        findings.append(_f("email.no_auth_results", "Sender authentication results are missing",
                           "No Authentication-Results header was found in the pasted source.", Severity.info, Strength.weak,
                           "Without the receiving server's SPF/DKIM/DMARC results the sender cannot be verified.",
                           "Paste the full original message (\"Show original\" / \"View source\") to include authentication results.",
                           "Headers may have been trimmed when copying.", {}))
    else:
        dmarc, spf, dkim = auth.get("dmarc"), auth.get("spf"), auth.get("dkim")
        if dmarc in ("fail", "quarantine", "reject"):
            findings.append(_f("email.dmarc_fail", "Sender domain failed DMARC",
                               f"The receiving server ({auth['authserv']}) recorded dmarc={dmarc} for the From domain '{from_dom}'.",
                               Severity.high, Strength.moderate, "A DMARC failure means the message was not authorised by the domain shown in From: a classic sign of spoofing.",
                               "Treat the sender as unverified. Contact the organisation through its official website.",
                               "Mailing lists and some forwarding can break DMARC for legitimate mail.", {"authentication_results": auth}))
        elif spf in ("fail", "softfail") and dkim not in ("pass",):
            findings.append(_f("email.auth_fail", "Sender authentication failed (SPF failed, no valid DKIM)",
                               f"spf={spf}, dkim={dkim or 'none'}, dmarc={dmarc or 'none'} as recorded by {auth['authserv']}.",
                               Severity.medium, Strength.moderate, "The sending server was not authorised by the sender's domain.",
                               "Be cautious with links and attachments; verify the sender independently.",
                               "Forwarded mail often fails SPF.", {"authentication_results": auth}))
        elif dmarc == "pass" or (dkim == "pass" and from_reg and any(_registrable(d) == from_reg for d in auth.get("dkim_domains", []))):
            findings.append(_f("email.auth_pass", "Sender domain authenticated (DMARC/DKIM aligned)",
                               f"dmarc={dmarc or 'n/a'}, dkim={dkim or 'n/a'}, spf={spf or 'n/a'} for '{from_dom}' as recorded by {auth['authserv']}.",
                               Severity.info, Strength.weak, "The message really came from the From domain. That domain itself may still be malicious or look-alike.",
                               "Check that the domain is the organisation's real one.", "Authentication proves origin, not intent.", {"authentication_results": auth}))
        elif dmarc in (None, "none") and spf in (None, "none", "neutral") and dkim in (None, "none"):
            findings.append(_f("email.auth_none", "Sender domain is not authenticated",
                               f"No passing SPF/DKIM/DMARC result for '{from_dom}' ({auth['authserv']}).", Severity.low, Strength.weak,
                               "Unauthenticated mail is easy to forge.", "Verify the sender through an official channel.",
                               "Some small legitimate senders do not configure authentication.", {"authentication_results": auth}))

    # --- display-name and look-alike sender
    low_disp = display.lower()
    for b in url_rules.brand_data()["brands"]:
        names = [b["name"].lower()] + [t.strip() for t in b.get("text", []) if len(t.strip()) >= 4]
        if low_disp and any(re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", low_disp) for n in names):
            if from_reg and from_reg not in b["official"] and not any(from_dom.endswith("." + o) for o in b["official"]):
                free = from_reg in FREEMAIL
                findings.append(_f("email.display_name_spoof", f"Display name claims {b['name']} but the address is not theirs",
                                   f"From: \"{display[:60]}\" <{mask('email', from_addr)}>; '{from_reg}' is not an official {b['name']} domain"
                                   + (" (a free webmail account)." if free else "."),
                                   Severity.high, Strength.strong if free else Strength.moderate,
                                   "Mail clients often show only the display name, so attackers put a trusted brand there.",
                                   f"Ignore the display name; {b['name']} writes from {', '.join(b['official'][:2])}.",
                                   "The brand list is curated; partners may send on a brand's behalf from their own domains.",
                                   {"brand": b["name"], "from_domain": from_reg, "official": b["official"][:3]}))
            break
    if from_dom:
        try:
            lf, _ = url_rules.analyse_url(parse_url(f"https://{from_dom}/"))
            for f in lf:
                if f.code in ("url.typosquat", "url.homograph", "url.brand_in_domain"):
                    f.id = f"from.{f.id}"
                    f.title = "Sender domain: " + f.title
                    findings.append(f)
        except UrlRejected:
            pass

    # --- Reply-To / Return-Path divergence
    for rt in reply_to[:2]:
        rt_reg = _registrable(_domain_of(rt))
        if from_reg and rt_reg and rt_reg != from_reg:
            free = rt_reg in FREEMAIL
            findings.append(_f("email.reply_to_mismatch", "Replies go to a different domain than the sender",
                               f"From domain '{from_reg}', Reply-To <{mask('email', rt)}> ('{rt_reg}')" + (" — a free webmail account." if free else "."),
                               Severity.medium if not free else Severity.high, Strength.moderate,
                               "Redirecting replies to another mailbox is common in invoice and CEO fraud.",
                               "Do not reply directly; contact the sender using details you already have.",
                               "Newsletters and ticketing systems sometimes use a different reply domain.", {"from_domain": from_reg, "reply_to_domain": rt_reg}))
            indicators.append(("email", rt, mask("email", rt)))
            break
    if return_path and from_reg:
        rp_reg = _registrable(_domain_of(return_path))
        if rp_reg and rp_reg != from_reg:
            findings.append(_f("email.return_path_mismatch", "Bounce address uses a different domain",
                               f"Return-Path domain '{rp_reg}' differs from From domain '{from_reg}'.", Severity.low, Strength.weak,
                               "Can indicate a spoofed From address.", "Check the authentication results above.",
                               "Very common for legitimate bulk mail sent through e-mail service providers.", {"return_path_domain": rp_reg}))

    # --- HTML links whose visible text shows another destination
    hrefs = []
    for href, text in lp.links[:200]:
        if not href.lower().startswith(("http://", "https://")):
            continue
        hrefs.append(href)
        shown = re.search(r"((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,})(?:/|\s|$)", text.lower())
        if not shown:
            continue
        try:
            real = _registrable(parse_url(href).host)
            seen = _registrable(parse_url(shown.group(1) if shown.group(1).startswith("http") else "https://" + shown.group(1)).host)
        except UrlRejected:
            continue
        if real and seen and real != seen:
            findings.append(_f("email.link_text_mismatch", "A link shows one address but goes to another",
                               f"Link text shows '{seen}' but the link goes to '{defang(real)}'.", Severity.high, Strength.moderate,
                               "Disguising the real destination is a core phishing technique.", "Do not click; type the address you expect yourself.",
                               "Click-tracking services in newsletters also rewrite links.", {"shown": seen, "actual": real}))
            break

    # --- attachments (never opened)
    atts = _attachments(msg)
    for a in atts:
        exts = a["extensions"]
        last = exts[-1] if exts else ""
        double = len(exts) == 2 and exts[0] in DOC_EXT and (last in DANGEROUS_EXT or last in HTML_EXT)
        if double or last in DANGEROUS_EXT:
            findings.append(_f("email.dangerous_attachment", "Executable or script attachment" + (" disguised with a double extension" if double else ""),
                               f"Attachment '{a['name'][:80]}' ({a['declared_type']}, {a['size']} bytes).", Severity.high,
                               Strength.strong if double else Strength.moderate, "Opening it can run code on your device.",
                               "Do not open it. Delete the message or report it to your IT/security team.",
                               "File names are attacker-controlled; the content was not inspected.", {"attachment": a}))
        elif last in HTML_EXT:
            findings.append(_f("email.html_attachment", "HTML file attachment",
                               f"Attachment '{a['name'][:80]}' opens as a web page.", Severity.high, Strength.moderate,
                               "HTML attachments are widely used for fake login pages that work offline from your inbox.",
                               "Do not open it or enter credentials in it.", "Some systems send HTML receipts.", {"attachment": a}))
        elif last in MACRO_EXT:
            findings.append(_f("email.macro_attachment", "Macro-enabled Office attachment", f"Attachment '{a['name'][:80]}'.",
                               Severity.medium, Strength.moderate, "Macros can run code when enabled.", "Do not enable macros.",
                               "Some business workflows use macros.", {"attachment": a}))
        elif last in CONTAINER_EXT:
            findings.append(_f("email.archive_attachment", "Archive or disk-image attachment", f"Attachment '{a['name'][:80]}'.",
                               Severity.low, Strength.weak, "Archives and disk images are used to slip executables past filters.",
                               "Only open archives you expected.", "Archives are common in normal business mail.", {"attachment": a}))

    if from_addr:
        indicators.append(("email", from_addr, mask("email", from_addr)))
    facts = {
        "format": "email",
        "subject": subject,
        "from_display": display[:80],
        "from": mask("email", from_addr) if from_addr else None,
        "from_domain": from_dom,
        "reply_to": [mask("email", r) for r in reply_to[:3]],
        "return_path_domain": _domain_of(return_path) or None,
        "received_hops": len(received),
        "authentication_results": {k: v for k, v in auth.items() if k != "raw"} or None,
        "attachments": [{k: a[k] for k in ("name", "declared_type", "size", "sha256")} for a in atts],
        "html_links": len(hrefs),
    }
    return findings, (f"Subject: {subject}\n\n" if subject else "") + body, facts, indicators, hrefs
