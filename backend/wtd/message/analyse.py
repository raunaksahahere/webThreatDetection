"""Scam message / email analysis: indicator extraction, social-engineering rules, link analysis.

Privacy: the raw message is never stored or logged. The report keeps a redacted excerpt, the SHA-256 of
the input, extracted indicators (personal identifiers as keyed HMACs, displayed masked), and findings.
Language cues (urgency, rewards, threats) are weak evidence: alone they cannot exceed Suspicious, and a
message is never labelled fraudulent solely because it is urgent or persuasive.
"""
from __future__ import annotations

import re
import zlib
from urllib.parse import parse_qs, urlsplit

from .. import intel
from ..checks import url_rules
from ..models import CheckResult, CheckStatus, Finding, Indicator, Module, Provenance, Severity, Strength, iso
from ..netguard import UrlRejected, defang, parse_url, refang
from .email_checks import analyse_email, looks_like_email
from ..pipeline import EXECUTOR, STORE, _check, _finish, correlate, correlation_findings, hmac_key, new_report, submit_url

SOURCE = "wtd.message_rules v1 (deterministic patterns)"
MSG_LIMITATIONS = [
    "Language patterns are signals, not proof: urgent or persuasive wording alone never makes a message fraudulent.",
    "Links were analysed statically and against threat intelligence; open them only after checking the linked report.",
    "Sender identity (email headers, phone number ownership) could not be verified from pasted text.",
    "Personal identifiers are stored only as keyed hashes for correlation and are shown masked.",
]

URL_RX = re.compile(r"\b(?:h[tx]{2}ps?(?:\[:\]|:)//|www\.)[^\s<>\"'`]+|\b[a-z0-9-]+(?:\.|\[\.\]|\(\.\))(?:[a-z0-9-]+(?:\.|\[\.\]|\(\.\)))*(?:com|in|net|org|top|xyz|info|co|io|me|ly|link|click|online|site|shop|live|app|cc|tk|ml|ga|cf|gq|ru|cn)\b(?:/[^\s<>\"']*)?", re.I)
EMAIL_RX = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b", re.I)
UPI_HANDLES = ("okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl", "paytm", "upi", "apl", "yapl", "ptyes", "ptsbi", "pthdfc", "ptaxis",
               "icici", "sbi", "hdfcbank", "axisbank", "kotak", "barodampay", "pnb", "freecharge", "jupiteraxis", "slc", "fam", "naviaxis", "waicici")
UPI_RX = re.compile(r"\b[a-z0-9._-]{2,64}@(" + "|".join(UPI_HANDLES) + r")\b", re.I)
PHONE_RX = re.compile(r"(?<![\d\w])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)|(?<![\d\w])\+(?!91)\d{1,3}[\s-]?\d{3,4}[\s-]?\d{3,4}[\s-]?\d{2,4}(?!\d)")
BTC_RX = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TRX_RX = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
AMOUNT_RX = re.compile(r"(?:₹|rs\.?|inr|\$|usd|usdt)\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*\s?(?:rupees|rs\b|inr|usdt)", re.I)
LONG_DIGITS = re.compile(r"\b\d(?:[ -]?\d){11,18}\b")

RULES = [
    ("msg.urgency", "Creates time pressure", Severity.low, Strength.weak,
     r"\b(urgent(ly)?|immediately|right away|within \d+\s?(hours?|hrs?|minutes?|mins?|days?)|today only|last (chance|date|day)|expir(e|es|ed|ing)|deadline|act now|before midnight|asap|(closes|ends|due|expires?|last date is) (today|tonight|tomorrow))\b",
     "Pressure to act quickly is used to stop people from checking.", "Slow down and verify through an official channel."),
    ("msg.threat", "Threatens negative consequences", Severity.low, Strength.weak,
     r"\b(suspend(ed)?|block(ed)?|deactivat(e|ed)|frozen|legal action|penalt(y|ies)|arrest|police|court|fine of|disconnect(ed)?|cancel(l)?ed)\b",
     "Fear of losing access or legal trouble is a common manipulation.", "Contact the organisation through its official number, not the one in the message."),
    ("msg.reward", "Promises a prize, refund or easy money", Severity.low, Strength.weak,
     r"\b(congratulations|you('ve| have)? won|winner|lottery|prize|cash ?back|refund|reward|gift|bonus|free (iphone|gift|recharge)|lucky draw|claim (now|your))\b",
     "Unexpected rewards are bait to collect details or fees.", "Legitimate prizes never require you to pay or share secrets."),
    ("msg.job_offer", "Unsolicited job or easy-earning offer", Severity.medium, Strength.weak,
     r"\b(work from home|part[- ]time (online |home )?(job|work)|online (part[- ]time )?job|earn (rs\.?|₹|inr)?\s?\d[\d,]*\s?(/-)?\s?((per|a) (day|hour|week)|daily|weekly|per task)|daily (income|earning)s?|like (videos|posts)|(video|youtube|instagram) like task|(rating|review|rate) (hotels|products|apps|movies)|prepaid task|task (bonus|commission)|telegram (task|group)|task[- ]based|data entry job|hiring urgently)\b",
     "Task and job scams lure victims with easy money and later demand deposits.", "Do not pay any fee to get a job; verify the company independently."),
    ("msg.investment", "High-return investment pitch", Severity.medium, Strength.weak,
     r"\b(guaranteed (returns?|profit)|double your (money|investment)|\d{2,3}% (returns?|profit)|risk[- ]free (profit|investment)|crypto (trading|investment|signals)|forex signals)\b",
     "Guaranteed or unusually high returns are the hallmark of investment fraud.", "Check whether the entity is registered with the regulator (e.g. SEBI)."),
    ("msg.impersonation_claim", "Claims to be from an official organisation", Severity.low, Strength.weak,
     r"\b(customer care|customer support|kyc|account (team|department)|fraud (team|department)|security team|official notice|income tax department|electricity (board|department)|courier|customs)\b",
     "Scammers pose as banks, government offices, couriers and support teams.", "Verify the sender through the organisation's official website or number."),
]
CRED_RX = re.compile(r"\b(share|send|provide|tell|give|enter|confirm|reply with|forward|update|verify)\b[^.\n]{0,40}\b(otp|one[- ]time (password|code)|pin|mpin|upi pin|password|cvv|card (number|details)|aadhaar|aadhar|pan (number|card)|bank details|login (details|credentials)|verification code|seed phrase|private key)\b", re.I)
NEGATION_RX = re.compile(r"\b(never|do not|don't|dont|not)\b[^.\n]{0,25}\b(share|send|provide|tell|give|disclose)\b", re.I)
PAY_RX = re.compile(r"\b(pay|payment|transfer|deposit|send money|processing fee|registration fee|activation fee|security deposit|refundable deposit|charges? of|scan (the )?qr)\b", re.I)
UPI_URI_RX = re.compile(r"upi://pay\?[^\s\"'<>]{3,1000}", re.I)
RECEIVE_LURE_RX = re.compile(r"\b(receive|refund|cash ?back|prize|reward|won|winner|lottery|credited|claim|bonus|get paid|payment received)\b", re.I)
GIFT_CARD_RX = re.compile(r"\b(gift ?cards?|google play (card|code)|amazon (gift )?(card|voucher)|itunes card|steam card)\b", re.I)


def redact(text: str) -> str:
    t = EMAIL_RX.sub(lambda m: m.group(0)[0] + "•••@" + m.group(0).split("@")[1], text)
    t = UPI_RX.sub(lambda m: m.group(0)[:2] + "•••@" + m.group(1), t)
    t = LONG_DIGITS.sub(lambda m: "•" * 6 + re.sub(r"\D", "", m.group(0))[-4:], t)
    t = PHONE_RX.sub(lambda m: re.sub(r"\d(?=(?:\D*\d){3})", "•", m.group(0)), t)
    return t


def mask(kind: str, v: str) -> str:
    if kind == "email":
        u, d = v.split("@", 1)
        return f"{u[:1]}•••@{d}"
    if kind == "upi":
        u, d = v.split("@", 1)
        return f"{u[:2]}•••@{d}"
    if kind == "phone":
        digits = re.sub(r"\D", "", v)
        return f"•••••{digits[-4:]}"
    if kind == "crypto_wallet":
        return v[:6] + "…" + v[-4:]
    return v


def shingles(text: str) -> list[int]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return sorted({zlib.crc32(" ".join(words[i:i + 3]).encode()) for i in range(max(0, len(words) - 2))})[:2000]


def _f(code, title, observed, sev, strength, impact, rec, lim, ev, module=Module.message) -> Finding:
    return Finding(id=code, code=code, module=module, title=title, observed=observed, evidence=ev, source=SOURCE, provenance=Provenance.live,
                   observed_at=iso(), severity=sev, strength=strength, impact=impact, recommendation=rec, limitation=lim)


def _quote(text: str, m: re.Match, width: int = 50) -> str:
    s, e = max(0, m.start() - width), min(len(text), m.end() + width)
    return ("…" if s else "") + text[s:e].replace("\n", " ") + ("…" if e < len(text) else "")


def analyse_text(text: str) -> tuple[list[Finding], list[tuple[str, str, str]], dict, list[str]]:
    """Return findings, indicators (type, match_key, display), subject facts, extracted URLs."""
    red = redact(text)
    findings: list[Finding] = []
    low = text.lower()
    for code, title, sev, strength, rx, impact, rec in RULES:
        ms = list(re.finditer(rx, red, re.I))
        if ms:
            findings.append(_f(code, title, f"{len(ms)} phrase(s), e.g. \"{_quote(red, ms[0])}\"", sev, strength, impact, rec,
                               "Wording alone is not evidence of fraud; legitimate messages can use the same phrases.",
                               {"matches": sorted({m.group(0).lower() for m in ms})[:8]}))
    cred = [m for m in CRED_RX.finditer(red) if not NEGATION_RX.search(red[max(0, m.start() - 30): m.end()])]
    if cred:
        findings.append(_f("msg.credential_request", "Asks you to share an OTP, PIN, password or ID details",
                           f"\"{_quote(red, cred[0])}\"", Severity.high, Strength.moderate,
                           "Banks, government services and employers never ask for OTPs, PINs or passwords by message.",
                           "Never share these codes. If you already did, contact your bank immediately and change the password.",
                           "Pattern-based; a message that merely mentions these words without asking is excluded where a negation is detected.",
                           {"requested": sorted({m.group(2).lower() for m in cred})[:5]}))
    pay = list(PAY_RX.finditer(UPI_URI_RX.sub(" ", red)))  # the word "pay" inside upi://pay is handled by the QR rule
    amounts = AMOUNT_RX.findall(text)
    upis = sorted({m.group(0).lower() for m in UPI_RX.finditer(text)})
    emails = sorted({e.lower() for e in EMAIL_RX.findall(text) if not UPI_RX.fullmatch(e)})
    phones = sorted({re.sub(r"[\s-]", "", p) for p in PHONE_RX.findall(text)})
    wallets = sorted(set(BTC_RX.findall(text)) | set(ETH_RX.findall(text)) | set(TRX_RX.findall(text)))
    gift = list(GIFT_CARD_RX.finditer(red))
    upi_uris = [m.group(0) for m in UPI_URI_RX.finditer(text)]
    for uri in upi_uris[:1]:
        q = parse_qs(urlsplit(uri.replace("upi://pay", "upi://pay/", 1)).query)
        pa = (q.get("pa") or [""])[0].lower()
        pn, am, tn = (q.get("pn") or [""])[0][:60], (q.get("am") or [""])[0][:12], (q.get("tn") or [""])[0][:80]
        if pa and pa not in upis:
            upis.append(pa)
        lure = RECEIVE_LURE_RX.search(f"{pn} {tn} {red}")
        findings.append(_f("msg.upi_pay_request", "This is a UPI payment request: approving it SENDS money",
                           f"upi://pay to {mask('upi', pa) if '@' in pa else 'unknown payee'}" + (f" ({pn})" if pn else "")
                           + (f", amount Rs {am}" if am else ", amount left to the payer") + (f", note '{tn}'" if tn else "")
                           + (f". The text around it talks about receiving money ('{lure.group(0)}')." if lure else "."),
                           Severity.high if lure else Severity.low, Strength.strong if lure else Strength.weak,
                           "In UPI you never scan a QR code or enter your PIN to receive money; 'scan to get your refund/prize' QR codes take money instead.",
                           "Do not scan or approve it unless you intend to pay this exact payee. Check the payee name in your UPI app.",
                           "Legitimate merchants also use payment QR codes; the risk is in being told it will pay you.",
                           {"payee": mask("upi", pa) if "@" in pa else None, "payee_name": pn, "amount": am, "receive_lure": bool(lure)}))
    if pay and (amounts or upis or wallets):
        findings.append(_f("msg.payment_request", "Requests a payment or fee", f"\"{_quote(red, pay[0])}\"" + (f"; amount(s): {', '.join(amounts[:3])}" if amounts else ""),
                           Severity.medium, Strength.moderate, "Advance fees and 'processing charges' are the core of many scams.",
                           "Do not pay before verifying the request through an official channel.", "Legitimate invoices also request payment.",
                           {"amounts": amounts[:5], "channels": (["UPI"] if upis else []) + (["crypto"] if wallets else [])}))
    if gift or wallets or (upis and pay and any(f.code in ("msg.job_offer", "msg.reward", "msg.investment") for f in findings)):
        chan = "gift cards" if gift else "cryptocurrency" if wallets else "UPI to a personal ID"
        lure = [f.code for f in findings if f.code in ("msg.job_offer", "msg.reward", "msg.investment")]
        findings.append(_f("msg.unusual_payment", f"Asks for payment via {chan}" + (" as an advance fee" if lure else ""),
                           f"Payment channel: {chan}" + (f", combined with a {lure[0].split('.')[1].replace('_', ' ')} pitch (advance-fee pattern)." if lure else "."),
                           Severity.high, Strength.strong if lure else Strength.moderate,
                           "Gift cards, crypto and personal UPI IDs are irreversible and favoured by fraudsters.",
                           "Never pay a 'fee', 'deposit' or 'tax' this way.", "Some legitimate small businesses accept personal UPI.",
                           {"channel": chan}))
    # Links and brand/link mismatch
    raw_urls = []
    for m in URL_RX.finditer(text):
        u = m.group(0).rstrip(").,;:!?]'\"")
        if "@" in u and not u.lower().startswith(("http", "hxxp", "www")):
            continue
        raw_urls.append(u)
    parsed = []
    for u in dict.fromkeys(raw_urls):
        try:
            parsed.append(parse_url(u))
        except UrlRejected:
            continue
    parsed = parsed[:5]
    indicators: list[tuple[str, str, str]] = []
    for p in parsed:
        reg = url_rules.split_domain(p.host).registrable
        indicators.append(("url", p.href, defang(p.href)))
        if reg:
            indicators.append(("domain", reg, reg.replace(".", "[.]")))
    claimed = [b for b in url_rules.brand_data()["brands"]
               if any(re.search(rf"(?<![a-z0-9]){re.escape(t.strip())}(?![a-z0-9])", low) for t in b.get("text", []) if len(t.strip()) >= 3)]
    for b in claimed[:3]:
        indicators.append(("brand", b["name"].lower(), b["name"]))
        for p in parsed:
            reg = url_rules.split_domain(p.host).registrable
            if reg and reg not in b["official"]:
                is_short = reg in url_rules.brand_data()["shorteners"]
                findings.append(_f("msg.brand_link_mismatch", f"Claims to be {b['name']} but links elsewhere",
                                   f"The message mentions {b['name']} but its link goes to '{reg}', not an official {b['name']} domain"
                                   + (" (a link shortener hides the destination)." if is_short else "."),
                                   Severity.high, Strength.moderate if is_short else Strength.strong,
                                   "Messages that impersonate a brand while linking to another domain are classic phishing.",
                                   f"Do not use the link. Go to {b['name']}'s official site ({', '.join(b['official'][:2])}) yourself.",
                                   "The brand list is curated; partners and resellers may link to their own domains legitimately.",
                                   {"brand": b["name"], "link_domain": reg, "official": b["official"][:3]}))
                break
    for kind, vals in (("email", emails), ("phone", phones), ("upi", upis), ("crypto_wallet", wallets)):
        for v in vals[:10]:
            indicators.append((kind, hmac_key(v.lower()), mask(kind, v)))
    facts = {"length": len(text), "urls": [defang(p.href) for p in parsed], "emails": [mask("email", e) for e in emails[:10]],
             "phones": [mask("phone", p) for p in phones[:10]], "upi_ids": [mask("upi", u) for u in upis[:10]],
             "crypto_wallets": [mask("crypto_wallet", w) for w in wallets[:10]], "amounts": amounts[:10],
             "claimed_brands": [b["name"] for b in claimed[:5]], "redacted_text": red[:4000]}
    return findings, indicators, facts, [p.href for p in parsed]


def analyse_message(rid: str, text: str, investigate_links: bool, via: str | None = None) -> None:
    r = STORE.get(rid)
    r.status = "running"
    STORE.save(r)
    findings: list[Finding] = []
    checks: list[CheckResult] = []
    try:
        email_facts, email_items = None, []
        if looks_like_email(text):
            ef, body, email_facts, email_items, hrefs = analyse_email(text)
            findings += ef
            auth = email_facts.get("authentication_results")
            checks.append(_check("email.structure", Module.message, CheckStatus.succeeded, True,
                                 f"headers parsed; {email_facts['received_hops']} Received hop(s); {len(email_facts['attachments'])} attachment(s) listed (not opened)"))
            checks.append(_check("email.authentication", Module.message, CheckStatus.succeeded if auth else CheckStatus.skipped, False,
                                 f"SPF/DKIM/DMARC as recorded by {auth.get('authserv', '?')}" if auth else "no Authentication-Results header in the pasted source"))
            text = body + ("\n" + "\n".join(dict.fromkeys(hrefs))[:4000] if hrefs else "")
        mf, items, facts, urls = analyse_text(text)
        findings += mf
        if email_facts:
            seen = {(t, k) for t, k, _ in items}
            items += [(t, hmac_key(v), d) for t, v, d in email_items if (t, hmac_key(v)) not in seen]
            facts["email"] = email_facts
        checks.append(_check("message.rules", Module.message, CheckStatus.succeeded, True, f"{len(mf)} pattern(s); {len(urls)} link(s) extracted"))
        for i, u in enumerate(urls):
            p = parse_url(u)
            uf, _ = url_rules.analyse_url(p)
            for f in uf:
                if f.severity == "info" and f.code != "url.official_domain":
                    continue
                f.id = f"link{i + 1}.{f.id}"
                f.observed = f"[{defang(p.href)[:80]}] " + f.observed
                findings.append(f)
        if urls:
            hosts = [parse_url(u).host for u in urls]
            io = intel.lookup(urls[0], hosts, set(url_rules.brand_data()["shared_hosting"]))
            findings += io.findings
            checks += io.checks
        else:
            checks.append(_check("intel.links", Module.intel, CheckStatus.skipped, False, "no links in the message"))
        linked = []
        if investigate_links and urls:
            for u in urls[:3]:
                try:
                    lr = submit_url(u)
                    linked.append({"url": defang(u), "report_id": lr.id})
                except UrlRejected:
                    pass
        facts["linked_reports"] = linked
        if via == "qr":
            facts["delivered_via"] = "QR code"
        r.subject = facts
        sh = shingles(facts["redacted_text"])
        r.indicators = [Indicator(type=t, display=d, match_key=k, hashed=k.startswith("hmac:")) for t, k, d in items]
        links = correlate(r, items, sh)
        r.correlations = links
        findings += correlation_findings(links)
        checks.append(_check("correlation.indicators", Module.correlation, CheckStatus.succeeded, False, f"{len(links)} related report(s)"))
        STORE.add_indicators(r.id, r.created_at, items, sh)
        _finish(r, findings, checks, MSG_LIMITATIONS)
    except Exception as e:
        r.status, r.error, r.completed_at = "failed", f"internal error: {type(e).__name__}", iso()
        STORE.save(r)


def submit_message(text: str, investigate_links: bool = True, via: str | None = None):
    excerpt = redact(" ".join(text.split()))[:160]
    if looks_like_email(text):
        import email as _email
        import email.policy as _policy

        m = _email.message_from_string(text.lstrip()[:200_000], policy=_policy.default)
        frm = str(m.get("From", ""))
        dom = frm.rsplit("@", 1)[-1].strip("> ").lower() if "@" in frm else "unknown sender"
        excerpt = redact(f"E-mail from {dom}: " + " ".join(str(m.get("Subject", "(no subject)")).split()))[:160]
    r = new_report("message", excerpt + ("…" if len(text) > 160 else ""), text)
    EXECUTOR.submit(analyse_message, r.id, text, investigate_links, via)
    return r
