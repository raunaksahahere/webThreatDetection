"""Extract security-relevant features from hostile HTML without rendering or executing it.

Uses the standard-library tokenizer (html.parser). Caps the number of tags processed. Returns
plain data (counts, hosts, short strings). The UI never renders fetched HTML.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

from ada_url import URL

MAX_TAGS = 20_000
MAX_LIST = 40
SENSITIVE_INPUT = re.compile(
    r"pass(word|wd|code)?|pin\b|otp|one.?time|cvv|cvc|card.?(no|num)|ccnum|expiry|aadhaar|aadhar|pan.?(no|num|card)|ssn|"
    r"upi.?pin|mpin|seed|mnemonic|private.?key|netbank|login.?id|user.?id",
    re.I,
)
JS_RISK = {
    "eval": re.compile(r"\beval\s*\("),
    "atob": re.compile(r"\batob\s*\("),
    "unescape": re.compile(r"\bunescape\s*\("),
    "document_write": re.compile(r"document\.write\s*\("),
    "location_assign": re.compile(r"(window|document|top)\.location(\.href)?\s*=|location\.(replace|assign)\s*\("),
    "fromcharcode": re.compile(r"fromCharCode"),
}


def _host(u: str, base: str) -> tuple[str | None, str | None]:
    try:
        p = URL(u, base)
    except ValueError:
        return None, None
    scheme = p.protocol.rstrip(":")
    return scheme, (p.hostname or "").lower().strip("[]").rstrip(".") or None


class _Extractor(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.base_scheme, self.base_host = _host(base, base)
        self.tags = 0
        self.title_parts: list[str] = []
        self.in_title = False
        self.in_script = False
        self.in_style = False
        self.text_parts: list[str] = []
        self.text_len = 0
        self.forms: list[dict] = []
        self.current_form: dict | None = None
        self.scripts_external: list[str] = []
        self.inline_script_chars = 0
        self.js_risk_counts = {k: 0 for k in JS_RISK}
        self.iframes: list[dict] = []
        self.meta_refresh: str | None = None
        self.mixed_active: list[str] = []
        self.mixed_passive: list[str] = []
        self.resource_hosts: dict[str, int] = {}
        self.link_hosts: dict[str, int] = {}
        self.icon_hosts: list[str] = []
        self.data_uris = 0
        self.sri_missing_external_scripts = 0
        self.password_fields = 0
        self.sensitive_fields: list[str] = []
        self.truncated = False

    # --- helpers
    def _resource(self, url: str, active: bool) -> None:
        if url.strip().lower().startswith("data:"):
            self.data_uris += 1
            return
        scheme, host = _host(url, self.base)
        if not host:
            return
        if host != self.base_host:
            self.resource_hosts[host] = self.resource_hosts.get(host, 0) + 1
        if self.base_scheme == "https" and scheme == "http":
            (self.mixed_active if active else self.mixed_passive).append(url[:200])

    def handle_starttag(self, tag, attrs):
        self.tags += 1
        if self.tags > MAX_TAGS:
            self.truncated = True
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self.in_title = True
        elif tag == "script":
            self.in_script = True
            if a.get("src"):
                self.scripts_external.append(a["src"][:300])
                self._resource(a["src"], active=True)
                if "integrity" not in a:
                    _, h = _host(a["src"], self.base)
                    if h and h != self.base_host:
                        self.sri_missing_external_scripts += 1
        elif tag == "style":
            self.in_style = True
        elif tag == "iframe":
            src = a.get("src", "")
            hidden = a.get("width") in ("0", "1") or a.get("height") in ("0", "1") or "display:none" in a.get("style", "").replace(" ", "")
            self.iframes.append({"src": src[:200], "hidden": hidden})
            if src:
                self._resource(src, active=True)
        elif tag in ("img", "audio", "video", "source"):
            if a.get("src"):
                self._resource(a["src"], active=False)
        elif tag == "link":
            rel = a.get("rel", "").lower()
            href = a.get("href", "")
            if href:
                self._resource(href, active="stylesheet" in rel)
                if "icon" in rel:
                    _, h = _host(href, self.base)
                    if h:
                        self.icon_hosts.append(h)
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")[:300]
        elif tag == "a" and a.get("href"):
            _, h = _host(a["href"], self.base)
            if h and h != self.base_host:
                self.link_hosts[h] = self.link_hosts.get(h, 0) + 1
        elif tag == "form":
            action = a.get("action", "")
            scheme, h = _host(action or self.base, self.base)
            self.current_form = {
                "action_host": h,
                "action_scheme": scheme,
                "method": (a.get("method") or "get").lower()[:10],
                "external": bool(h and h != self.base_host),
                "inputs": [],
                "has_password": False,
                "sensitive": [],
            }
            self.forms.append(self.current_form)
        elif tag in ("input", "select", "textarea"):
            itype = a.get("type", "text").lower()
            name = " ".join([a.get("name", ""), a.get("id", ""), a.get("placeholder", ""), a.get("autocomplete", "")])[:200]
            sens = itype == "password" or bool(SENSITIVE_INPUT.search(name))
            if itype == "password":
                self.password_fields += 1
            if sens:
                label = itype if itype == "password" else (SENSITIVE_INPUT.search(name).group(0).lower() if SENSITIVE_INPUT.search(name) else itype)
                self.sensitive_fields.append(label)
            if self.current_form is not None and itype not in ("hidden", "submit", "button"):
                self.current_form["inputs"].append(itype)
                if itype == "password":
                    self.current_form["has_password"] = True
                if sens:
                    self.current_form["sensitive"].append(label)

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "script":
            self.in_script = False
        elif tag == "style":
            self.in_style = False
        elif tag == "form":
            self.current_form = None

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)
        elif self.in_script:
            self.inline_script_chars += len(data)
            for k, rx in JS_RISK.items():
                self.js_risk_counts[k] += len(rx.findall(data[:200_000]))
        elif not self.in_style and self.text_len < 6000:
            t = " ".join(data.split())
            if t:
                self.text_parts.append(t)
                self.text_len += len(t)


def extract_features(html: str, base_url: str) -> dict:
    p = _Extractor(base_url)
    try:
        p.feed(html[:2_000_000])
        p.close()
    except Exception:  # malformed markup must not crash the inspector
        pass
    text = " ".join(p.text_parts)[:6000]
    title = " ".join(" ".join(p.title_parts).split())[:200]
    top = lambda d: [h for h, _ in sorted(d.items(), key=lambda kv: -kv[1])][:MAX_LIST]
    return {
        "kind": "html",
        "title": title,
        "text_excerpt": text[:1500],
        "text_for_brands": text.lower()[:6000],
        "forms": p.forms[:MAX_LIST],
        "password_fields": p.password_fields,
        "sensitive_fields": sorted(set(p.sensitive_fields))[:MAX_LIST],
        "scripts_external": p.scripts_external[:MAX_LIST],
        "inline_script_chars": p.inline_script_chars,
        "js_risk_counts": p.js_risk_counts,
        "iframes": p.iframes[:MAX_LIST],
        "meta_refresh": p.meta_refresh,
        "mixed_active": p.mixed_active[:MAX_LIST],
        "mixed_passive": p.mixed_passive[:MAX_LIST],
        "resource_hosts": top(p.resource_hosts),
        "link_hosts": top(p.link_hosts),
        "icon_hosts": p.icon_hosts[:10],
        "data_uris": p.data_uris,
        "sri_missing_external_scripts": p.sri_missing_external_scripts,
        "directory_listing": title.lower().startswith("index of /"),
        "tags_truncated": p.truncated,
    }
