"""Request boundary: URL parsing, destination policy, and validated DNS resolution.

Design (see docs/SECURITY.md):
- Parse with ada-url (WHATWG URL Standard, the parser browsers and Node use), so the host we
  validate is the host a browser would contact. IPv4 shorthand (2130706433, 0x7f.1, 127.1,
  0177.0.0.1) and percent-encoded hosts are normalized before policy checks.
- Only http/https, only ports in ALLOWED_PORTS, no credentials in URLs, no internal names.
- Every resolved address must be globally routable; IPv6 forms that embed IPv4
  (mapped, NAT64, 6to4, Teredo) are checked on the embedded address too.
- If ANY resolved address is non-public, the host is blocked (mixed answers are a rebinding
  and split-horizon red flag). The fetcher connects only to the addresses returned here.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import dns.exception
import dns.resolver
import idna
from ada_url import URL

ALLOWED_SCHEMES = {"http", "https"}
DEFAULT_PORTS = {"http": 80, "https": 443}
ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_URL_LENGTH = 2048
BLOCKED_SUFFIXES = (
    ".localhost", ".local", ".localdomain", ".internal", ".intranet", ".corp", ".lan",
    ".home.arpa", ".home", ".onion", ".test", ".invalid", ".example", ".arpa",
)
BLOCKED_NAMES = {"localhost", "metadata", "metadata.google.internal", "instance-data"}
NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")
NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
# Explicit blocks from the IANA special-purpose registries. Needed because ipaddress.is_global
# returns True for some of these on CPython 3.13 (verified 2026-11-08, see RESEARCH.md).
EXPLICIT_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/96",  # IPv4-compatible (deprecated), includes ::127.0.0.1
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
    "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
)]

_REFANG = [
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"^hXXp", re.I), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
]


class UrlRejected(ValueError):
    """The input cannot be interpreted as an http(s) URL at all."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ParsedUrl:
    raw: str
    href: str  # WHATWG-serialized URL (fragment removed)
    scheme: str
    host: str  # ASCII (A-label) host, lowercase, no trailing dot; IPv6 without brackets
    host_unicode: str  # U-label form for display/homograph analysis ('' if not decodable)
    port: int
    explicit_port: bool
    path_query: str
    username_present: bool
    is_ip: bool

    @property
    def origin(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{h}" + ("" if self.port == DEFAULT_PORTS[self.scheme] else f":{self.port}")

    def request_target(self) -> str:
        return self.path_query or "/"


def refang(text: str) -> str:
    s = text.strip().strip("<>\"'`")
    for rx, rep in _REFANG:
        s = rx.sub(rep, s)
    return s


def defang(url: str) -> str:
    """Make a URL non-clickable for display: hxxps://example[.]com/path."""
    s = re.sub(r"^http", "hxxp", url, flags=re.I)
    m = re.match(r"^([a-z]+://)([^/?#]*)(.*)$", s, flags=re.I | re.S)
    if not m:
        return s.replace(".", "[.]")
    return m.group(1) + m.group(2).replace(".", "[.]") + m.group(3)


def parse_url(raw: str) -> ParsedUrl:
    """Parse a submitted URL or bare domain. Raises UrlRejected for unusable input.

    This does not decide whether the URL may be fetched; see fetch_block_reason().
    """
    if not raw or not raw.strip():
        raise UrlRejected("empty", "No URL or domain was provided.")
    s = refang(raw)
    if len(s) > MAX_URL_LENGTH:
        raise UrlRejected("too_long", f"URL longer than {MAX_URL_LENGTH} characters.")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s):
        raise UrlRejected("control_chars", "URL contains control characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", s):
        s = "https://" + s.lstrip("/")
    elif re.match(r"^[a-zA-Z0-9.-]+:\d+(/|$)", s):  # host:port without scheme
        s = "https://" + s
    try:
        u = URL(s)
    except ValueError as e:
        raise UrlRejected("unparseable", "The input is not a valid URL.") from e
    scheme = u.protocol.rstrip(":").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlRejected("scheme", f"Only http and https URLs can be investigated (got '{scheme}').")
    host = u.hostname
    if not host:
        raise UrlRejected("no_host", "URL has no host.")
    is_ip = False
    if host.startswith("["):
        host = host[1:-1]
        is_ip = True
    else:
        host = host.rstrip(".").lower()
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            pass
    if not host:
        raise UrlRejected("no_host", "URL has no host.")
    try:
        host_unicode = host if is_ip else idna.decode(host)
    except idna.IDNAError:
        host_unicode = ""
    port = int(u.port) if u.port else DEFAULT_PORTS[scheme]
    u.hash = ""
    path_query = (u.pathname or "/") + (u.search or "")
    return ParsedUrl(
        raw=raw.strip()[:MAX_URL_LENGTH],
        href=u.href,
        scheme=scheme,
        host=host,
        host_unicode=host_unicode,
        port=port,
        explicit_port=bool(u.port),
        path_query=path_query,
        username_present=bool(u.username or u.password),
        is_ip=is_ip,
    )


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip in NAT64_WKP:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]  # (server, client); client is the obfuscated-decoded address
    return None


def ip_block_reason(addr: str) -> str | None:
    """Return why an address must not be contacted, or None if it is publicly routable."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "not an IP address"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id:
            return "IPv6 address with zone identifier"
        if ip in NAT64_LOCAL:
            return "local-use NAT64 prefix (64:ff9b:1::/48)"
        inner = _embedded_ipv4(ip)
        if inner is not None:
            r = ip_block_reason(str(inner))
            if r:
                return f"IPv6 address embeds a blocked IPv4 address ({inner}: {r})"
            if ip.ipv4_mapped or ip in NAT64_WKP:
                return None  # embedded public IPv4 is acceptable
            if ip.sixtofour or ip.teredo:
                return "transition-mechanism address (6to4/Teredo) is not contacted"
    for net in EXPLICIT_BLOCKED:
        if ip.version == net.version and ip in net:
            if ip.is_loopback:
                return "loopback address"
            if ip.is_link_local:
                return "link-local address (includes cloud metadata 169.254.169.254)"
            return f"special-purpose address range {net}"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address (includes cloud metadata 169.254.169.254)"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_private:
        return "private or special-purpose address"
    if ip.is_reserved:
        return "reserved address"
    if not ip.is_global:
        return "address is not globally routable (e.g. shared/CGNAT 100.64.0.0/10)"
    return None


def host_block_reason(host: str) -> str | None:
    h = host.lower().rstrip(".")
    if h in BLOCKED_NAMES or any(h.endswith(s) or h == s[1:] for s in BLOCKED_SUFFIXES):
        return f"internal or reserved hostname '{h}'"
    if "." not in h and ":" not in h:
        return f"single-label hostname '{h}' (resolves only on internal networks)"
    return None


def fetch_block_reason(p: ParsedUrl) -> str | None:
    """Policy check before any network activity for this URL (no DNS yet)."""
    if p.username_present:
        return "credentials embedded in the URL (user:password@host) are never sent; the URL is analysed statically only"
    if p.port not in ALLOWED_PORTS:
        return f"port {p.port} is not an allowed web port ({', '.join(map(str, sorted(ALLOWED_PORTS)))})"
    if p.is_ip:
        return ip_block_reason(p.host)
    return host_block_reason(p.host)


@dataclass(frozen=True)
class Resolution:
    host: str
    addresses: tuple[str, ...]  # validated public addresses, in connection order
    blocked: tuple[tuple[str, str], ...]  # (address, reason)
    cnames: tuple[str, ...]
    error: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.addresses) and not self.blocked and self.error is None


def resolve(host: str, *, timeout: float = 4.0, resolver: dns.resolver.Resolver | None = None) -> Resolution:
    """Resolve A and AAAA records and validate every answer.

    If any answer is non-public the whole host is treated as blocked.
    """
    if ":" in host or re.fullmatch(r"[0-9.]+", host):
        r = ip_block_reason(host)
        return Resolution(host, () if r else (host,), ((host, r),) if r else (), ())
    res = resolver or dns.resolver.Resolver()
    res.lifetime = timeout
    addrs: list[str] = []
    cnames: list[str] = []
    errors: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ans = res.resolve(host, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return Resolution(host, (), (), (), "NXDOMAIN: the domain does not exist")
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            errors.append(f"{rtype}: {type(e).__name__}")
            continue
        if ans.canonical_name and ans.canonical_name.to_text().rstrip(".").lower() != host:
            cn = ans.canonical_name.to_text().rstrip(".").lower()
            if cn not in cnames:
                cnames.append(cn)
        if ans.rrset is not None:
            addrs.extend(r.to_text() for r in ans.rrset)
    if not addrs:
        return Resolution(host, (), (), tuple(cnames), "; ".join(errors) or "no A/AAAA records")
    blocked = tuple((a, r) for a in addrs if (r := ip_block_reason(a)))
    public = tuple(a for a in addrs if not ip_block_reason(a))
    # Prefer IPv4 first for reliability on hosts without IPv6 connectivity.
    public = tuple(sorted(public, key=lambda a: ":" in a))
    return Resolution(host, public if not blocked else (), blocked, tuple(cnames))
