"""Safe fetcher: pinned connections, TLS capture, manual redirects, hard limits.

Runs inside the isolated inspector subprocess (wtd.inspector). Never executes scripts, never
saves files, never downloads non-text payloads, never sends cookies or credentials.

Test seams: `resolve_fn`, `ip_policy` and `connect_fn` exist only as Python arguments so unit
tests can drive local fixture servers. The production entry point (wtd.inspector.main) never
exposes them, and no environment variable or API field can change them.
"""
from __future__ import annotations

import base64
import socket
import ssl
import time
import zlib
from dataclasses import dataclass, field
from typing import Callable

import h11
from ada_url import URL

from . import netguard
from .htmlfeatures import extract_features

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0 Safari/537.36 WTD-Inspector/0.1 (passive security analysis)"
)
TEXT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")


@dataclass(frozen=True)
class Limits:
    max_redirects: int = 5
    connect_timeout: float = 5.0
    read_timeout: float = 8.0
    total_timeout: float = 25.0
    max_body_bytes: int = 1_000_000
    max_decoded_bytes: int = 2_000_000
    max_header_bytes: int = 64 * 1024
    max_addresses_tried: int = 2


@dataclass
class TlsCapture:
    version: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    chain_der_b64: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class HopResult:
    index: int
    url: str
    host: str
    ip: str | None = None
    status: int | None = None
    reason: str | None = None
    location: str | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    blocked_reason: str | None = None
    error: str | None = None
    tls: TlsCapture | None = None
    duration_ms: int = 0
    resolved: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)


@dataclass
class FetchResult:
    requested_url: str
    hops: list[HopResult] = field(default_factory=list)
    final_url: str | None = None
    final_status: int | None = None
    content_type: str | None = None
    body_bytes: int = 0
    body_truncated: bool = False
    body_note: str | None = None
    features: dict | None = None
    stop_reason: str | None = None
    total_ms: int = 0


class FetchError(Exception):
    pass


ResolveFn = Callable[[str], netguard.Resolution]
IpPolicy = Callable[[str], "str | None"]
ConnectFn = Callable[[str, int, float], socket.socket]


def _default_connect(ip: str, port: int, timeout: float) -> socket.socket:
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
    except BaseException:
        s.close()
        raise
    return s


def _tls_context() -> ssl.SSLContext:
    # Capture mode: we must see invalid/expired/self-signed chains to report on them.
    # Trust is evaluated separately by wtd.checks.tls_checks on the captured chain.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


class _Deadline:
    def __init__(self, seconds: float):
        self.end = time.monotonic() + seconds

    def remaining(self, cap: float) -> float:
        r = self.end - time.monotonic()
        if r <= 0:
            raise FetchError("total time limit exceeded")
        return min(cap, r)


def _bounded_decode(data: bytes, encoding: str, limit: int) -> tuple[bytes, str | None]:
    enc = encoding.lower().strip()
    if enc in ("", "identity"):
        return data, None
    if enc in ("gzip", "x-gzip", "deflate"):
        wbits = 16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(data, limit)
        except zlib.error:
            if enc == "deflate":  # raw deflate fallback
                d = zlib.decompressobj(-zlib.MAX_WBITS)
                out = d.decompress(data, limit)
            else:
                return b"", f"{enc} body could not be decompressed"
        note = "decompressed body truncated at limit" if d.unconsumed_tail else None
        return out, note
    return b"", f"unsupported content-encoding '{enc}' (body not decoded)"


def _charset(content_type: str, body: bytes) -> str:
    ct = content_type.lower()
    if "charset=" in ct:
        cs = ct.split("charset=", 1)[1].split(";")[0].strip().strip('"\'')
        try:
            "".encode(cs)
            return cs
        except LookupError:
            pass
    head = body[:2048].lower()
    i = head.find(b"charset=")
    if i != -1:
        cs = head[i + 8 : i + 40].split(b'"')[0].split(b"'")[0].split(b";")[0].split(b">")[0].strip().strip(b'"\'').decode("ascii", "ignore")
        try:
            "".encode(cs)
            return cs
        except LookupError:
            pass
    return "utf-8"


def _one_request(
    parsed: netguard.ParsedUrl,
    ip: str,
    hop: HopResult,
    limits: Limits,
    deadline: _Deadline,
    connect_fn: ConnectFn,
    want_body: bool,
) -> tuple[bytes, bool, str | None]:
    """Perform one GET to a pinned IP. Returns (body, truncated, note)."""
    sock = connect_fn(ip, parsed.port, deadline.remaining(limits.connect_timeout))
    try:
        if parsed.scheme == "https":
            sni = None if parsed.is_ip else parsed.host
            tls_sock = _tls_context().wrap_socket(sock, server_hostname=sni)
            cap = TlsCapture(version=tls_sock.version())
            c = tls_sock.cipher()
            if c:
                cap.cipher, cap.cipher_bits = c[0], c[2]
            try:
                cap.chain_der_b64 = [base64.b64encode(d).decode() for d in tls_sock.get_unverified_chain()[:8]]
            except Exception as e:  # pragma: no cover - defensive
                cap.error = f"chain capture failed: {type(e).__name__}"
            hop.tls = cap
            sock = tls_sock
        host_header = parsed.host if ":" not in parsed.host else f"[{parsed.host}]"
        if parsed.explicit_port and parsed.port != netguard.DEFAULT_PORTS[parsed.scheme]:
            host_header += f":{parsed.port}"
        conn = h11.Connection(h11.CLIENT, max_incomplete_event_size=limits.max_header_bytes)
        req = h11.Request(
            method="GET",
            target=parsed.request_target(),
            headers=[
                ("Host", host_header),
                ("User-Agent", USER_AGENT),
                ("Accept", "text/html,application/xhtml+xml;q=0.9,text/plain;q=0.8,*/*;q=0.1"),
                ("Accept-Encoding", "gzip, deflate"),
                ("Accept-Language", "en"),
                ("Connection", "close"),
            ],
        )
        sock.sendall(conn.send(req) + conn.send(h11.EndOfMessage()))
        body = bytearray()
        truncated = False
        note = None
        while True:
            ev = conn.next_event()
            if ev is h11.NEED_DATA:
                sock.settimeout(deadline.remaining(limits.read_timeout))
                data = sock.recv(65536)
                conn.receive_data(data)
                continue
            if isinstance(ev, h11.Response):
                hop.status = ev.status_code
                hop.reason = ev.reason.decode("latin-1", "replace")[:80]
                hop.headers = [(k.decode("latin-1").lower(), v.decode("latin-1", "replace")[:2048]) for k, v in ev.headers][:100]
                hdr = dict(hop.headers)
                if 300 <= ev.status_code < 400 or not want_body:
                    break
                ctype = hdr.get("content-type", "")
                if not any(t in ctype.lower() for t in TEXT_TYPES) and ctype:
                    note = f"non-text content ({ctype[:80]}) was not downloaded"
                    break
                continue
            if isinstance(ev, h11.Data):
                room = limits.max_body_bytes - len(body)
                body += ev.data[:room]
                if len(ev.data) > room:
                    truncated = True
                    break
                continue
            if isinstance(ev, (h11.EndOfMessage, h11.ConnectionClosed)):
                break
            if isinstance(ev, h11.InformationalResponse):
                continue
        return bytes(body), truncated, note
    finally:
        try:
            sock.close()
        except Exception:
            pass


def fetch(
    url: str,
    limits: Limits = Limits(),
    *,
    resolve_fn: ResolveFn | None = None,
    ip_policy: IpPolicy | None = None,
    connect_fn: ConnectFn | None = None,
) -> FetchResult:
    t_start = time.monotonic()
    resolve_fn = resolve_fn or (lambda h: netguard.resolve(h))
    ip_policy = ip_policy or netguard.ip_block_reason
    connect_fn = connect_fn or _default_connect
    deadline = _Deadline(limits.total_timeout)
    result = FetchResult(requested_url=url)
    seen: set[str] = set()
    current = url
    try:
        for index in range(limits.max_redirects + 1):
            t_hop = time.monotonic()
            try:
                parsed = netguard.parse_url(current)
            except netguard.UrlRejected as e:
                result.hops.append(HopResult(index, current[:2048], "", blocked_reason=str(e)))
                result.stop_reason = f"redirect target rejected: {e}"
                break
            hop = HopResult(index, parsed.href, parsed.host)
            result.hops.append(hop)
            if parsed.href in seen:
                hop.blocked_reason = "redirect loop"
                result.stop_reason = "redirect loop detected"
                break
            seen.add(parsed.href)
            reason = netguard.fetch_block_reason(parsed)
            if parsed.is_ip and reason is None:
                reason = ip_policy(parsed.host)
            if reason:
                hop.blocked_reason = reason
                result.stop_reason = f"destination blocked by policy: {reason}"
                break
            if parsed.is_ip:
                addresses = [parsed.host]
            else:
                res = resolve_fn(parsed.host)
                hop.cnames = list(res.cnames)
                if res.error:
                    hop.error = f"DNS: {res.error}"
                    result.stop_reason = f"DNS resolution failed: {res.error}"
                    break
                bad = [(a, r) for a in res.addresses if (r := ip_policy(a))] + list(res.blocked)
                if bad:
                    hop.resolved = [a for a, _ in bad]
                    hop.blocked_reason = f"{parsed.host} resolves to a non-public address ({bad[0][0]}: {bad[0][1]})"
                    result.stop_reason = f"destination blocked by policy: {hop.blocked_reason}"
                    break
                addresses = list(res.addresses)
                hop.resolved = addresses
            body, truncated, note = b"", False, None
            last_err: Exception | None = None
            for ip in addresses[: limits.max_addresses_tried]:
                # Re-check immediately before connecting: the connection uses exactly this address.
                if ip_policy(ip):
                    continue
                try:
                    hop.ip = ip
                    body, truncated, note = _one_request(parsed, ip, hop, limits, deadline, connect_fn, want_body=True)
                    last_err = None
                    break
                except FetchError:
                    raise
                except (OSError, ssl.SSLError, h11.RemoteProtocolError, h11.LocalProtocolError) as e:
                    last_err = e
                    continue
            hop.duration_ms = int((time.monotonic() - t_hop) * 1000)
            if last_err is not None or hop.status is None:
                hop.error = f"{type(last_err).__name__}: {str(last_err)[:200]}" if last_err else "no response"
                result.stop_reason = f"connection failed: {hop.error}"
                break
            if 300 <= hop.status < 400:
                loc = dict(hop.headers).get("location")
                if not loc:
                    result.stop_reason = "redirect without Location header"
                    result.final_url, result.final_status = parsed.href, hop.status
                    break
                try:
                    nxt = URL(loc, parsed.href).href
                except ValueError:
                    hop.location = loc[:2048]
                    result.stop_reason = "invalid redirect Location"
                    break
                hop.location = nxt
                current = nxt
                if index == limits.max_redirects:
                    result.stop_reason = f"more than {limits.max_redirects} redirects"
                continue
            # Final response
            hdr = dict(hop.headers)
            result.final_url, result.final_status = parsed.href, hop.status
            result.content_type = hdr.get("content-type")
            decoded, dnote = _bounded_decode(body, hdr.get("content-encoding", ""), limits.max_decoded_bytes)
            result.body_bytes = len(body)
            result.body_truncated = truncated
            result.body_note = note or dnote
            if decoded and result.content_type and "html" in result.content_type.lower():
                text = decoded.decode(_charset(result.content_type, decoded), errors="replace")
                result.features = extract_features(text, base_url=parsed.href)
            elif decoded:
                text = decoded.decode(_charset(result.content_type or "", decoded), errors="replace")
                result.features = {"kind": "text", "text_excerpt": text[:1500]}
            break
    except FetchError as e:
        result.stop_reason = str(e)
    result.total_ms = int((time.monotonic() - t_start) * 1000)
    return result


def probe_http_upgrade(host: str, limits: Limits = Limits(max_redirects=0, total_timeout=8.0), **kw) -> dict:
    """One request to http://host/ to see whether it redirects to HTTPS (no body read)."""
    r = fetch(f"http://{host}/", limits, **kw)
    first = r.hops[0] if r.hops else None
    return {
        "status": first.status if first else None,
        "location": first.location if first else None,
        "redirects_to_https": bool(first and first.location and first.location.startswith("https://")),
        "error": (first.error or first.blocked_reason) if first else r.stop_reason,
    }
