"""Request-boundary tests: URL parsing tricks, address policy, and the fetcher against local fixtures.

The fetcher's resolve/policy/connect seams are used ONLY here, to reach a loopback fixture server
while every other destination keeps the production policy.
"""
import gzip
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wtd import netguard
from wtd.fetcher import Limits, fetch

BLOCKED = ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
           "198.18.0.1", "::1", "::", "fe80::1", "fc00::1", "fec0::1", "ff02::1", "::127.0.0.1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
           "64:ff9b::a9fe:a9fe", "2002:c0a8:0101::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "5f00::1", "2001:db8::1"]
ALLOWED = ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"]


@pytest.mark.parametrize("ip", BLOCKED)
def test_blocked_addresses(ip):
    assert netguard.ip_block_reason(ip) is not None


@pytest.mark.parametrize("ip", ALLOWED)
def test_public_addresses(ip):
    assert netguard.ip_block_reason(ip) is None


@pytest.mark.parametrize("url,host", [
    ("http://2130706433/", "127.0.0.1"), ("http://0x7f.1/", "127.0.0.1"), ("http://127.1/", "127.0.0.1"), ("http://0177.0.0.1/", "127.0.0.1"),
    ("http://%31%32%37.0.0.1/", "127.0.0.1"), ("https://evil.com\\@good.com/", "evil.com"), ("https://аpple.com/", "xn--pple-43d.com"),
    ("hxxps://bad[.]example[.]top/x", "bad.example.top"), ("Example.COM.", "example.com"),
])
def test_parser_normalises_like_browsers(url, host):
    assert netguard.parse_url(url).host == host


@pytest.mark.parametrize("url", ["http://2130706433/", "http://[::ffff:127.0.0.1]/", "http://localhost/", "http://intranet/", "http://x.internal/",
                                 "https://user:pw@example.com/", "https://example.com:22/", "http://169.254.169.254/latest/meta-data"])
def test_fetch_policy_blocks_before_network(url):
    assert netguard.fetch_block_reason(netguard.parse_url(url)) is not None


@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///etc/passwd", "ftp://example.com/", "gopher://x/", "", "https://exa mple.com/"])
def test_unusable_inputs_rejected(url):
    with pytest.raises(netguard.UrlRejected):
        netguard.parse_url(url)


# ------------------------------------------------------------------ fixture server
BIG = b"<html><title>big</title>" + b"A" * 3_000_000
BOMB = gzip.compress(b"<html>" + b"\0" * 50_000_000)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        p = self.path
        if p == "/ok":
            self._send(200, b"<html><title>Fixture</title><form action='https://collector.example/x'><input type=password name=pw></form></html>",
                       [("Content-Type", "text/html")])
        elif p == "/to-private":
            self._send(302, headers=[("Location", "http://internal.fixture:8080/secret")])
        elif p == "/to-metadata":
            self._send(302, headers=[("Location", "http://169.254.169.254/latest/meta-data")])
        elif p == "/to-mixed":
            self._send(302, headers=[("Location", "http://mixed.fixture:8080/ok")])
        elif p == "/loop":
            self._send(302, headers=[("Location", "/loop")])
        elif p.startswith("/chain"):
            n = int(p.split("/")[-1])
            self._send(302, headers=[("Location", f"/chain/{n + 1}")])
        elif p == "/big":
            self._send(200, BIG, [("Content-Type", "text/html")])
        elif p == "/bomb":
            self._send(200, BOMB, [("Content-Type", "text/html"), ("Content-Encoding", "gzip")])
        elif p == "/slow":
            time.sleep(3)
            self._send(200, b"<html>late</html>", [("Content-Type", "text/html")])
        elif p == "/download":
            self._send(200, b"MZ" + b"\0" * 5000, [("Content-Type", "application/x-msdownload")])
        else:
            self._send(404, b"nf", [("Content-Type", "text/plain")])


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


DNS = {"site.fixture": ("127.0.0.1",), "internal.fixture": ("10.0.0.5",), "mixed.fixture": ("127.0.0.1", "192.168.0.7")}


def _resolve(host):
    addrs = DNS.get(host)
    if addrs is None:
        return netguard.Resolution(host, (), (), (), "NXDOMAIN: the domain does not exist")
    blocked = tuple((a, r) for a in addrs if (r := _policy(a)))
    return netguard.Resolution(host, tuple(a for a in addrs if not _policy(a)) if not blocked else (), blocked, ())


def _policy(ip):
    return None if ip == "127.0.0.1" else netguard.ip_block_reason(ip)  # loopback allowed ONLY for the fixture


def _go(port, path, **kw):
    def connect(ip, _port, timeout):
        assert ip == "127.0.0.1", f"fetcher tried to connect to {ip}"
        return socket.create_connection((ip, port), timeout=timeout)
    return fetch(f"http://site.fixture:8080{path}", kw.pop("limits", Limits()), resolve_fn=_resolve, ip_policy=_policy, connect_fn=connect)


def test_ok_page_features(server):
    r = _go(server, "/ok")
    assert r.final_status == 200 and r.features["password_fields"] == 1
    assert r.features["forms"][0]["external"] is True


def test_redirect_to_private_dns_is_blocked(server):
    r = _go(server, "/to-private")
    assert r.final_status is None and "non-public" in r.stop_reason
    assert r.hops[-1].ip is None  # never connected


def test_redirect_to_metadata_literal_is_blocked(server):
    r = _go(server, "/to-metadata")
    assert "blocked by policy" in r.stop_reason and "link-local" in r.stop_reason


def test_mixed_public_private_dns_answer_is_blocked(server):
    r = _go(server, "/to-mixed")
    assert r.final_status is None and "non-public" in r.stop_reason


def test_redirect_loop_detected(server):
    r = _go(server, "/loop")
    assert r.stop_reason == "redirect loop detected"


def test_redirect_limit(server):
    r = _go(server, "/chain/0", limits=Limits(max_redirects=3))
    assert "more than 3 redirects" in r.stop_reason and len(r.hops) == 4


def test_oversized_body_truncated(server):
    r = _go(server, "/big")
    assert r.body_truncated and r.body_bytes <= Limits().max_body_bytes


def test_decompression_bomb_bounded(server):
    r = _go(server, "/bomb")
    assert r.final_status == 200 and r.body_note and "truncated" in r.body_note


def test_timeout_enforced(server):
    t = time.monotonic()
    r = _go(server, "/slow", limits=Limits(read_timeout=1.0, total_timeout=2.0))
    assert time.monotonic() - t < 3 and r.final_status is None


def test_binary_download_not_read(server):
    r = _go(server, "/download")
    assert r.body_bytes == 0 and "not downloaded" in r.body_note


def test_nxdomain_reported():
    r = fetch("http://missing.fixture:8080/", resolve_fn=_resolve, ip_policy=_policy)
    assert "NXDOMAIN" in r.stop_reason
