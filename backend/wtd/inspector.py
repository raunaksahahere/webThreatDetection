"""Isolated inspector: runs the network fetch and hostile-HTML parsing in a child process.

Defense in depth (not a VM or container):
- separate process, environment scrubbed (no API keys, no proxy variables),
- rlimits: address space, CPU seconds, open files, no core dumps, no file writes,
- wall-clock timeout enforced by the parent, output size capped, output validated.
The child receives only {"url": ...} on stdin; no test seams are reachable from here.
"""
from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys

CHILD_TIMEOUT_S = 40
MAX_OUTPUT_BYTES = 4_000_000


def _limit_child() -> None:  # runs in the child before exec
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    os.setsid()


def run_inspection(url: str, *, http_upgrade_probe: bool = True) -> dict:
    """Run the fetch in an isolated child process. Returns a dict (never raises on child failure)."""
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONHASHSEED": "random"}
    payload = json.dumps({"url": url, "http_upgrade_probe": http_upgrade_probe}).encode()
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-m", "wtd.inspector"],
            input=payload,
            capture_output=True,
            timeout=CHILD_TIMEOUT_S,
            env=env,
            preexec_fn=_limit_child,
            cwd="/",
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"inspector exceeded {CHILD_TIMEOUT_S}s wall-clock limit and was killed"}
    if len(proc.stdout) > MAX_OUTPUT_BYTES:
        return {"ok": False, "error": "inspector output exceeded size limit"}
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["no stderr"]
        return {"ok": False, "error": f"inspector exited with code {proc.returncode}: {tail[0][:200]}"}
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": "inspector returned invalid JSON"}
    if not isinstance(out, dict) or "fetch" not in out:
        return {"ok": False, "error": "inspector returned an unexpected structure"}
    out["ok"] = True
    return out


def main() -> None:
    from .fetcher import fetch, probe_http_upgrade
    from .netguard import UrlRejected, parse_url

    req = json.loads(sys.stdin.buffer.read(65536))
    url = str(req.get("url", ""))[:2048]
    result = fetch(url)
    out: dict = {"fetch": dataclasses.asdict(result)}
    # Revocation (OCSP): responder URL comes from the certificate, so it goes through the same request policy.
    try:
        import base64 as _b64

        from .checks.tls_checks import ocsp_request_url
        from .fetcher import Limits as _L

        tls_hop = next((h for h in reversed(result.hops) if h.tls and len(h.tls.chain_der_b64) >= 2), None)
        if tls_hop:
            built = ocsp_request_url([_b64.b64decode(c) for c in tls_hop.tls.chain_der_b64])
            if built:
                o = fetch(built[0], _L(max_redirects=1, total_timeout=8.0, max_body_bytes=65536, max_decoded_bytes=65536),
                          accept_types=("application/ocsp-response",))
                out["ocsp"] = {"host": tls_hop.host, "responder": built[0].split("/")[2][:120], "status": o.final_status,
                               "body_b64": o.body_b64, "error": o.stop_reason or o.body_note}
    except Exception as e:  # revocation is best-effort
        out["ocsp"] = {"error": f"OCSP check failed: {type(e).__name__}"}
    if req.get("http_upgrade_probe"):
        try:
            p = parse_url(url)
            if p.scheme == "https" and not p.is_ip:
                out["http_upgrade"] = probe_http_upgrade(p.host)
        except UrlRejected:
            pass
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
