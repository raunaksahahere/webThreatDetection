"""The CT lookup inside the real analysis pipeline: wiring, concurrency, and failure containment.

The inspector, DNS and intelligence are replaced with fakes; the TLS chain is a synthetic fixture and the CT service is mocked."""
import base64
import json
import time

import httpx
import pytest
from cryptography.x509.verification import Store

from wtd import intel, pipeline
from wtd.checks import ct_checks, dns_checks, tls_checks
from wtd.checks.ct_checks import CtClient
from wtd.models import CheckResult, CheckStatus, Module
from wtd.tls_fixtures import build

HOST = "demo.wtd.test"


@pytest.fixture
def world(monkeypatch):
    chain, root = build("valid", host=HOST)
    insp = {"ok": True, "http_upgrade": None, "ocsp": None, "fetch": {
        "hops": [{"index": 0, "url": f"https://{HOST}/", "host": HOST, "ip": "93.184.216.34", "status": 200, "headers": [["server", "fixture"]],
                  "duration_ms": 5, "tls": {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "chain_der_b64": [base64.b64encode(c).decode() for c in chain]}}],
        "final_status": 200, "final_url": f"https://{HOST}/", "stop_reason": None, "body_bytes": 12, "content_type": "text/html",
        "features": {"title": "Fixture", "forms": [], "password_fields": 0}}}
    monkeypatch.setattr(pipeline, "run_inspection", lambda url, **k: insp)
    monkeypatch.setattr(pipeline, "fetch_block_reason", lambda p: None)
    monkeypatch.setattr(tls_checks, "default_store", lambda: Store([root]))
    ok = CheckResult(name="dns.records", module=Module.dns, status=CheckStatus.succeeded, essential=False)
    monkeypatch.setattr(dns_checks, "dns_records", lambda reg, **k: ({}, ok))
    monkeypatch.setattr(dns_checks, "domain_age", lambda reg: ([], {}, CheckResult(name="dns.domain_age", module=Module.dns, status=CheckStatus.unavailable, essential=False)))
    monkeypatch.setattr(intel, "lookup", lambda *a, **k: intel.IntelOutcome())
    monkeypatch.setenv("WTD_CT", "1")
    return chain


def analyse(url=f"https://{HOST}/"):
    r = pipeline.new_report("url", "x", url)
    pipeline.analyse_url(r.id, url)
    return pipeline.STORE.get(r.id)


def entry_for(chain, cert_spki=None):
    lf = ct_checks.leaf_from_chain(chain[0], {"leaf_dns_names": [HOST], "embedded_scts": 0, "chain_trusted": True})
    return {"id": "9", "tbs_sha256": "aa" * 32, "cert_sha256": lf.sha256, "dns_names": [HOST], "pubkey_sha256": cert_spki or lf.spki_sha256,
            "issuer": {"name": "CN=WTD Synthetic Intermediate CA"}, "not_before": lf.not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_after": lf.not_after.strftime("%Y-%m-%dT%H:%M:%SZ")}


def mock_ct(monkeypatch, handler):
    monkeypatch.setattr(ct_checks, "CT", CtClient(transport=httpx.MockTransport(handler)))


def test_ct_result_reaches_the_report(world, monkeypatch):
    mock_ct(monkeypatch, lambda r: httpx.Response(200, content=json.dumps([entry_for(world)]).encode()))
    rep = analyse()
    chk = next(c for c in rep.checks if c.name == "tls.ct_lookup")
    assert rep.status == "complete" and chk.status == "succeeded" and chk.essential is False
    assert "presented certificate listed" in chk.detail
    assert rep.tls["ct_lookup"]["certificates"] == 1 and rep.tls["ct_lookup"]["sources"] == ["Cert Spotter"]
    f = next(x for x in rep.findings if x.code == "tls.ct_records")
    assert f.severity == "info" and f.source.startswith("Certificate Transparency record lookup")
    assert rep.assessment.classification == "Low Risk"
    assert any("Certificate Transparency records come from" in l for l in rep.limitations)


def test_embedded_sct_inspection_is_unchanged(world, monkeypatch):
    mock_ct(monkeypatch, lambda r: httpx.Response(200, content=b"[]"))
    rep = analyse()
    assert "embedded_scts" in rep.tls and rep.tls["embedded_scts"] == 0
    assert any(f.code == "tls.no_sct" for f in rep.findings)  # the existing check still runs alongside the lookup


def test_unavailable_ct_service_does_not_change_the_verdict_or_fail_the_analysis(world, monkeypatch):
    mock_ct(monkeypatch, lambda r: httpx.Response(503))
    rep = analyse()
    chk = next(c for c in rep.checks if c.name == "tls.ct_lookup")
    assert rep.status == "complete" and chk.status == "unavailable" and "not a risk signal" in chk.detail
    assert rep.assessment.classification == "Low Risk" and "tls.ct_lookup" not in rep.assessment.coverage.essential_missing


def test_a_crash_in_the_ct_code_is_contained(world, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(ct_checks, "analyse", boom)
    rep = analyse()
    chk = next(c for c in rep.checks if c.name == "tls.ct_lookup")
    assert rep.status == "complete" and chk.status == "failed" and "RuntimeError" in chk.detail


def test_ct_runs_while_dns_runs(world, monkeypatch):
    """The lookup overlaps the DNS/RDAP steps: with both slow, the total is about the larger, not the sum."""
    def slow(req):
        time.sleep(0.6)
        return httpx.Response(200, content=json.dumps([entry_for(world)]).encode())

    mock_ct(monkeypatch, slow)
    ok = CheckResult(name="dns.records", module=Module.dns, status=CheckStatus.succeeded, essential=False)
    monkeypatch.setattr(dns_checks, "dns_records", lambda reg, **k: (time.sleep(0.6), ({}, ok))[1])
    t0 = time.monotonic()
    rep = analyse()
    assert rep.status == "complete" and time.monotonic() - t0 < 1.1


def test_ip_site_skips_the_lookup(world, monkeypatch):
    mock_ct(monkeypatch, lambda r: pytest.fail("no CT request may be made for an IP address"))
    r = ct_checks.analyse("203.0.113.9", ct_checks.leaf_from_chain(world[0], {"leaf_dns_names": [], "embedded_scts": 0, "chain_trusted": True}))
    assert r[1].status == CheckStatus.skipped
