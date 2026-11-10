"""Certificate Transparency record lookup: parsing, dedupe, wildcard handling, failure modes, and what it may not do.

All network traffic is mocked (httpx.MockTransport); nothing here reaches a real CT service."""
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from wtd.checks import ct_checks
from wtd.checks.ct_checks import CT, CtClient, CtEntry, Leaf, analyse, covers, dedupe, matches_leaf, parse_certspotter, parse_crtsh
from wtd.classify import classify
from wtd.models import CheckResult, CheckStatus, Module
from wtd.tls_fixtures import build

@pytest.fixture(autouse=True)
def _ct_on(monkeypatch):
    monkeypatch.setenv("WTD_CT", "1")  # conftest turns CT off globally so no other test can reach a real service


NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
SPKI = "ab" * 32
OLD = NOW - timedelta(days=60)


def leaf(**kw) -> Leaf:
    d = dict(sha256="cd" * 32, spki_sha256=SPKI, serial="1a2b3c", not_before=OLD, not_after=OLD + timedelta(days=90),
             dns_names=["shop.example.com"], sct_count=2, publicly_trusted=True)
    d.update(kw)
    return Leaf(**d)


def cs_entry(names=("shop.example.com",), nb=OLD, na=OLD + timedelta(days=90), spki=SPKI, tbs="11" * 32, sha="cd" * 32, issuer="C=US, O=Example CA, CN=Example R1", id="1"):
    return {"id": id, "tbs_sha256": tbs, "cert_sha256": sha, "dns_names": list(names), "pubkey_sha256": spki,
            "issuer": {"name": issuer}, "not_before": nb.strftime("%Y-%m-%dT%H:%M:%SZ"), "not_after": na.strftime("%Y-%m-%dT%H:%M:%SZ")}


def crt_entry(names="shop.example.com", nb=OLD, na=OLD + timedelta(days=90), serial="001A2B3C", issuer="C=US, O=Example CA, CN=Example R1"):
    return {"issuer_name": issuer, "name_value": names, "common_name": names.split("\n")[0], "serial_number": serial,
            "not_before": nb.strftime("%Y-%m-%dT%H:%M:%S"), "not_after": na.strftime("%Y-%m-%dT%H:%M:%S")}


def client(routes, **kw) -> tuple[CtClient, list[str]]:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(f"{req.url.host}?{req.url.query.decode()}")
        r = routes[req.url.host]
        if isinstance(r, Exception):
            raise r
        return r(req) if callable(r) else r

    return CtClient(transport=httpx.MockTransport(handler), **kw), seen


def ok(data, **headers) -> httpx.Response:
    return httpx.Response(200, content=json.dumps(data).encode(), headers=headers)


# ------------------------------------------------------------------ pure helpers
def test_wildcard_covers_exactly_one_label():
    assert covers("www.example.com", ["*.example.com"])
    assert not covers("a.b.example.com", ["*.example.com"])
    assert not covers("example.com", ["*.example.com"])
    assert covers("example.com", ["example.com", "*.example.com"])
    assert not covers("evilexample.com", ["*.example.com"])


def test_precert_and_final_cert_are_one_certificate():
    pre = parse_certspotter(json.dumps([cs_entry(tbs="aa" * 32, sha="01" * 32), cs_entry(tbs="aa" * 32, sha="02" * 32)]).encode())
    assert len(dedupe(pre)) == 1
    crt = parse_crtsh(json.dumps([crt_entry(serial="0A"), crt_entry(serial="a")]).encode())
    assert len(dedupe(crt)) == 1  # serials compare without leading zeros or case


def test_mixed_sources_keep_the_record_with_a_matchable_hash():
    a = CtEntry("crt.sh", ["x.example.com"], "I", OLD, OLD + timedelta(days=90), serial="5")
    b = CtEntry("Cert Spotter", ["x.example.com"], "I", OLD, OLD + timedelta(days=90), serial="5", spki_sha256=SPKI)
    out = dedupe([a, b])
    assert len(out) == 1 and out[0].spki_sha256 == SPKI


def test_names_are_normalised_and_junk_dropped():
    es = parse_crtsh(json.dumps([crt_entry(names="SHOP.Example.com.\nbad name!\n*.Example.com\n\n")]).encode())
    assert es[0].dns_names == ["shop.example.com", "*.example.com"]


@pytest.mark.parametrize("body", [b"<html>502</html>", b"{}", b"[1]", b'[{"not_before": "x"}]', b'[{"not_before": "2026-01-01T00:00:00Z"}]'])
def test_malformed_certspotter_bodies_are_rejected(body):
    with pytest.raises(ct_checks.CtMalformed):
        parse_certspotter(body)


def test_truncated_crtsh_json_is_malformed():
    full = json.dumps([crt_entry()]).encode()
    with pytest.raises(ct_checks.CtMalformed):
        parse_crtsh(full[:-5])


def test_leaf_matching_uses_key_or_serial_with_validity():
    e = parse_certspotter(json.dumps([cs_entry(sha="ee" * 32)]).encode())[0]
    assert matches_leaf(e, leaf())  # same key and validity, different final-cert hash (precertificate)
    assert not matches_leaf(e, leaf(spki_sha256="00" * 32))
    assert not matches_leaf(e, leaf(not_after=OLD + timedelta(days=30)))
    c = parse_crtsh(json.dumps([crt_entry(serial="00001A2B3C")]).encode())[0]
    assert matches_leaf(c, leaf())
    assert not matches_leaf(c, leaf(serial="ff"))


def test_leaf_from_fixture_chain():
    chain, _ = build("valid", host="demo.wtd.test")
    lf = ct_checks.leaf_from_chain(chain[0], {"leaf_dns_names": ["demo.wtd.test"], "embedded_scts": 0, "chain_trusted": True})
    assert lf.dns_names == ["demo.wtd.test"] and lf.sct_count == 0 and len(lf.spki_sha256) == 64 and lf.publicly_trusted


# ------------------------------------------------------------------ analysis outcomes
def run(cl, lf=None, host="shop.example.com"):
    return analyse(host, lf or leaf(), client=cl, now=NOW)


def test_successful_lookup_with_listed_certificate():
    cl, seen = client({"api.certspotter.com": ok([cs_entry(), cs_entry(nb=OLD - timedelta(days=90), na=OLD, spki="99" * 32, tbs="22" * 32, sha="33" * 32)])})
    f, chk, summ = run(cl)
    assert chk.status == CheckStatus.succeeded and chk.essential is False
    rec = next(x for x in f if x.code == "tls.ct_records")
    assert rec.severity == "info" and rec.evidence["certificates_covering_host"] == 2 and rec.evidence["presented_certificate_listed"] is True
    assert rec.evidence["source"] == "Cert Spotter" and rec.evidence["lookup_time"] and "does not verify" in rec.limitation.lower()
    assert not [x for x in f if x.code == "tls.ct_leaf_not_listed"]
    assert summ["presented_certificate_listed"] is True
    assert seen == ["api.certspotter.com?domain=shop.example.com&include_subdomains=false&match_wildcards=true&expand=dns_names"]


def test_only_the_hostname_is_sent():
    cl, seen = client({"api.certspotter.com": ok([cs_entry()])})
    run(cl)
    assert all("shop.example.com" in s and "/" not in s.split("?", 1)[1] and "path" not in s for s in seen)


def test_missing_leaf_with_embedded_scts_gives_one_weak_low_finding():
    cl, _ = client({"api.certspotter.com": ok([cs_entry(spki="77" * 32, tbs="44" * 32, sha="55" * 32)])})
    f, chk, _ = run(cl)
    miss = [x for x in f if x.code == "tls.ct_leaf_not_listed"]
    assert len(miss) == 1 and (miss[0].severity, miss[0].strength) == ("low", "weak") and chk.status == CheckStatus.succeeded
    assert "lag" in miss[0].limitation.lower() or "gaps" in miss[0].limitation.lower()


@pytest.mark.parametrize("override", [dict(sct_count=0), dict(publicly_trusted=False), dict(not_before=NOW - timedelta(hours=5), not_after=NOW + timedelta(days=80))])
def test_missing_leaf_is_not_a_signal_when_explained_otherwise(override):
    cl, _ = client({"api.certspotter.com": ok([cs_entry(spki="77" * 32, tbs="44" * 32, sha="55" * 32)])})
    f, _, _ = run(cl, leaf(**override))
    assert not [x for x in f if x.code == "tls.ct_leaf_not_listed"]


def full_page(start, n=ct_checks.PAGE_FULL_MIN):
    return [cs_entry(tbs=f"{start + i:064x}", sha=f"{start + i + 5000:064x}", spki=f"{start + i + 9000:064x}", id=str(start + i)) for i in range(n)]


def test_a_short_page_is_the_last_page_and_no_extra_request_is_made():
    cl, seen = client({"api.certspotter.com": ok([cs_entry()], link='<https://api.certspotter.com/issuances?after=1>; rel="next"')})
    _, chk, summ = run(cl)
    assert len(seen) == 1 and chk.status == CheckStatus.succeeded and summ["partial"] is False  # the Link header is sent even on the last page


def test_full_pages_are_followed_until_an_empty_or_short_page():
    pages = iter([ok(full_page(0)), ok([cs_entry()])])
    cl, seen = client({"api.certspotter.com": lambda r: next(pages)})
    _, chk, summ = run(cl)
    assert len(seen) == 2 and "after=59" in seen[1] and summ["partial"] is False and chk.status == CheckStatus.succeeded


def test_still_full_at_the_page_cap_is_partial_inconclusive_and_never_a_signal():
    n = iter(range(100))
    cl, seen = client({"api.certspotter.com": lambda r: ok(full_page(next(n) * 1000))})
    f, chk, summ = run(cl, leaf(spki_sha256="00" * 32))  # presented certificate absent from what was retrieved
    assert len(seen) == ct_checks.MAX_PAGES and chk.status == CheckStatus.inconclusive and "partial" in chk.detail and summ["partial"] is True
    assert not [x for x in f if x.code == "tls.ct_leaf_not_listed"]


def test_wildcard_certificate_is_found_by_cert_spotter_in_one_request():
    wc = leaf(dns_names=["*.example.com"])
    cl, seen = client({"api.certspotter.com": ok([cs_entry(names=("*.example.com", "example.com"))])})
    f, chk, _ = run(cl, wc)
    assert len(seen) == 1 and "match_wildcards=true" in seen[0] and chk.status == CheckStatus.succeeded
    assert next(x for x in f if x.code == "tls.ct_records").evidence["wildcard_certificates"] == 1


def test_crtsh_fallback_also_queries_the_wildcard_base_name():
    wc = leaf(dns_names=["*.example.com"])
    cl, seen = client({"api.certspotter.com": httpx.Response(502),
                       "crt.sh": lambda r: ok([crt_entry(names="*.example.com\nexample.com")]) if "q=example.com" in str(r.url) else ok([])})
    f, chk, summ = run(cl, wc)
    assert [s.split("?")[0] for s in seen] == ["api.certspotter.com", "crt.sh", "crt.sh"] and "q=example.com" in seen[2]
    assert chk.status == CheckStatus.succeeded and summ["queried_names"] == ["shop.example.com", "example.com"]


def test_api_key_is_sent_only_as_a_bearer_header(monkeypatch):
    monkeypatch.setenv("CERTSPOTTER_API_KEY", "SECRET-CS-KEY")
    got = []
    cl, _ = client({"api.certspotter.com": lambda r: (got.append(r), ok([cs_entry()]))[1]})
    run(cl)
    assert got[0].headers["authorization"] == "Bearer SECRET-CS-KEY" and "SECRET-CS-KEY" not in str(got[0].url)


def test_no_records_for_private_ca_is_a_normal_result():
    cl, _ = client({"api.certspotter.com": ok([])})
    f, chk, _ = run(cl, leaf(sct_count=0, publicly_trusted=False))
    assert chk.status == CheckStatus.succeeded and [x.severity for x in f] == ["info"]


def test_no_records_for_certificate_with_scts_is_inconclusive():
    cl, _ = client({"api.certspotter.com": ok([])})
    f, chk, _ = run(cl)
    assert chk.status == CheckStatus.inconclusive and [x.code for x in f] == ["tls.ct_no_records"] and f[0].severity == "info"


def test_fallback_to_crtsh_when_certspotter_is_down():
    cl, seen = client({"api.certspotter.com": httpx.Response(503), "crt.sh": ok([crt_entry()])})
    f, chk, summ = run(cl)
    assert chk.status == CheckStatus.succeeded and summ["sources"] == ["crt.sh"] and len(seen) == 2
    rec = next(x for x in f if x.code == "tls.ct_records")
    assert rec.evidence["presented_certificate_listed"] is True and any("fell back" in n for n in rec.evidence["notes"])


def test_both_sources_down_is_unavailable_not_clean():
    cl, _ = client({"api.certspotter.com": httpx.ConnectTimeout("t"), "crt.sh": httpx.Response(502)})
    f, chk, _ = run(cl)
    assert chk.status == CheckStatus.unavailable and f == [] and "not a risk signal" in chk.detail


def test_malformed_from_every_source_is_failed():
    cl, _ = client({"api.certspotter.com": httpx.Response(200, content=b"<html>"), "crt.sh": httpx.Response(200, content=b"{")})
    _, chk, _ = run(cl)
    assert chk.status == CheckStatus.failed


def test_rate_limit_blocks_the_source_until_retry_after():
    clock = [1000.0]
    cl, seen = client({"api.certspotter.com": httpx.Response(429, headers={"retry-after": "600"}), "crt.sh": ok([crt_entry()])}, clock=lambda: clock[0])
    run(cl)
    assert [s.split("?")[0] for s in seen] == ["api.certspotter.com", "crt.sh"]
    cl.cache.clear()
    run(cl)
    assert [s.split("?")[0] for s in seen][2:] == ["crt.sh"]  # Cert Spotter is not asked again while blocked
    clock[0] += 601
    cl.cache.clear()
    run(cl)
    assert seen[-2].startswith("api.certspotter.com")


def test_hourly_budget_is_enforced():
    cl, seen = client({"api.certspotter.com": ok([cs_entry()]), "crt.sh": ok([crt_entry()])}, hourly_budget=2)
    for h in ("a.example.com", "b.example.com", "c.example.com"):
        analyse(h, leaf(dns_names=[h]), client=cl, now=NOW)
    assert len(seen) == 2
    _, chk, _ = analyse("d.example.com", leaf(dns_names=["d.example.com"]), client=cl, now=NOW)
    assert chk.status == CheckStatus.unavailable and "budget" in chk.detail


def test_results_are_cached():
    cl, seen = client({"api.certspotter.com": ok([cs_entry()])})
    run(cl)
    f, chk, summ = run(cl)
    assert len(seen) == 1 and summ["cached"] is True and "(cached)" in chk.detail
    assert next(x for x in f if x.code == "tls.ct_records").provenance == "cached"


def test_oversized_response_is_rejected():
    big = httpx.Response(200, content=b"[" + b" " * (ct_checks.MAX_BYTES + 10) + b"]")
    cl, _ = client({"api.certspotter.com": big, "crt.sh": big})
    _, chk, _ = run(cl)
    assert chk.status == CheckStatus.failed


def test_result_count_is_bounded():
    many = [cs_entry(tbs=f"{i:064x}", sha=f"{i + 1000:064x}", spki=f"{i + 2000:064x}", id=str(i)) for i in range(ct_checks.MAX_ENTRIES + 40)]
    cl, _ = client({"api.certspotter.com": ok(many)})
    _, chk, summ = run(cl)
    assert summ["certificates"] <= ct_checks.MAX_ENTRIES * ct_checks.MAX_PAGES and chk.status == CheckStatus.inconclusive


def test_ip_literals_disabled_and_odd_hosts_are_skipped(monkeypatch):
    cl, seen = client({})
    assert run(cl, host="203.0.113.7")[1].status == CheckStatus.skipped
    assert run(cl, host="localhost")[1].status == CheckStatus.skipped
    monkeypatch.setenv("WTD_CT", "0")
    assert run(cl)[1].status == CheckStatus.skipped and not seen


# ------------------------------------------------------------------ classification
def test_ct_findings_alone_never_raise_the_class():
    cl, _ = client({"api.certspotter.com": ok([cs_entry(spki="77" * 32, tbs="44" * 32, sha="55" * 32)])})
    f, chk, _ = run(cl)
    essential_ok = [CheckResult(name="x", module=Module.url, status=CheckStatus.succeeded, essential=True)]
    assert classify(f, essential_ok + [chk]).classification == "Low Risk"
    # nor does a recent first issue date
    cl2, _ = client({"api.certspotter.com": ok([cs_entry(nb=NOW - timedelta(days=2), na=NOW + timedelta(days=88))])})
    f2, chk2, _ = run(cl2, leaf(not_before=NOW - timedelta(days=2), not_after=NOW + timedelta(days=88)))
    assert classify(f2, essential_ok + [chk2]).classification == "Low Risk"


@pytest.mark.parametrize("status", [CheckStatus.unavailable, CheckStatus.failed, CheckStatus.inconclusive])
def test_an_unavailable_ct_check_does_not_make_the_result_inconclusive(status):
    chk = CheckResult(name="tls.ct_lookup", module=Module.tls, status=status, essential=False)
    ok_checks = [CheckResult(name="x", module=Module.url, status=CheckStatus.succeeded, essential=True)]
    a = classify([], ok_checks + [chk])
    assert a.classification == "Low Risk" and chk.name not in a.coverage.essential_missing
