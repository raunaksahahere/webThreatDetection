"""Google Safe Browsing and OpenPhish sources: matches, no-match vs unavailable vs not-checked, limits, privacy, staleness.

All network traffic is mocked; nothing here reaches a real provider."""
import json
import time

import httpx
import pytest

from wtd import intel, intel_phish
from wtd.classify import classify
from wtd.intel_phish import OpenPhishFeed, SafeBrowsing, feed_key, lookup_entry, lookup_gsb, lookup_openphish, parse_feed
from wtd.models import CheckResult, CheckStatus, Module

KEY = "TEST-KEY-do-not-leak"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("GSB_API_KEY", KEY)
    monkeypatch.delenv("WTD_OPENPHISH", raising=False)


def gsb(handler, clock=time.time):
    seen: list[httpx.Request] = []

    def h(req):
        seen.append(req)
        return handler(req)

    return SafeBrowsing(transport=httpx.MockTransport(h), clock=clock), seen


def match(url, tt="SOCIAL_ENGINEERING", cache="300s"):
    return {"threatType": tt, "platformType": "ANY_PLATFORM", "threatEntryType": "URL", "threat": {"url": url}, "cacheDuration": cache}


def reply(matches):
    return lambda req: httpx.Response(200, json={"matches": matches} if matches else {})


def ok_checks(checks):
    return [CheckResult(name="x", module=Module.url, status=CheckStatus.succeeded, essential=True)] + checks


# =============================================================== Safe Browsing
def test_positive_match_is_authoritative_with_attribution_and_qualified_wording():
    c, _ = gsb(reply([match("https://bad.example/login")]))
    o = lookup_gsb("https://bad.example/login", [], True, c)
    f = o.findings[0]
    assert (f.code, f.severity, f.strength) == ("intel.gsb_listed", "critical", "authoritative")
    assert "suspected" in f.title and "Advisory provided by Google" in f.observed
    assert f.evidence["advisory_url"].startswith("https://developers.google.com/safe-browsing") and f.evidence["threat_type"] == "SOCIAL_ENGINEERING"
    assert f.source.startswith("Google Safe Browsing") and f.observed_at and "not perfect" in f.limitation
    assert o.checks[0].status == CheckStatus.succeeded and o.checks[0].essential is False
    assert classify(o.findings, ok_checks(o.checks)).classification == "Confirmed Malicious"


def test_unwanted_software_is_strong_not_authoritative():
    c, _ = gsb(reply([match("http://dl.example/", "UNWANTED_SOFTWARE")]))
    o = lookup_gsb("http://dl.example/", [], True, c)
    assert (o.findings[0].severity, o.findings[0].strength) == ("high", "strong")
    assert classify(o.findings, ok_checks(o.checks)).classification == "High Risk"


def test_no_match_is_unknown_not_clean_and_cannot_lower_a_result():
    c, _ = gsb(reply([]))
    o = lookup_gsb("https://fine.example/", [], True, c)
    assert [f.code for f in o.findings] == ["intel.no_listing"] and "not clean" in o.findings[0].title and o.checks[0].status == CheckStatus.succeeded


def test_redirect_hosts_are_checked_at_host_level_in_one_request():
    c, seen = gsb(reply([match("http://evil.example/")]))
    o = lookup_gsb("https://start.example/a/b", ["start.example", "evil.example"], True, c)
    assert len(seen) == 1
    sent = [e["url"] for e in json.loads(seen[0].content)["threatInfo"]["threatEntries"]]
    assert sent == ["https://start.example/a/b", "http://evil.example/"]
    assert "evil.example" in o.findings[0].title


def test_only_scheme_host_and_path_are_sent_and_the_key_stays_out_of_the_url():
    assert lookup_entry("https://user:pw@Example.com:8443/a/b?token=SECRET&x=1#frag") == "https://example.com:8443/a/b"
    assert lookup_entry("https://example.com") == "https://example.com/"
    assert lookup_entry("ftp://example.com/") is None and lookup_entry("https://example.com/" + "a" * 600) is None
    c, seen = gsb(reply([]))
    lookup_gsb("https://example.com/p?token=SECRET#frag", [], True, c)
    req = seen[0]
    assert KEY not in str(req.url) and req.headers["x-goog-api-key"] == KEY
    assert b"SECRET" not in req.content and b"frag" not in req.content and b"token" not in req.content


def test_missing_key_is_unavailable_not_a_clean_result(monkeypatch):
    monkeypatch.setenv("GSB_API_KEY", "")
    o = lookup_gsb("https://x.example/", [], True, gsb(reply([]))[0])
    assert o.findings == [] and o.checks[0].status == CheckStatus.unavailable and "not configured" in o.checks[0].detail
    assert classify([], ok_checks(o.checks)).classification == "Low Risk"  # optional source: its absence does not force Inconclusive


def test_quick_check_mode_makes_no_third_party_request():
    c, seen = gsb(reply([]))
    o = lookup_gsb("https://x.example/", [], False, c)
    assert o.checks[0].status == CheckStatus.skipped and not seen


@pytest.mark.parametrize("status,word", [(429, "429"), (403, "rejected"), (400, "rejected"), (503, "unavailable")])
def test_provider_errors_are_unavailable_and_never_leak_the_key(status, word):
    c, _ = gsb(lambda r: httpx.Response(status, text=f"denied for key={KEY}"))
    o = lookup_gsb("https://x.example/", [], True, c)
    assert o.checks[0].status == CheckStatus.unavailable and word in o.checks[0].detail and KEY not in o.checks[0].detail
    assert o.findings == []


def test_timeout_is_unavailable():
    def boom(req):
        raise httpx.ReadTimeout("slow", request=req)

    o = lookup_gsb("https://x.example/", [], True, gsb(boom)[0])
    assert o.checks[0].status == CheckStatus.unavailable and "timed out" in o.checks[0].detail


@pytest.mark.parametrize("resp", [
    httpx.Response(200, content=b"<html>"), httpx.Response(200, json=[1]), httpx.Response(200, json={"matches": [1]}),
    httpx.Response(200, json={"matches": [match("https://other.example/")]}),  # a match we cannot attribute
    httpx.Response(200, json={"matches": [match("https://x.example/", "BANANA")]}),
    httpx.Response(200, content=b" " * (intel_phish.GSB_MAX_BYTES + 5)),
])
def test_malformed_responses_are_failed_not_clean(resp):
    o = lookup_gsb("https://x.example/", [], True, gsb(lambda r: resp)[0])
    assert o.checks[0].status == CheckStatus.failed and o.findings == []


def test_rate_limit_429_backs_off_without_more_requests():
    clock = [1000.0]
    c, seen = gsb(lambda r: httpx.Response(429), clock=lambda: clock[0])
    lookup_gsb("https://a.example/", [], True, c)
    lookup_gsb("https://b.example/", [], True, c)
    assert len(seen) == 1
    clock[0] += 61
    lookup_gsb("https://c.example/", [], True, c)
    assert len(seen) == 2


def test_local_per_minute_limit(monkeypatch):
    monkeypatch.setenv("GSB_MAX_PER_MIN", "2")
    c, seen = gsb(reply([]))
    for h in "abc":
        o = lookup_gsb(f"https://{h}.example/", [], True, c)
    assert len(seen) == 2 and o.checks[0].status == CheckStatus.unavailable and "per minute" in o.checks[0].detail


def test_cache_honours_cache_duration_then_expires():
    clock = [1000.0]
    c, seen = gsb(reply([match("https://bad.example/", cache="120s")]), clock=lambda: clock[0])
    lookup_gsb("https://bad.example/", [], True, c)
    o = lookup_gsb("https://bad.example/", [], True, c)
    assert len(seen) == 1 and o.findings[0].provenance == "cached" and o.findings[0].evidence["cached"] is True
    clock[0] += 121
    lookup_gsb("https://bad.example/", [], True, c)
    assert len(seen) == 2


def test_negative_results_are_cached_briefly():
    clock = [1000.0]
    c, seen = gsb(reply([]), clock=lambda: clock[0])
    lookup_gsb("https://ok.example/", [], True, c)
    lookup_gsb("https://ok.example/", [], True, c)
    assert len(seen) == 1
    clock[0] += intel_phish.GSB_NEG_TTL + 1
    lookup_gsb("https://ok.example/", [], True, c)
    assert len(seen) == 2


# =============================================================== OpenPhish
FEED = "\n".join(["https://phish.example/login?id=1", "https://www.facebook-q.blogspot.com/", "http://evil.test/a/b/", "", "# note",
                  "not a url", "ftp://x/y", "https://phish.example/other"])


def feed_obj(tmp_path, text=FEED, age_h=1.0, clock=None):
    clock = clock or (lambda: 10_000_000.0)
    p = tmp_path / "op.txt"
    p.write_text(text)
    (tmp_path / "op.json").write_text(json.dumps({"fetched_at": clock() - age_h * 3600, "etag": "e1"}))
    f = OpenPhishFeed(path=p, url="https://feed.invalid/feed.txt", transport=httpx.MockTransport(lambda r: httpx.Response(500)), clock=clock)
    f.last_attempt = clock()  # no background refresh in these tests
    return f


def test_feed_parsing_skips_malformed_lines_and_normalises():
    keys, hosts, bad = parse_feed(FEED)
    assert bad == 2 and "phish.example/login?id=1" in keys and "evil.test/a/b" in keys and hosts["phish.example"] == 2
    assert feed_key("HTTPS://Phish.Example./login?id=1#frag") == "phish.example/login?id=1"
    assert feed_key("javascript:alert(1)") is None


def test_disabled_by_default_is_not_checked_and_says_why(tmp_path):
    o = lookup_openphish("https://phish.example/login?id=1", ["phish.example"], set(), feed_obj(tmp_path))
    assert o.findings == [] and o.checks[0].status == CheckStatus.skipped and "terms" in o.checks[0].detail and "not checked" in o.checks[0].detail


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("WTD_OPENPHISH", "1")


def test_exact_match_is_authoritative_when_fresh(tmp_path, enabled):
    o = lookup_openphish("https://phish.example/login?id=1", ["phish.example"], set(), feed_obj(tmp_path))
    codes = {f.code for f in o.findings}
    assert codes == {"intel.openphish_url_listed"}  # the exact match covers its own host: no second finding for the same listing
    f = o.findings[0]
    assert (f.severity, f.strength, f.provenance) == ("critical", "authoritative", "dataset") and f.evidence["category"] == "phishing"
    assert f.evidence["snapshot_time"] and f.evidence["stale"] is False
    assert classify(o.findings, ok_checks(o.checks)).classification == "Confirmed Malicious"


def test_host_match_without_exact_url_is_strong(tmp_path, enabled):
    o = lookup_openphish("https://phish.example/new-page", ["phish.example"], set(), feed_obj(tmp_path))
    f = o.findings[0]
    assert (f.code, f.severity, f.strength) == ("intel.openphish_host_listed", "high", "strong") and "not among them" in f.observed
    assert classify(o.findings, ok_checks(o.checks)).classification == "High Risk"


def test_shared_platform_host_is_context_only(tmp_path, enabled):
    o = lookup_openphish("https://other.blogspot.com/", ["www.facebook-q.blogspot.com", "other.blogspot.com"], {"blogspot.com"}, feed_obj(tmp_path))
    assert [(f.severity, f.strength) for f in o.findings] == [("info", "weak")]
    assert classify(o.findings, ok_checks(o.checks)).classification == "Low Risk"


def test_scheme_and_trailing_slash_do_not_defeat_exact_matching(tmp_path, enabled):
    o = lookup_openphish("http://evil.test/a/b", ["evil.test"], set(), feed_obj(tmp_path))
    assert o.findings[0].code == "intel.openphish_url_listed"


def test_no_match_is_unknown_not_clean(tmp_path, enabled):
    o = lookup_openphish("https://fine.example/", ["fine.example"], set(), feed_obj(tmp_path))
    assert [f.code for f in o.findings] == ["intel.no_listing"] and o.checks[0].status == CheckStatus.succeeded


def test_stale_snapshot_downgrades_matches_and_makes_no_match_inconclusive(tmp_path, enabled):
    stale = feed_obj(tmp_path, age_h=48)
    hit = lookup_openphish("https://phish.example/login?id=1", ["phish.example"], set(), stale)
    assert (hit.findings[0].severity, hit.findings[0].strength) == ("critical", "strong") and hit.findings[0].evidence["stale"] is True
    assert "stale" in hit.findings[0].limitation.lower()
    assert classify(hit.findings, ok_checks(hit.checks)).classification == "High Risk"  # not Confirmed on stale data
    miss = lookup_openphish("https://fine.example/", ["fine.example"], set(), stale)
    assert miss.checks[0].status == CheckStatus.inconclusive and "STALE" in miss.checks[0].detail


def test_too_old_snapshot_is_unavailable(tmp_path, enabled):
    o = lookup_openphish("https://phish.example/login?id=1", ["phish.example"], set(), feed_obj(tmp_path, age_h=24 * 9))
    assert o.findings == [] and o.checks[0].status == CheckStatus.unavailable and "too old" in o.checks[0].detail


def test_no_snapshot_yet_is_unavailable(tmp_path, enabled):
    f = OpenPhishFeed(path=tmp_path / "none.txt", transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    f.last_attempt = f.clock()
    o = lookup_openphish("https://x.example/", ["x.example"], set(), f)
    assert o.checks[0].status == CheckStatus.unavailable and o.findings == []


def test_refresh_is_conditional_rate_limited_and_keeps_the_old_snapshot_on_failure(tmp_path):
    clock = [20_000_000.0]
    calls = []

    def handler(req):
        calls.append(dict(req.headers))
        if len(calls) == 1:
            return httpx.Response(200, text="https://new.example/x\n", headers={"etag": "v2"})
        if len(calls) == 2:
            return httpx.Response(304)
        return httpx.Response(500)

    f = OpenPhishFeed(path=tmp_path / "op.txt", url="https://feed.invalid/f", transport=httpx.MockTransport(handler), clock=lambda: clock[0])
    assert f.refresh() and "new.example/x" in f.keys and json.loads((tmp_path / "op.json").read_text())["etag"] == "v2"
    assert f.refresh() is False and len(calls) == 1  # inside the minimum refresh interval: no request
    clock[0] += intel_phish.OP_MIN_REFRESH_S + 1
    assert f.refresh() and calls[1].get("if-none-match") == "v2"  # 304 confirms the snapshot is current
    clock[0] += intel_phish.OP_MIN_REFRESH_S + 1
    assert f.refresh() is False and "new.example/x" in f.keys and "refresh failed" in (f.error or "")


@pytest.mark.parametrize("resp", [httpx.Response(200, text="<html>nope</html>"), httpx.Response(200, content=b"x" * (intel_phish.OP_MAX_BYTES + 1))])
def test_unusable_feed_is_rejected_and_keeps_the_old_snapshot(tmp_path, resp):
    f = OpenPhishFeed(path=tmp_path / "op.txt", transport=httpx.MockTransport(lambda r: resp), clock=lambda: 1.0e9)
    f.keys = {"old.example"}
    assert f.refresh() is False and f.keys == {"old.example"} and f.error


# =============================================================== integration through intel.lookup
def test_lookup_merges_all_sources_and_keeps_each_status_distinct(monkeypatch, tmp_path):
    monkeypatch.setattr(intel_phish, "GSB", gsb(reply([match("https://bad.example/x")]))[0])
    monkeypatch.setattr(intel.CERTPL, "domains", {"unrelated.example"})
    monkeypatch.setattr(intel.CERTPL, "refresh_async", lambda: None)
    o = intel.lookup("https://bad.example/x", ["bad.example"], set())
    by = {c.name: c.status for c in o.checks}
    assert by["intel.gsb"] == "succeeded" and by["intel.openphish"] == "skipped" and by["intel.urlhaus"] == "unavailable" and by["intel.certpl"] == "succeeded"
    assert any(f.code == "intel.gsb_listed" for f in o.findings)


def test_redirect_host_lookup_has_no_url_level_entry(monkeypatch):
    c, seen = gsb(reply([]))
    monkeypatch.setattr(intel_phish, "GSB", c)
    monkeypatch.setattr(intel.CERTPL, "refresh_async", lambda: None)
    intel.lookup(None, ["hop.example"], set())
    assert [e["url"] for e in json.loads(seen[0].content)["threatInfo"]["threatEntries"]] == ["http://hop.example/"]
