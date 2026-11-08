"""AI output validation and provider failure handling, API security, persistence across restart."""
import json

import pytest
from fastapi.testclient import TestClient

from wtd.ai import explain
from wtd.classify import classify
from wtd.models import CheckResult, Finding, Report, iso
from wtd.store import Store


def _report(cls_findings=None, kind="message", text="Dear customer, share your OTP now at hxxps://x[.]top"):
    fs = cls_findings or [Finding(id="msg.credential_request", code="msg.credential_request", module="message", title="Asks for OTP", observed="x",
                                  source="t", observed_at=iso(), severity="high", strength="moderate", impact="", recommendation="", limitation=""),
                          Finding(id="msg.brand_link_mismatch", code="msg.brand_link_mismatch", module="message", title="Brand/link mismatch",
                                  observed="x", source="t", observed_at=iso(), severity="high", strength="strong", impact="", recommendation="", limitation="")]
    checks = [CheckResult(name="message.rules", module="message", status="succeeded", essential=True)]
    r = Report(id="r1", kind=kind, status="complete", created_at=iso(), input_display="x", input_sha256="0" * 64,
               subject={"redacted_text": text}, findings=fs, checks=checks)
    r.assessment = classify(fs, checks)
    return r


def good(**over):
    d = {"summary": "This message is High Risk.", "points": [{"finding_ids": ["msg.credential_request"], "explanation": "It asks for an OTP."}],
         "observations": [{"technique": "credential request", "quote": "share your OTP now", "rationale": "asks for a secret"}],
         "recommended_actions": ["Do not reply."], "uncertainty": "Sender not verified.", "injection_attempt_observed": False}
    d.update(over)
    return json.dumps(d)


def test_valid_output_accepted_and_quote_verified():
    res = explain._validate(_report(), good(), "Dear customer, share your OTP now at hxxps://x[.]top")
    assert res.status == "ok" and res.observations[0].quote_verified


def test_malformed_json_is_failed():
    assert explain._validate(_report(), "not json {", "").status == "failed"


def test_unknown_finding_ids_dropped():
    res = explain._validate(_report(), good(points=[{"finding_ids": ["made.up", "msg.credential_request"], "explanation": "x"}]), "")
    assert res.points[0].finding_ids == ["msg.credential_request"] and any("made.up" in n for n in res.validation_notes)


def test_fabricated_quote_flagged():
    res = explain._validate(_report(), good(observations=[{"technique": "t", "quote": "send bitcoin immediately", "rationale": "r"}]), "share your OTP now")
    assert res.observations[0].quote_verified is False


def test_contradicting_classification_rejected():
    res = explain._validate(_report(), good(summary="After review this message is classified as Low Risk."), "")
    assert res.status == "rejected"


def test_safe_claim_on_risky_target_rejected():
    res = explain._validate(_report(), good(summary="The message is safe to act on."), "")
    assert res.status == "rejected"


def test_injection_flag_passed_through():
    assert explain._validate(_report(), good(injection_attempt_observed=True), "").injection_attempt_observed is True


def test_provider_failure_falls_back_then_unavailable(monkeypatch):
    monkeypatch.setattr(explain.SETTINGS.__class__, "__getattribute__", object.__getattribute__)
    from dataclasses import replace
    monkeypatch.setattr(explain, "SETTINGS", replace(explain.SETTINGS, ai_enabled=True))

    def boom(_):
        raise RuntimeError("unavailable: provider requires credit (HTTP 402)")
    monkeypatch.setattr(explain, "_openrouter", boom)
    monkeypatch.setattr(explain, "_ollama", lambda m: (good(), "ollama (local)"))
    res = explain.explain_report(_report())
    assert res.status == "ok" and res.provider == "ollama (local)" and any("402" in n for n in res.validation_notes)
    monkeypatch.setattr(explain, "_ollama", boom)
    res = explain.explain_report(_report())
    assert res.status == "unavailable" and "402" in res.error


def test_ai_disabled_is_explicit():
    assert explain.explain_report(_report()).status == "disabled"  # conftest sets WTD_AI_ENABLED=0


# ------------------------------------------------------------------ persistence
def test_store_survives_restart_and_marks_interrupted(tmp_path):
    db = tmp_path / "s.sqlite3"
    s = Store(db)
    done = _report()
    done.id = "done"
    s.save(done)
    running = _report()
    running.id, running.status = "running", "running"
    s.save(running)
    s.conn.close()
    s2 = Store(db)  # simulated restart
    assert s2.recover_interrupted() == 1
    assert s2.get("done").status == "complete" and s2.get("done").assessment.classification == done.assessment.classification
    assert s2.get("running").status == "interrupted"


# ------------------------------------------------------------------ API
@pytest.fixture(scope="module")
def client():
    from wtd.api import app
    return TestClient(app)


def test_health_is_public(client):
    assert client.get("/api/health").status_code == 200


def test_token_required(client):
    assert client.get("/api/analyses").status_code == 401
    assert client.post("/api/analyses", json={"kind": "url", "url": "https://example.com"}).status_code == 401
    assert client.get("/api/analyses", headers={"X-WTD-Token": "wrong"}).status_code == 401


@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///etc/passwd", "ftp://x.com/"])
def test_unusable_urls_rejected_with_422(client, url):
    r = client.post("/api/analyses", json={"kind": "url", "url": url}, headers={"X-WTD-Token": "test-token"})
    assert r.status_code == 422


def test_oversized_message_rejected(client):
    r = client.post("/api/analyses", json={"kind": "message", "text": "a" * 150_001}, headers={"X-WTD-Token": "test-token"})
    assert r.status_code == 422


def test_rate_limit(client, monkeypatch):
    from wtd import api
    from dataclasses import replace
    monkeypatch.setattr(api, "SETTINGS", replace(api.SETTINGS, max_analyses_per_minute=2))
    api._hits.clear()
    codes = [client.post("/api/analyses", json={"kind": "url", "url": "javascript:x"}, headers={"X-WTD-Token": "test-token"}).status_code for _ in range(3)]
    assert codes[-1] == 429


def test_negated_classification_mention_is_not_a_contradiction():
    r = _report()
    res = explain._validate(r, good(summary="The redirect alone does not classify as Low Risk evidence; it is High Risk because of the OTP request."), "")
    assert res.status == "ok"


# ------------------------------------------------------------------ AI campaign brief validation
def _cluster(kind="campaign"):
    return {"cluster_id": "c1", "kind": kind, "report_ids": ["r1", "r2"], "distinct_targets": 2,
            "shared": ["upi: wt•••@ybl", "email: h•••@wtd-demo.invalid"], "classifications": ["High Risk"], "links": [], "reports": []}


_EVID = {"reports": [{"report_id": "r1", "findings": [{"id": "msg.unusual_payment"}]}, {"report_id": "r2", "findings": [{"id": "msg.job_offer"}]}]}


def test_campaign_tactic_report_must_carry_finding():
    from wtd.ai import campaign
    res = campaign._validate(_cluster(), _EVID, _brief(common_tactics=[{"technique": "advance fee", "report_ids": ["r1", "r2"], "finding_ids": ["msg.unusual_payment"]}]))
    assert res["common_tactics"][0]["report_ids"] == ["r1"]


def _brief(**over):
    d = {"summary": "Both messages ask for fees to the same UPI ID.", "assessment": "likely_same_campaign",
         "link_explanations": [{"indicator": "upi: wt•••@ybl", "report_ids": ["r1", "r2", "rX"], "explanation": "Same payee."}],
         "common_tactics": [{"technique": "advance fee", "report_ids": ["r1"], "finding_ids": ["msg.unusual_payment", "msg.made_up"]}],
         "next_steps": ["Report the UPI ID to the bank."], "uncertainty": "Masked values only.", "injection_attempt_observed": False}
    d.update(over)
    return json.dumps(d)


def test_campaign_brief_grounding_enforced():
    from wtd.ai import campaign
    res = campaign._validate(_cluster(), _EVID, _brief(link_explanations=[
        {"indicator": "upi: wt•••@ybl", "report_ids": ["r1", "r2", "rX"], "explanation": "Same payee."},
        {"indicator": "ip: 1.2.3.4", "report_ids": ["r1"], "explanation": "invented"}]))
    assert res["status"] == "ok"
    assert [l["indicator"] for l in res["link_explanations"]] == ["upi: wt•••@ybl"]
    assert res["link_explanations"][0]["report_ids"] == ["r1", "r2"]
    assert res["common_tactics"][0]["finding_ids"] == ["msg.unusual_payment"]
    assert any("not in this cluster" in n for n in res["validation_notes"])


def test_campaign_brief_cannot_exceed_link_type():
    from wtd.ai import campaign
    assert campaign._validate(_cluster("shared_infrastructure"), _EVID, _brief())["status"] == "rejected"
    assert campaign._validate(_cluster("repeat_checks"), _EVID, _brief(assessment="possibly_related"))["status"] == "rejected"
    assert campaign._validate(_cluster("repeat_checks"), _EVID, _brief(assessment="repeat_checks_only"))["status"] == "ok"


def test_campaign_brief_rejects_attribution_and_unsupported_confirmed():
    from wtd.ai import campaign
    assert campaign._validate(_cluster(), _EVID, _brief(summary="This is attributed to APT 41."))["status"] == "rejected"
    assert campaign._validate(_cluster(), _EVID, _brief(summary="All reports are Confirmed Malicious."))["status"] == "rejected"
    assert campaign._validate(_cluster(), _EVID, "nope")["status"] == "failed"


def test_review_validation(client):
    h = {"X-WTD-Token": "test-token"}
    assert client.post("/api/analyses/x/threat-report/review", json={"status": "Pending"}, headers=h).status_code == 422
    assert client.post("/api/analyses/x/threat-report/review", json={"status": "Disputed", "note": ""}, headers=h).status_code == 422
    assert client.post("/api/analyses/nope/threat-report/review", json={"status": "Validated"}, headers=h).status_code == 409
    assert client.post("/api/analyses/x/threat-report/review", json={"status": "Validated"}).status_code == 401


def test_quick_check_is_local_and_fast(client, monkeypatch):
    from wtd import intel
    calls = []
    monkeypatch.setattr(intel, "_urlhaus", lambda *a, **k: calls.append(a) or {})
    h = {"X-WTD-Token": "test-token"}
    r = client.post("/api/quick-check", json={"url": "https://paypa1.com/signin"}, headers=h)
    assert r.status_code == 200 and r.json()["classification"] == "High Risk"
    assert any(f["code"] == "url.typosquat" for f in r.json()["findings"])
    assert calls == []  # no third-party lookup for browsing
    assert client.post("/api/quick-check", json={"url": "javascript:alert(1)"}, headers=h).status_code == 422
    assert client.post("/api/quick-check", json={"url": "https://example.com"}).status_code == 401


@pytest.mark.parametrize("summary", [
    "It may mean the URL was recently registered, so do not assume it is safe.",            # observed S1 output
    "The certificate is valid but does not prove the site is legitimate or safe.",          # observed S4 output
    "The page looks legitimate but its domain imitates the bank.",
])
def test_negated_or_descriptive_safe_wording_is_not_a_safe_claim(summary):
    assert explain._validate(_report(), good(summary=summary), "").status == "ok"


def test_plain_safe_claim_still_rejected():
    assert explain._validate(_report(), good(summary="Overall the site is legitimate."), "").status == "rejected"


def test_cors_only_for_listed_origins():
    """WTD_CORS_ORIGINS enables cross-origin calls from exactly the listed dashboard origin (fresh interpreter)."""
    import subprocess
    import sys
    code = (
        "from fastapi.testclient import TestClient\n"
        "from wtd.api import app\n"
        "c = TestClient(app)\n"
        "h = {'Origin': 'https://wtd.vercel.app', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'x-wtd-token,content-type'}\n"
        "ok = c.options('/api/analyses', headers=h)\n"
        "bad = c.options('/api/analyses', headers={**h, 'Origin': 'https://evil.example'})\n"
        "assert ok.headers.get('access-control-allow-origin') == 'https://wtd.vercel.app', ok.headers\n"
        "assert 'access-control-allow-origin' not in bad.headers, bad.headers\n"
        "assert 'access-control-allow-credentials' not in ok.headers\n"
        "print('ok')\n"
    )
    import os
    env = {**os.environ, "WTD_CORS_ORIGINS": "https://wtd.vercel.app/", "WTD_API_TOKEN": "test-token", "WTD_AI_ENABLED": "0"}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, cwd=str(__import__("pathlib").Path(__file__).parents[1]))
    assert r.returncode == 0 and "ok" in r.stdout, r.stderr[-800:]
