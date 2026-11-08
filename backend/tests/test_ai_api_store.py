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
    r = client.post("/api/analyses", json={"kind": "message", "text": "a" * 20001}, headers={"X-WTD-Token": "test-token"})
    assert r.status_code == 422


def test_rate_limit(client, monkeypatch):
    from wtd import api
    from dataclasses import replace
    monkeypatch.setattr(api, "SETTINGS", replace(api.SETTINGS, max_analyses_per_minute=2))
    api._hits.clear()
    codes = [client.post("/api/analyses", json={"kind": "url", "url": "javascript:x"}, headers={"X-WTD-Token": "test-token"}).status_code for _ in range(3)]
    assert codes[-1] == 429
