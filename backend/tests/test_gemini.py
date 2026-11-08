"""Gemini provider: request shape, key handling, per-model fallback (quota / unknown model / schema), refusals,
provider order, campaign briefs routed through the same chain, and the /api/health AI status."""
import json
from dataclasses import replace

import httpx
import pytest

from wtd.ai import explain
from tests.test_ai_api_store import _report, good

KEY = "AIzaTESTKEY_not_real_0123456789"
M1, M2 = "gemini-3.5-flash-lite", "gemini-3.1-flash-lite"


class Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("x", request=None, response=None)


def ok_body(text, thought=None, reason="STOP"):
    parts = ([{"text": thought, "thought": True}] if thought else []) + [{"text": text}]
    return {"candidates": [{"content": {"parts": parts}, "finishReason": reason}]}


@pytest.fixture()
def gem(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    monkeypatch.setenv("WTD_GEMINI_MODELS", f"{M1},{M2}")
    monkeypatch.setattr(explain, "SETTINGS", replace(explain.SETTINGS, ai_enabled=True))
    monkeypatch.setattr(explain, "_gemini_alias", {})
    monkeypatch.setattr(explain, "_gemini_listed", None)
    monkeypatch.setattr(explain.time, "sleep", lambda s: None)
    calls = []

    def install(*responses, listing=None):
        queue = list(responses)

        def post(url, json=None, headers=None, timeout=None):
            calls.append({"url": url, "body": json, "headers": headers})
            return queue.pop(0)

        def get(url, params=None, headers=None, timeout=None):
            calls.append({"url": url, "headers": headers, "list": True})
            return Resp(200, {"models": [{"name": f"models/{n}", "supportedGenerationMethods": ["generateContent"]} for n in (listing or [])]})

        monkeypatch.setattr(explain.httpx, "post", post)
        monkeypatch.setattr(explain.httpx, "get", get)
        return calls

    return install


def test_request_shape_and_key_only_in_header(gem):
    calls = gem(Resp(200, ok_body(good())))
    text, label = explain._gemini(explain._messages({"a": 1}, "hello"))
    assert json.loads(text)["summary"] and label == f"gemini:{M1}"
    c = calls[0]
    assert c["url"].endswith(f"/models/{M1}:generateContent") and KEY not in c["url"]
    assert c["headers"] == {"x-goog-api-key": KEY}
    b = c["body"]
    assert "security analyst" in b["systemInstruction"]["parts"][0]["text"]
    assert b["contents"][0]["role"] == "user" and "<untrusted_content>" in b["contents"][0]["parts"][0]["text"]
    g = b["generationConfig"]
    assert g["temperature"] == 0 and g["responseMimeType"] == "application/json" and g["responseJsonSchema"] == explain.SCHEMA


def test_explain_report_uses_gemini_first(gem, monkeypatch):
    gem(Resp(200, ok_body(good(), thought="hidden reasoning that must be ignored")))
    monkeypatch.setattr(explain, "_openrouter", lambda m: pytest.fail("openrouter must not be called"))
    res = explain.explain_report(_report())
    assert res.status == "ok" and res.provider == f"gemini:{M1}" and res.model == M1


def test_quota_on_first_model_hands_over_to_second(gem):
    calls = gem(Resp(429, {"error": {"message": "Resource exhausted"}}), Resp(200, ok_body(good())))
    _, label = explain._gemini(explain._messages({}, ""))
    assert label == f"gemini:{M2}" and len(calls) == 2


def test_unknown_model_id_resolves_to_served_variant(gem):
    calls = gem(Resp(404, {"error": {"message": "not found"}}), Resp(200, ok_body(good())),
                listing=[f"{M1}-preview-10-2026", "gemini-embedding-2"])
    _, label = explain._gemini(explain._messages({}, ""))
    assert label == f"gemini:{M1}-preview-10-2026"
    assert explain._gemini_alias[M1] == f"{M1}-preview-10-2026"
    assert [c.get("list") for c in calls] == [None, True, None]


def test_unknown_model_without_variant_moves_on(gem):
    gem(Resp(404, {}), Resp(200, ok_body(good())), listing=["gemini-embedding-2"])
    assert explain._gemini(explain._messages({}, ""))[1] == f"gemini:{M2}"


def test_schema_rejection_retries_in_json_mode(gem):
    calls = gem(Resp(400, {"error": {"message": "Invalid JSON payload received. Unknown name \"responseJsonSchema\""}}), Resp(200, ok_body(good())))
    explain._gemini(explain._messages({}, ""))
    assert "responseJsonSchema" in calls[0]["body"]["generationConfig"]
    assert "responseJsonSchema" not in calls[1]["body"]["generationConfig"]
    assert calls[1]["body"]["generationConfig"]["responseMimeType"] == "application/json"


def test_rejected_key_stops_immediately_and_never_echoes_key(gem):
    calls = gem(Resp(403, {"error": {"message": f"API key not valid {KEY}"}}))
    with pytest.raises(RuntimeError) as e:
        explain._gemini(explain._messages({}, ""))
    assert "rejected the API key" in str(e.value) and KEY not in str(e.value) and len(calls) == 1


def test_transient_error_retried_once(gem):
    gem(Resp(503, {}), Resp(200, ok_body(good())))
    assert explain._gemini(explain._messages({}, ""))[1] == f"gemini:{M1}"


@pytest.mark.parametrize("body,expect", [
    (ok_body("", reason="SAFETY"), "rejected"),
    ({"promptFeedback": {"blockReason": "PROHIBITED_CONTENT"}}, "rejected"),
    (ok_body('{"summary": "cut', reason="MAX_TOKENS"), "truncated"),
    ({"candidates": []}, "empty"),
])
def test_refusals_and_truncation_are_explicit(gem, body, expect):
    gem(Resp(200, body))
    with pytest.raises(RuntimeError, match=expect):
        explain._gemini(explain._messages({}, ""))


def test_all_models_exhausted_falls_back_to_local(gem, monkeypatch):
    gem(Resp(429, {}), Resp(429, {}))
    monkeypatch.setattr(explain, "_openrouter", lambda m: (_ for _ in ()).throw(RuntimeError("unavailable: OPENROUTER_API_KEY not set")))
    monkeypatch.setattr(explain, "_ollama", lambda m: (good(), "ollama (local)"))
    res = explain.explain_report(_report())
    assert res.status == "ok" and res.provider == "ollama (local)"


def test_no_key_means_gemini_skipped(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY not set"):
        explain._gemini([{"role": "user", "content": "x"}])


def test_provider_order_is_configurable(gem, monkeypatch):
    monkeypatch.setenv("WTD_AI_PROVIDERS", "local, gemini, bogus, local")
    assert explain.provider_order() == ["local", "gemini"]
    seen = []
    monkeypatch.setattr(explain, "_ollama", lambda m: seen.append("local") or (good(), "ollama (local)"))
    explain.explain_report(_report())
    assert seen == ["local"]


def test_campaign_briefs_pass_their_schema_to_gemini(gem, monkeypatch):
    got = {}

    def fake(msgs, schema=None, max_tokens=1200):
        got.update(schema=schema, max_tokens=max_tokens)
        return "{}", f"gemini:{M1}"

    monkeypatch.setattr(explain, "_gemini", fake)
    from wtd.ai import campaign
    name, raw, label, model, err = next(explain.attempts([{"role": "user", "content": "x"}], campaign.SCHEMA, "campaign_brief", 1400))
    assert name == "gemini" and model == M1 and got == {"schema": campaign.SCHEMA, "max_tokens": 1400}


def test_health_reports_the_provider_actually_configured(gem, monkeypatch):
    monkeypatch.setattr(explain, "ollama_up", lambda: False)
    s = explain.status()
    assert s == {"provider": "gemini", "model": M1, "fallback_models": [M2], "status": "configured"}
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert explain.status()["status"] == "not configured"
    monkeypatch.setattr(explain, "ollama_up", lambda: True)
    assert explain.status()["provider"] == "ollama (local)"
    monkeypatch.setattr(explain, "SETTINGS", replace(explain.SETTINGS, ai_enabled=False))
    assert explain.status()["status"] == "disabled"
