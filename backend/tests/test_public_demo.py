"""Public demo mode (WTD_PUBLIC_DEMO=1): no token needed, per-session and per-visitor daily quotas,
operator token lifts quotas, on-chain writes stay operator-only on non-local chains; token mode unchanged when off."""
import pytest
from fastapi.testclient import TestClient

from wtd import access, pipeline

TOKEN = {"X-WTD-Token": "test-token"}
S1 = {"X-WTD-Session": "11111111-2222-4333-8444-555555555555"}
S2 = {"X-WTD-Session": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}
URL = {"kind": "url", "url": "https://example.com/demo"}


@pytest.fixture()
def client():
    from wtd.api import app
    return TestClient(app)


@pytest.fixture()
def public(monkeypatch):
    monkeypatch.setenv("WTD_PUBLIC_DEMO", "1")
    monkeypatch.setenv("WTD_PUBLIC_SESSION_LIMIT", "3")
    monkeypatch.setenv("WTD_PUBLIC_DAILY_LIMIT", "5")
    monkeypatch.setattr(pipeline, "analyse_url", lambda *a, **k: None)  # no network in these tests
    access.QUOTA.reset()
    from wtd import api
    api._hits.clear()
    yield
    access.QUOTA.reset()


def test_token_mode_is_unchanged_when_switch_is_off(client, monkeypatch):
    monkeypatch.delenv("WTD_PUBLIC_DEMO", raising=False)
    assert client.post("/api/analyses", json=URL).status_code == 401
    assert client.get("/api/analyses").status_code == 401
    assert client.get("/api/health").json()["access"] == {"mode": "operator_token"}
    assert client.get("/api/quota").json() == {"public_demo": False}


def test_public_mode_needs_no_token(client, public):
    h = client.get("/api/health").json()["access"]
    assert h["mode"] == "public_demo" and h["session_limit"] == 3 and h["daily_limit"] == 5
    r = client.post("/api/analyses", json=URL, headers=S1)
    assert r.status_code == 202 and r.json()["quota"]["session"] == {"used": 1, "limit": 3, "remaining": 2}
    assert client.get("/api/analyses").status_code == 200
    assert client.get(f"/api/analyses/{r.json()['id']}").status_code == 200


def test_session_limit_then_daily_limit(client, public):
    codes = [client.post("/api/analyses", json=URL, headers=S1).status_code for _ in range(4)]
    assert codes == [202, 202, 202, 429]
    msg = client.post("/api/analyses", json=URL, headers=S1).json()["detail"]
    assert "3 analyses per browser session" in msg
    assert client.get("/api/quota", headers=S1).json()["session"]["remaining"] == 0
    # A new session gets its own allowance, but the visitor's daily cap (5) still bounds it.
    codes2 = [client.post("/api/analyses", json=URL, headers=S2).status_code for _ in range(3)]
    assert codes2 == [202, 202, 429]
    assert "per visitor per day" in client.post("/api/analyses", json=URL, headers=S2).json()["detail"]


def test_missing_or_bogus_session_header_falls_back_to_address(client, public):
    for h in ({}, {"X-WTD-Session": "x"}, {"X-WTD-Session": "bad id with spaces 1234567890"}):
        client.post("/api/analyses", json=URL, headers=h)
    assert client.get("/api/quota").json()["session"]["used"] == 3


def test_rejected_address_does_not_use_quota(client, public):
    r = client.post("/api/analyses", json={"kind": "url", "url": "javascript:alert(1)"}, headers=S1)
    assert r.status_code == 422
    assert client.get("/api/quota", headers=S1).json()["session"]["used"] == 0


def test_operator_token_lifts_quotas(client, public):
    codes = [client.post("/api/analyses", json=URL, headers={**S1, **TOKEN}).status_code for _ in range(6)]
    assert codes == [202] * 6
    assert client.get("/api/quota", headers=TOKEN).json() == {"public_demo": True, "operator": True}


def test_wrong_token_is_treated_as_visitor_not_operator(client, public):
    codes = [client.post("/api/analyses", json=URL, headers={**S1, "X-WTD-Token": "wrong"}).status_code for _ in range(4)]
    assert codes[-1] == 429


def test_chain_writes_open_only_on_local_chain(client, public, monkeypatch):
    rid = client.post("/api/analyses", json=URL, headers=S1).json()["id"]
    monkeypatch.setattr(access, "local_chain", lambda: False)
    for path, body in ((f"/api/analyses/{rid}/threat-report", {}), (f"/api/analyses/{rid}/threat-report/revise", {"reason": "x"}),
                       (f"/api/analyses/{rid}/threat-report/review", {"status": "Validated", "note": "n"})):
        r = client.post(path, json=body)
        assert r.status_code == 401 and "public chain" in r.json()["detail"]
    monkeypatch.setattr(access, "local_chain", lambda: True)
    assert client.post(f"/api/analyses/{rid}/threat-report", json={}).status_code != 401


def test_chain_writes_need_token_when_switch_off(client, monkeypatch):
    monkeypatch.delenv("WTD_PUBLIC_DEMO", raising=False)
    monkeypatch.setattr(access, "local_chain", lambda: True)
    assert client.post("/api/analyses/x/threat-report", json={}).status_code == 401


def test_local_chain_reads_deployment(tmp_path, monkeypatch):
    from dataclasses import replace
    from wtd import config
    f = tmp_path / "d.json"
    monkeypatch.setattr(config, "SETTINGS", replace(config.SETTINGS, deployment_file=f))
    assert access.local_chain() is False  # missing file → treated as public (locked)
    f.write_text('{"chainId": 11155111}')
    assert access.local_chain() is False
    f.write_text('{"chainId": 31337}')
    assert access.local_chain() is True
