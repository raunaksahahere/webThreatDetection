"""Investigator-supplied URLhaus key (X-URLhaus-Key): used for one analysis, precedence over the server key,
shape-checked, never stored in the report or database, and testable without saving it."""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from wtd import intel, pipeline

USER_KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678abcdef01"
SERVER_KEY = "f" * 48
TOKEN = {"X-WTD-Token": "test-token"}


@pytest.fixture()
def seen_keys(monkeypatch):
    keys: list[str] = []

    def fake(kind, value, key):
        keys.append(key)
        return {"query_status": "no_results"}

    monkeypatch.setattr(intel, "_urlhaus", fake)
    return keys


@pytest.fixture(scope="module")
def client():
    from wtd.api import app
    return TestClient(app)


def test_user_key_used_when_server_has_none(seen_keys, monkeypatch):
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    out = intel.lookup("https://example.org/x", ["example.org"], user_urlhaus_key=USER_KEY)
    chk = next(c for c in out.checks if c.name == "intel.urlhaus")
    assert chk.status == "succeeded" and "own key" in chk.detail and USER_KEY not in chk.detail
    assert seen_keys and set(seen_keys) == {USER_KEY}


def test_user_key_takes_precedence_over_server_key(seen_keys, monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", SERVER_KEY)
    intel.lookup("https://example.org/y", ["example.org"], user_urlhaus_key=USER_KEY)
    assert set(seen_keys) == {USER_KEY}


def test_no_key_anywhere_is_unavailable_not_clean(seen_keys, monkeypatch):
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    out = intel.lookup("https://example.org/z", ["example.org"])
    chk = next(c for c in out.checks if c.name == "intel.urlhaus")
    assert chk.status == "unavailable" and "personal key" in chk.detail and not seen_keys


def test_rejected_user_key_is_reported_as_theirs(monkeypatch):
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)

    def reject(kind, value, key):
        raise PermissionError("URLhaus rejected the Auth-Key (HTTP 401)")

    monkeypatch.setattr(intel, "_urlhaus", reject)
    out = intel.lookup("https://example.org/w", ["example.org"], user_urlhaus_key=USER_KEY)
    chk = next(c for c in out.checks if c.name == "intel.urlhaus")
    assert chk.status == "unavailable" and "investigator's own key" in chk.detail


@pytest.mark.parametrize("bad", ["short", "has space in it 0123456789", "x" * 101, "abcé" * 10, "key;drop" + "a" * 20])
def test_malformed_header_rejected(client, bad):
    r = client.post("/api/analyses", json={"kind": "url", "url": "https://example.com"}, headers={**TOKEN, "X-URLhaus-Key": bad.encode("utf-8")})
    assert r.status_code == 422


def test_header_reaches_pipeline_and_is_never_stored(client, monkeypatch):
    got = {}

    def fake_analyse(rid, url, via=None, urlhaus_key=None):
        got["key"] = urlhaus_key

    monkeypatch.setattr(pipeline, "analyse_url", fake_analyse)
    r = client.post("/api/analyses", json={"kind": "url", "url": "https://example.com/judge"}, headers={**TOKEN, "X-URLhaus-Key": USER_KEY})
    assert r.status_code == 202
    pipeline.EXECUTOR.submit(lambda: None).result()  # let the worker pick the job up
    assert got.get("key") == USER_KEY
    rid = r.json()["id"]
    assert USER_KEY not in json.dumps(client.get(f"/api/analyses/{rid}", headers=TOKEN).json())
    con = sqlite3.connect(pipeline.STORE.path if hasattr(pipeline.STORE, "path") else __import__("os").environ["WTD_DB"])
    dump = "\n".join(con.iterdump())
    assert USER_KEY not in dump


def test_message_links_inherit_user_key(client, monkeypatch):
    from wtd.message import analyse as msg
    got = {}

    def fake_analyse(rid, text, investigate_links, via=None, urlhaus_key=None):
        got["key"] = urlhaus_key

    monkeypatch.setattr(msg, "analyse_message", fake_analyse)
    r = client.post("/api/analyses", json={"kind": "message", "text": "verify at https://example.net/a", "investigate_links": True},
                    headers={**TOKEN, "X-URLhaus-Key": USER_KEY})
    assert r.status_code == 202
    pipeline.EXECUTOR.submit(lambda: None).result()
    assert got.get("key") == USER_KEY


def test_key_check_endpoint(client, monkeypatch):
    monkeypatch.setattr(intel, "check_urlhaus_key", lambda k: (k == USER_KEY, "URLhaus accepted this key" if k == USER_KEY else "URLhaus rejected this key (HTTP 401)"))
    assert client.post("/api/intel/urlhaus/check", headers={"X-URLhaus-Key": USER_KEY}).status_code == 401  # operator token still required
    ok = client.post("/api/intel/urlhaus/check", headers={**TOKEN, "X-URLhaus-Key": USER_KEY})
    assert ok.status_code == 200 and ok.json()["accepted"] is True
    bad = client.post("/api/intel/urlhaus/check", headers={**TOKEN, "X-URLhaus-Key": "0" * 48})
    assert bad.status_code == 200 and bad.json()["accepted"] is False
    assert client.post("/api/intel/urlhaus/check", headers=TOKEN).status_code == 422
