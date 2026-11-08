"""TLS fixtures, classification policy, message rules, and commitment canonicalization."""
import json
from pathlib import Path

import pytest
from cryptography.x509.verification import Store

from wtd.checks import tls_checks
from wtd.classify import classify
from wtd.message.analyse import analyse_text, redact
from wtd.models import CheckResult, Finding, iso
from wtd.registry.canonical import canonical_bytes, commitment, make_envelope, report_id_bytes32
from wtd.tls_fixtures import build

ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------ TLS
@pytest.mark.parametrize("kind,expected", [
    ("valid", {"tls.valid"}), ("expired", {"tls.expired"}), ("mismatch", {"tls.hostname_mismatch"}),
    ("untrusted", {"tls.untrusted_chain"}), ("self_signed", {"tls.self_signed"}), ("distrusted", {"tls.distrusted_ca"}),
    ("weak_rsa", {"tls.weak_key"}),
])
def test_tls_fixture_scenarios(kind, expected):
    chain, root = build(kind)
    f, s = tls_checks.analyse_chain("demo.wtd.test", False, chain, "TLSv1.3", None, store=Store([root]))
    codes = {x.code for x in f}
    assert expected <= codes, codes
    if kind != "valid":
        assert "tls.valid" not in codes


def test_configuration_problem_is_not_a_trust_incident():
    chain, root = build("expired")
    f, _ = tls_checks.analyse_chain("demo.wtd.test", False, chain, None, None, store=Store([root]))
    assert "tls.distrusted_ca" not in {x.code for x in f}
    exp = next(x for x in f if x.code == "tls.expired")
    assert exp.strength == "moderate" and "not evidence of phishing" in exp.limitation


def test_distrusted_fixture_is_labelled_synthetic():
    chain, root = build("distrusted")
    f, _ = tls_checks.analyse_chain("demo.wtd.test", False, chain, None, None, store=Store([root]))
    d = next(x for x in f if x.code == "tls.distrusted_ca")
    assert d.provenance == "synthetic" and "SYNTHETIC" in d.source


def test_real_emudhra_entries_loaded():
    idx = tls_checks.default_distrust_index()
    cur = json.loads((ROOT / "backend/wtd/data/distrust/curated_incidents.json").read_text())
    fps = [c["sha256"] for c in cur["incidents"][0]["certificates"]]
    assert len(fps) == 8 and all(fp in idx.by_cert_sha256 for fp in fps)
    assert len(idx.by_spki_sha256) > 100  # Chromium blocklist parsed


# ------------------------------------------------------------------ classification
def F(code, sev, strength, module="url"):
    return Finding(id=code, code=code, module=module, title=code, observed="x", source="test", observed_at=iso(), severity=sev,
                   strength=strength, impact="", recommendation="", limitation="")


OK = [CheckResult(name="fetch.page", module="web", status="succeeded", essential=True)]
MISSING = [CheckResult(name="fetch.page", module="web", status="failed", essential=True)]


def test_authoritative_listing_confirms():
    assert classify([F("intel.certpl_listed", "critical", "authoritative", "intel")], OK).classification == "Confirmed Malicious"


def test_strong_high_is_high_risk():
    assert classify([F("url.homograph", "critical", "strong")], OK).classification == "High Risk"


def test_two_tls_config_problems_count_once():
    fs = [F("tls.expired", "high", "moderate", "tls"), F("tls.hostname_mismatch", "high", "moderate", "tls")]
    assert classify(fs, OK).classification == "Suspicious"


def test_weak_signals_capped_at_suspicious():
    fs = [F(f"msg.w{i}", "medium", "weak", "message") for i in range(8)]
    assert classify(fs, OK).classification == "Suspicious"


def test_posture_findings_excluded():
    fs = [F(f"web.hdr.{i}", "medium", "weak", "web") for i in range(6)]
    assert classify(fs, OK).classification == "Low Risk"


def test_missing_essential_check_is_inconclusive_not_low():
    a = classify([F("url.keywords", "low", "weak")], MISSING)
    assert a.classification == "Inconclusive" and a.coverage.essential_missing == ["fetch.page"]


def test_valid_cert_does_not_lower_risk_and_is_noted():
    fs = [F("url.homograph", "critical", "strong"), F("tls.valid", "info", "weak", "tls")]
    a = classify(fs, OK)
    assert a.classification == "High Risk" and any("valid" in c for c in a.contradictions)


def test_no_intel_listing_is_unknown_not_clean():
    fs = [F("intel.no_listing", "info", "weak", "intel"), F("url.typosquat", "high", "moderate"), F("url.brand_in_domain", "high", "moderate")]
    a = classify(fs, OK)
    assert a.classification == "High Risk" and any("unknown, not clean" in c for c in a.contradictions)


# ------------------------------------------------------------------ messages
def msg_class(text):
    f, *_ = analyse_text(text)
    return classify(f, [CheckResult(name="message.rules", module="message", status="succeeded", essential=True)]).classification, {x.code for x in f}


def test_benign_urgent_message_not_fraud():
    cls, codes = msg_class("Reminder: NEET registration closes today at 11:50 PM. Apply only on https://neet.nta.ac.in/. Do not share your OTP with anyone.")
    assert "msg.urgency" in codes and cls == "Low Risk"


def test_benign_otp_notice_not_a_credential_request():
    cls, codes = msg_class("123456 is your OTP for HDFC Bank NetBanking. Do not share it with anyone. HDFC Bank never asks for OTP.")
    assert "msg.credential_request" not in codes and cls == "Low Risk"


def test_kyc_phish_is_high_risk():
    cls, codes = msg_class("Dear SBI customer, your account will be blocked today. Update KYC at hxxps://sbi-kyc-update[.]top/login and share the OTP.")
    assert {"msg.credential_request", "msg.brand_link_mismatch"} <= codes and cls == "High Risk"


def test_advance_fee_job_scam_is_high_risk():
    cls, codes = msg_class("Part-time job, earn Rs 3000 per day by liking videos. Pay registration fee of Rs 499 to rahulk@ybl to start.")
    assert "msg.unusual_payment" in codes and cls == "High Risk"


def test_personal_identifiers_masked_and_hashed():
    f, ind, facts, _ = analyse_text("Call 9876543210 or mail john.doe@gmail.com, pay to rahulk@ybl")
    shown = json.dumps(facts) + json.dumps([d for _, _, d in ind])
    assert "9876543210" not in shown and "john.doe" not in shown and "rahulk@" not in shown
    assert all(k.startswith("hmac:") for t, k, _ in ind if t in ("phone", "email", "upi"))
    assert "9876543210" not in redact("call 98765 43210")


# ------------------------------------------------------------------ commitments
def test_commitment_vectors_reproduce():
    v = json.loads((ROOT / "docs/commitment-vectors.json").read_text())
    for vec in v["vectors"]:
        assert commitment(vec["envelope"]) == vec["commitment"]
        assert canonical_bytes(vec["envelope"]).decode() == vec["jcs_utf8"]
    assert commitment(v["tampered"]["envelope"]) != v["vectors"][0]["commitment"]
    assert report_id_bytes32(v["report_id"]) == v["report_id_bytes32"]


def test_floats_rejected_and_salt_changes_commitment():
    with pytest.raises(ValueError):
        canonical_bytes({"a": 1.5})
    tr = {"schema": "wtd.threat-report.v1", "report_id": "x"}
    assert commitment(make_envelope(tr)) != commitment(make_envelope(tr))  # random salt prevents guessing
