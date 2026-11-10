"""Message evaluation: statistics, cleaning, deterministic splits, and a guard that it mirrors the production message path."""
import json

import pytest

from wtd import evaluation as ev
from wtd import intel
from wtd.message import analyse as ma


def test_wilson_interval_known_values():
    assert ev.wilson(0, 0) == [None, None]
    lo, hi = ev.wilson(50, 100)
    assert (lo, hi) == (40.4, 59.6)
    lo, hi = ev.wilson(0, 20)
    assert lo == 0.0 and 15.0 < hi < 17.0  # an observed 0% on 20 is still compatible with about 16%
    lo, hi = ev.wilson(20, 20)
    assert hi == 100.0 and 83.0 < lo < 85.0


def test_rate_and_confusion_on_a_hand_made_set():
    def r(stratum, cls, ft=None, split="holdout"):
        return {"stratum": stratum, "classification": cls, "fraud_type": ft, "split": split, "codes": [], "ms": 1.0, "snippet": "", "dataset": "d",
                "index": 0, "sha256": "x", "rule": ""}

    rs = ([r(ev.POSITIVE, "High Risk", "KYC Scam")] * 3 + [r(ev.POSITIVE, "Low Risk", "KYC Scam")] + [r(ev.POSITIVE, "Suspicious", "Job Scam")]
          + [r("legit_uci_ham", "Low Risk")] * 8 + [r("legit_uci_ham", "Suspicious")] + [r("legit_scamshield", "Low Risk")] * 2
          + [r("legit_scamshield", "Inconclusive")]
          + [r("ambiguous_promo", "Suspicious")] * 5 + [r("uci_spam", "Low Risk")] * 5)  # informational strata never enter the matrix
    c = ev.confusion(rs)
    assert (c["tp"], c["fn"], c["fp"], c["tn"]) == (4, 1, 1, 11)
    assert c["recall"]["pct"] == 80.0 and c["false_positive_rate"]["k"] == 1 and c["abstentions"]["k"] == 1
    assert c["precision_on_this_mixture"]["pct"] == 80.0
    s = ev.summarise(rs)
    assert s["holdout"]["recall_by_fraud_type"]["KYC Scam"]["k"] == 3 and s["holdout"]["recall_by_fraud_type"]["Job Scam"]["n"] == 1
    assert s["rules_missing_on_false_negatives"] == {"KYC Scam": 1}
    assert ev.errors(rs)["false_positives"][0]["classification"] == "Suspicious" and len(ev.errors(rs)["missed_scams"]) == 1


def test_split_is_deterministic_normalised_and_roughly_30_70():
    a = ev.Row("d", 0, ev.POSITIVE, None, "Hello   WORLD ")
    b = ev.Row("d", 9, ev.POSITIVE, None, "hello world")
    assert a.sha == b.sha and a.split == b.split
    rows = [ev.Row("d", i, "legit_uci_ham", None, f"message number {i}") for i in range(2000)]
    dev = sum(r.split == "dev" for r in rows)
    assert 0.25 < dev / 2000 < 0.35 and {r.split for r in rows} == {"dev", "holdout"}


def test_build_removes_duplicates_conflicts_and_cross_dataset_overlap():
    ss = [ev.Row("ScamShield-IN", 0, ev.POSITIVE, "KYC Scam", "Update KYC now at x.com"),
          ev.Row("ScamShield-IN", 1, ev.POSITIVE, "KYC Scam", "update  kyc now at x.com"),  # duplicate after normalisation
          ev.Row("ScamShield-IN", 2, "legit_scamshield", None, "Dinner at 8?"),
          ev.Row("ScamShield-IN", 3, ev.POSITIVE, "Job Scam", "Same text two labels"),
          ev.Row("ScamShield-IN", 4, "legit_scamshield", None, "same text two labels")]
    uci = [ev.Row("UCI", 0, "legit_uci_ham", None, "DINNER at 8?"), ev.Row("UCI", 1, "legit_uci_ham", None, "See you tomorrow")]
    rows, log = ev.build(ss, uci)
    assert log["uci_removed_overlap_with_scamshield"] == 1 and log["exact_duplicates_removed"] == 1 and log["conflicting_labels_removed"] == 1
    assert sorted(r.text for r in rows) == ["Dinner at 8?", "See you tomorrow", "Update KYC now at x.com"]


def test_loaders_use_only_labelled_rows_and_map_strata(tmp_path):
    p = tmp_path / "ss.json"
    p.write_text(json.dumps([{"message": "m1", "label": "fraud", "fraud_type": "OTP Phishing"}, {"message": "m2", "label": "fraud", "fraud_type": "Generic Promo Fraud"},
                             {"message": "m3", "label": "legit", "fraud_type": None}, {"message": "chat", "label": None, "fraud_type": None}, {"label": "fraud"}]))
    assert [(r.stratum, r.text) for r in ev.load_scamshield(p)] == [(ev.POSITIVE, "m1"), ("ambiguous_promo", "m2"), ("legit_scamshield", "m3")]
    u = tmp_path / "uci"
    u.write_text("ham\thello there\nspam\twin a prize\nbogus\tx\nham\t\n")
    assert [(r.stratum, r.text) for r in ev.load_uci(u)] == [("legit_uci_ham", "hello there"), ("uci_spam", "win a prize")]


MESSAGES = [
    "Dear SBI customer, your YONO account will be BLOCKED today. Update KYC within 2 hours at hxxps://sbi-kycupdate[.]top/login and share the OTP",
    "Your Amazon order #402-1234567 has been delivered. Thanks for shopping.",
    "Congratulations! You are selected for a work from home job. Pay Rs 500 registration fee via UPI to claim@okaxis",
    "Meeting moved to 4pm, see you there",
    "HDFC Bank: 482913 is your OTP for login. Do not share this OTP with anyone.",
    "From: Support <help@paypa1-secure.top>\nTo: you@example.com\nSubject: Verify your account\nDate: Mon, 10 Nov 2026 10:00:00 +0000\n\nClick https://paypa1-secure.top/login to verify.",
]


@pytest.mark.parametrize("text", MESSAGES)
def test_offline_assessment_matches_the_production_message_path(text, monkeypatch):
    """The evaluation must measure what the pipeline does before any network lookup: same findings, same class."""
    monkeypatch.setattr(intel, "lookup", lambda *a, **k: intel.IntelOutcome())
    monkeypatch.setattr(ma, "submit_url", lambda *a, **k: None)
    r = ma.new_report("message", "x", text)
    ma.analyse_message(r.id, text, investigate_links=False)
    got = ma.STORE.get(r.id)
    assert got.status == "complete"
    prod = {f.code for f in got.findings if f.severity != "info" and not f.code.startswith("correlation")}
    mine = ev.assess_message(text)
    assert set(mine["codes"]) == prod
    # the production classifier also sees intel checks; with none configured they are not essential here, so classes agree unless a
    # production-only essential check is missing (CERT Polska), which is exactly the documented abstention path.
    if got.assessment.classification != "Inconclusive":
        assert mine["classification"] == got.assessment.classification


def test_ai_checks_are_independent_of_the_validator():
    msg = "Pay Rs 500 at fee-now.top within 2 hours"
    ai = {"summary": "It asks for 500 rupees and says the site is fee-now.top. A 9999 fine is also mentioned.",
          "points": [{"explanation": "Mentions 2 hours.", "finding_ids": ["msg.urgency"]}],
          "observations": [{"quote": "Pay Rs 500", "rationale": "payment"}, {"quote": "send your password", "rationale": "invented"}],
          "recommended_actions": ["Visit evil-bank.com"]}
    c = ev.ai_checks(ai, msg, "Creates time pressure")
    assert c["unverified_quotes"] == 1 and c["observations"] == 2
    assert c["unsupported_numbers"] == ["9999"] and c["unsupported_domains"] == ["evil-bank.com"]
