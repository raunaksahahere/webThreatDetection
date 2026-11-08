"""Submit three SYNTHETIC task-scam messages that share a payment handle and a contact address, so the Incidents view
shows a deterministic campaign cluster and the AI campaign brief can be demonstrated.

The identifiers are fictional: the e-mail uses the reserved .invalid TLD (RFC 2606) and the UPI handle is a demo
string. Usage: backend/.venv/bin/python scripts/seed_campaign.py [--base http://127.0.0.1:8000]
"""
import argparse
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
MESSAGES = [
    "Hello! We are hiring for a part-time online job. Earn Rs 2500 daily by rating hotels from home. Registration fee Rs 499 "
    "(refundable) — pay to UPI wtd.demo.campaign@ybl and send the screenshot to hr.desk@wtd-demo.invalid",
    "Congratulations, your profile is selected for the video like task. Daily income Rs 3000. To activate your account pay "
    "Rs 999 today to wtd.demo.campaign@ybl. Contact hr.desk@wtd-demo.invalid for joining.",
    "Prepaid task bonus: deposit Rs 5000 and receive Rs 8000 back within 24 hours. Only 10 slots left. Transfer to UPI "
    "wtd.demo.campaign@ybl. Queries: hr.desk@wtd-demo.invalid",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    a = ap.parse_args()
    h = {"X-WTD-Token": (ROOT / "data/api_token").read_text().strip()}
    ids = []
    for m in MESSAGES:
        r = httpx.post(f"{a.base}/api/analyses", json={"kind": "message", "text": m, "investigate_links": False}, headers=h, timeout=30)
        r.raise_for_status()
        ids.append(r.json()["id"])
    for i in ids:
        for _ in range(120):
            rep = httpx.get(f"{a.base}/api/analyses/{i}", headers=h, timeout=30).json()
            if rep["status"] not in ("queued", "running"):
                break
            time.sleep(2)
        print(i, rep["status"], (rep.get("assessment") or {}).get("classification"))
    cl = [c for c in httpx.get(f"{a.base}/api/incidents", headers=h, timeout=30).json() if set(ids) <= set(c["report_ids"])]
    if not cl:
        print("no cluster found", file=sys.stderr)
        return 1
    print("cluster", cl[0]["cluster_id"], cl[0]["kind"], cl[0]["shared"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
