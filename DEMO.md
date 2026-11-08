# Demo script (3 minutes; rehearsable)

Journey: **submit → safe investigation → explanation → risk → register commitment → independent verification.**

## Before recording (5 min)
```bash
export PATH=$HOME/.foundry/bin:$PATH
scripts/chain.sh start && scripts/deploy.sh      # chain + contract (state survives restarts)
scripts/api.sh start                             # http://127.0.0.1:8000/
ollama serve >/dev/null 2>&1 &                   # local AI fallback (if not already running)
cat data/api_token                               # paste into the dashboard prompt
backend/.venv/bin/python scripts/run_cases.py    # pre-runs all documented cases (fallback material)
```
Open two windows: the browser on the dashboard, and a terminal in the repo root.

## Script

| Time | Show | Say (short) |
|---|---|---|
| 0:00 | Investigate page | "Paste a link or a message and get evidence, not just a label." |
| 0:10 | **Message tab** → paste case S1 (SBI KYC message) → Start | "This claims to be State Bank of India." |
| 0:25 | Report: **High Risk**, rule R-HIGH-1, coverage counts | "Deterministic rules decide. The class comes from named findings: an OTP request, a brand-to-link mismatch, and a look-alike domain." |
| 0:40 | AI panel: summary, finding-ID chips, model badge | "The AI explains only these findings. Its citations and quotes are checked in code, and it can't change the result." |
| 0:55 | Message tab → case B3 (urgent NEET reminder) → **Low Risk** with "Creates time pressure" listed | "Urgency is noted but isn't fraud: official link, no request for secrets." |
| 1:10 | Website tab → `https://paypa1.com/signin` → **High Risk** | "A typosquat with a mismatched certificate. We connect only to validated public IPs and run no scripts." Show redirect chain + TLS panel. |
| 1:35 | History → **SYNTHETIC FIXTURE** report (eMudhra-like) | "The eMudhra CA keys were publicly recoverable. We match chains against browser distrust data, including the eight real eMudhra fingerprints from Mozilla's bug 2083449. This chain is synthetic, and it's labelled that way." |
| 1:55 | Back to S1 report → **Register commitment on-chain** → tx hash, block, contract | "Only a salted hash goes on-chain. No URL, message or personal data." |
| 2:10 | **Download report** → terminal: `node verifier/verify.mjs --envelope ~/Downloads/wtd-threat-report-*.json --deployment deployments/local.json` → `RESULT: MATCH` | "A separate Node tool recomputes the hash and reads the contract directly." |
| 2:30 | Edit the file (`"High Risk"` → `"Low Risk"`), rerun → `RESULT: NO MATCH` (exit 1) | "Any change is detected. The chain proves integrity, not truth." |
| 2:45 | Report footer limitations | "No tool can prove a site is safe. We show what was checked, what wasn't, and why." |

Tampering one-liner:
`jq '.threat_report.classification="Low Risk"' ~/Downloads/wtd-threat-report-*.json > /tmp/tampered.json && node verifier/verify.mjs --envelope /tmp/tampered.json --deployment deployments/local.json`

## Fallbacks (say what is happening; never fake it)
| Problem | Fallback |
|---|---|
| Internet down | Use pre-run reports from History (persisted in SQLite); the synthetic TLS demo, chain registration and the verifier all work offline. State: "these were run earlier today". |
| Free AI model rate-limited (HTTP 429) | The local model takes over automatically (15–45 s); the badge shows `ollama (local)`. |
| No AI at all | The report shows "AI unavailable" and the deterministic findings stand alone. Say so. |
| Chain not running | `scripts/chain.sh start && scripts/deploy.sh`. The register button shows "blockchain unavailable" until then. |
| A live site changed or went offline | Use its pre-run report; classifications of live sites can legitimately change over time. |

Do not open any analysed link in the browser during the demo.
