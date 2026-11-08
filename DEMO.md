# Demo script (3 minutes; rehearsable)

Journey: **submit → safe investigation → explanation → risk → correlate → register commitment → independent review → independent verification.**

## Before recording (5 min)
```bash
export PATH=$HOME/.foundry/bin:$PATH
scripts/chain.sh start && scripts/deploy.sh      # chain + contract (state survives restarts)
scripts/api.sh start                             # http://127.0.0.1:8000/
ollama serve >/dev/null 2>&1 &                   # local AI fallback (if not already running)
cat data/api_token                               # paste into the dashboard prompt
backend/.venv/bin/python scripts/run_cases.py    # pre-runs all documented cases (fallback material)
backend/.venv/bin/python scripts/seed_campaign.py   # 3 synthetic task-scam messages sharing a UPI ID + e-mail → campaign cluster
```
Then open Incidents and click **Generate AI campaign brief** once, so it is cached (it takes up to about 90 s with free or local models).
Open two windows: the browser on the dashboard, and a terminal in the repo root. Load the extension (see `extension/README.md`) and turn on "Warn me before risky pages" in its options.

## Script

| Time | Show | Say (short) |
|---|---|---|
| 0:00 | Investigate page | "Paste a link, a message or a raw e-mail and get evidence, not just a label." |
| 0:08 | Message tab → **Load an .eml file** → `backend/tests/fixtures/phish_paypal.eml` (synthetic) → Start | "This is the raw source of a fake PayPal e-mail." |
| 0:20 | Report: **High Risk** and its findings: DMARC fail, display-name spoof, Reply-To to Gmail, link text showing paypal.com but going elsewhere, `Invoice_8812.pdf.html` attachment, OTP request | "Every finding names its evidence and its limitation. Authentication results come from the receiving server, and the attachment is listed, never opened." |
| 0:40 | AI panel: summary, finding-ID chips, model badge | "The AI explains only these findings. Citations and quotes are checked in code, and it can't change the result." |
| 0:50 | Website tab → `https://paypa1.com/signin` → **High Risk**: typosquat + TLS hostname mismatch, redirect chain, TLS panel | "We connect only to validated public IPs and run no scripts. The certificate is checked independently." |
| 1:05 | History → **SYNTHETIC FIXTURE** report (eMudhra-like) | "Chains are matched against browser distrust data, including the eight real eMudhra fingerprints from Mozilla bug 2083449. This chain is synthetic, and labelled so." |
| 1:20 | Incidents → **Campaign link** card (3 different messages share a UPI ID and an e-mail) → AI campaign brief | "Correlation is deterministic. Repeat checks of one site are never called a campaign. The AI brief may cite only this cluster's indicators, and its verdict can't exceed the link type." |
| 1:40 | Open one campaign report → **Register commitment on-chain** → tx hash, block | "Only a salted hash and a class code go on-chain. No URL, message or personal data." |
| 1:50 | **Independent review** → Disputed + note → status updates | "A separate reviewer key. The contract forbids self-review, and only the note's hash goes on-chain." |
| 2:00 | **Download report** → terminal: `node verifier/verify.mjs --envelope ~/Downloads/wtd-threat-report-*.json --deployment deployments/local.json` → `RESULT: MATCH` with status history | "A separate Node tool recomputes the hash and reads the contract directly." |
| 2:15 | Tamper (one-liner below), rerun → `NO MATCH` (exit 1) | "Any change is detected. The chain proves integrity, not truth." |
| 2:25 | Browser: type `https://xn--80ak6aa92e.com/` → extension **warning page** | "The optional real-time mode checks only the address against your local server. Nothing goes to third parties." |
| 2:40 | `docs/EVALUATION.md` table | "False positives are measured: 0.4% on 1,000 unseen popular sites from the URL rules alone. Lexical rules catch only about 11% of real phishing domains on their own, which is why feeds, TLS and page evidence exist." |
| 2:52 | Report limitations section | "No tool can prove a site is safe. We show what was checked, what wasn't, and why." |

Tampering one-liner:
`jq '.threat_report.classification="Low Risk"' ~/Downloads/wtd-threat-report-*.json > /tmp/tampered.json && node verifier/verify.mjs --envelope /tmp/tampered.json --deployment deployments/local.json`

If the Sepolia deployment exists (`deployments/sepolia.json`), you can show the same registration on Etherscan instead of the local chain. Run the API with `WTD_NETWORK=sepolia scripts/api.sh restart`, and the verifier with `--deployment deployments/sepolia.json --rpc https://ethereum-sepolia-rpc.publicnode.com`.

## Fallbacks (say what is happening; never fake it)
| Problem | Fallback |
|---|---|
| Internet down | Use pre-run reports from History (persisted in SQLite). The e-mail, the synthetic TLS demo, chain registration, review and the verifier all work offline. Say: "these were run earlier today". |
| Free AI model rate-limited (HTTP 429) | The local model takes over automatically (15–90 s); the badge shows `ollama (local)`. |
| No AI at all | The report shows "AI unavailable" and the deterministic findings stand alone. Say so. |
| Chain not running | `scripts/chain.sh start && scripts/deploy.sh`. The register button shows "blockchain unavailable" until then. |
| A live site changed or went offline | Use its pre-run report; classifications of live sites can legitimately change over time. |
| Extension not loaded | Show `docs/screenshots/10-extension-warning.png`, captured by the automated browser test. |

Do not open any analysed link in the browser during the demo. The homograph domain above is a public, harmless demonstration page.
