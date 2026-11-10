# WTD: Web Threat Detection & Digital Trust Intelligence

Paste a suspicious **link**, **message**, **raw e-mail** or **QR code** and get an evidence-based risk assessment. Every finding carries its source and its limitations. An AI explanation is grounded in those findings, and the report's integrity is anchored on-chain so anyone can check it independently.

Hackathon prototype (AI · Cybersecurity · Web3).

> Automated checks cannot prove a site or message is safe. "Low Risk" means no significant indicator was found in the checks listed in the report.

## What it does

| Requirement (problem statement §7) | Where |
|---|---|
| URL/domain investigation | `backend/wtd/pipeline.py`, isolated inspector (`inspector.py`, `fetcher.py`, `netguard.py`) |
| Phishing and impersonation indicators | homographs, typosquats, brand-in-domain/subdomain, fake-TLD labels, credential forms posting elsewhere, brand assets hot-linked, new domains (`checks/url_rules.py`, `checks/web_checks.py`, `checks/dns_checks.py`). **False positives measured** on real lists: [`docs/EVALUATION.md`](docs/EVALUATION.md) |
| HTTPS/TLS analysis and trust issues | `checks/tls_checks.py`: independent path verification, expiry, hostname, weak crypto, lifetime, CT, distrust lists (Chromium, Mozilla OneCRL, eMudhra fingerprints from Bugzilla 2083449); `checks/ct_checks.py`: Certificate Transparency **record lookup** (Cert Spotter, crt.sh fallback; a monitoring-service query, not verification of SCT signatures or inclusion proofs) that checks whether the presented certificate is logged and when certificates were first issued for the name |
| AI evidence-grounded explanations | `ai/explain.py`: Gemini (Flash Lite, with a second model when the first is over quota) → free OpenRouter model → local Ollama; strict JSON schema; cited IDs, quotes and classification validated in code |
| Scam-message analysis | `message/analyse.py`: indicator extraction (URLs, emails, phones, UPI, wallets) and social-engineering rules; urgency alone is never fraud |
| E-mail security analysis | `message/email_checks.py`: paste or load raw `.eml`; receiving-server SPF/DKIM/DMARC, display-name and look-alike senders, Reply-To divergence, disguised links, risky attachments (never opened) |
| QR-code scam detection | Dashboard **QR code** tab: decoded locally (jsQR); web addresses get the full investigation; `upi://pay` codes flagged when presented as "scan to receive money" |
| Structured, explainable risk | `classify.py`: five classes, auditable rules, coverage counts, contradictions listed |
| AI correlation | `incidents.py` + `ai/campaign.py`: deterministic clusters typed as campaign / shared infrastructure / repeat checks; validated AI campaign brief (cited indicators, reports and findings checked; verdict capped by link type) |
| Threat intelligence | CERT Polska Warning List (phishing domains), URLhaus (malware URLs), Google Safe Browsing (needs the operator's key) and OpenPhish (**off by default**: its terms restrict use to personal, non-commercial research). Each reports its own status: no match, unavailable, not checked or stale |
| On-chain threat-report registry | `contracts/src/ThreatReportRegistry.sol` (roles, ordered revisions, status history); register, revise and **independent review** (Validated/Disputed/Retracted, separate reviewer key, note hash on-chain) from the dashboard; local anvil chain, Sepolia tooling in `scripts/testnet.sh` |
| Independent verification | `verifier/verify.mjs` (Node + viem) recomputes the commitment and reads contract storage |
| Investigation dashboard | `frontend/` (React + Vite), served at `/` |
| Measured evaluation | URL rules: [`docs/EVALUATION.md`](docs/EVALUATION.md). Message rules: [`docs/EVALUATION_MESSAGES.md`](docs/EVALUATION_MESSAGES.md) (`scripts/eval_messages.py`) |
| ≥ 3 suspicious + 3 benign cases | `TESTING.md`, `docs/test-cases-observed.json` (12 cases, all matched) |
| Optional companion extension | `extension/` (MV3): page and link checks on click; opt-in warning before risky pages via a local-only quick check |

All six functional modules are covered: URL analysis, TLS trust, message analysis, deterministic correlation, passive website security assessment, and decentralised report integrity.

## Quick start (Ubuntu/macOS)

Prerequisites: [uv](https://docs.astral.sh/uv/), Node 20+, [Foundry](https://getfoundry.sh) (`forge`, `anvil`), curl. Optional: Ollama for the local AI fallback.

```bash
scripts/setup.sh                 # Python 3.13 env, contract build, npm installs, dashboard build, intel snapshots
# optional: edit .env → URLHAUS_AUTH_KEY=... (free key from your own abuse.ch account).
#   Visitors never enter a key; every analysis uses this one (public-demo quotas bound how often).
scripts/chain.sh start           # local chain (chain id 31337), state persisted in chain-state/
scripts/deploy.sh                # deploys ThreatReportRegistry, writes deployments/local.json
scripts/api.sh start             # API + dashboard on http://127.0.0.1:8000/
cat data/api_token               # operator token the dashboard asks for
# Public demo instead (no token; per-session and daily limits): WTD_PUBLIC_DEMO=1 scripts/api.sh start
```

Hosting: the API runs as a Docker web service on Render (`render.yaml`, `Dockerfile`) and the dashboard optionally on Vercel (`frontend/vercel.json`, with `VITE_API_BASE` pointing at the API). See [`docs/DEPLOY.md`](docs/DEPLOY.md).

Demonstrations:
- **Offline eMudhra-like demo.** This creates a clearly labelled SYNTHETIC report:

  ```bash
  (cd backend && .venv/bin/python -m wtd.demo tls-distrusted)
  ```

- **Independent verification.** Download a registered report from the dashboard ("Download report for independent verification"), then run:

  ```bash
  node verifier/verify.mjs --envelope wtd-threat-report-XXXX.json --deployment deployments/local.json
  # exit 0 = matches latest revision · 2 = superseded revision · 1 = altered / not anchored · 3 = error
  ```

## Verification evidence

| | Network | Status | Where |
|---|---|---|---|
| **Public** | Ethereum Sepolia (chain id 11155111) | **Not deployed yet.** The testnet reporter address held no test ETH when this snapshot was prepared. The tooling is ready and rehearsed on a disposable local chain; no public contract address or transaction is claimed anywhere in this repository. | After the steps below: `docs/SEPOLIA_EVIDENCE.md`, `docs/evidence/sepolia-demo.json` |
| **Local** | anvil (chain id 31337) | Observed 2026-11-08: register, verify, tamper, revise, review, restart | `docs/WEB3.md` ("Observed results"), `verifier/e2e-demo.sh`. Anvil is a developer chain whose RPCs can rewrite state, so this shows the contract's rules, not public availability |

To produce the public evidence (fund the reporter address printed by `scripts/testnet.sh balance` from a Sepolia faucet first):

```bash
scripts/testnet.sh deploy                                # deploys ThreatReportRegistry, grants roles, writes deployments/sepolia.json
backend/.venv/bin/python scripts/sepolia_evidence.py     # registers a synthetic report, revises and reviews it, runs the independent verifier
                                                         # against a public RPC (match, tampered, superseded, current), writes docs/SEPOLIA_EVIDENCE.md
```

Only a salted commitment hash, a classification code and a note hash go on-chain, and the demonstration report is a synthetic test vector. A match proves a report is unchanged since registration, not that it is true.

Tests:

```bash
(cd backend && .venv/bin/python -m pytest -q)        # 249 tests: request boundary, TLS, CT lookup, intelligence sources, classifier, messages, e-mail, AI validation (explanations and campaign briefs), message evaluation, API, persistence
(cd contracts && forge test)                          # 22 contract tests incl. unauthorised writes and revision ordering
node verifier/test-vectors.mjs                        # cross-language canonicalization vectors
backend/.venv/bin/python scripts/run_cases.py         # documented cases through the live API
(cd e2e && npm install && npm test)                   # real-browser click-through (Brave/Chrome, headless): dashboard 13 steps, extension 13 steps
backend/.venv/bin/python scripts/eval_url_rules.py --tranco top-1m.csv --tranco-id 94P72   # false-positive / detection evaluation (docs/EVALUATION.md)
backend/.venv/bin/python scripts/eval_messages.py --download                                # message-rule evaluation on public labelled SMS data (docs/EVALUATION_MESSAGES.md)
```

The browser checks use an installed Brave or Chrome (`WTD_BROWSER=/path` to override) and save screenshots to `docs/screenshots/`.

![Report page](docs/screenshots/02-report-verdict.png)

## How it decides

| Class | Rule |
|---|---|
| Confirmed Malicious | Authoritative intelligence listing (e.g. a CERT Polska domain match, or an exact fresh URLhaus URL) |
| High Risk | One strong high-severity indicator, or two independent moderate high-severity ones |
| Inconclusive | Nothing significant found, but an essential check failed or was unavailable |
| Suspicious | One moderate indicator, or three weak ones |
| Low Risk | None of the above, with all essential checks completed |

Weak signals (urgent wording, keywords, AI observations, missing security headers) can never exceed Suspicious. Neither a valid certificate nor a missing intelligence listing ever lowers a result. Full methodology: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Web3 design and observed outputs: [`docs/WEB3.md`](docs/WEB3.md). API and schema: [`docs/INTERFACES.md`](docs/INTERFACES.md).

## Safety and privacy
- Arbitrary URLs are treated as hostile:
  - browser-equivalent parsing and an explicit block of private, loopback, metadata and IPv6-embedded addresses;
  - DNS answers are validated, and the connection goes only to a validated IP, with every redirect re-checked;
  - fetches run in a resource-limited child process with no secrets;
  - no scripts are executed, no downloads made, no ports scanned.
- Destinations already listed as malicious are **not visited**.
- Pasted messages are never stored raw. Personal identifiers are kept as keyed hashes and shown masked, and text is redacted before any AI call.
- Only free AI models are used, called with `data_collection: deny`. The AI cannot change findings or the classification; output contradicting them is marked `rejected`.
- Only a hash commitment and a classification code go on-chain. URLs, messages and personal data stay off-chain.

## Limitations (honest scope)
- The documented cases demonstrate coverage, not detection accuracy. The only measured figures are for single layers: the URL rules alone (`docs/EVALUATION.md`: 0.4% flagged on 1,000 unseen popular sites, and 11% of held-out CERT Polska phishing domains caught without the feed) and the message rules on public labelled SMS data (holdout, offline rule layer only): 29 of 48 specific scam messages flagged (60.4%, 95% CI 46.3–73.0%) and 11 of 3,505 legitimate messages flagged (0.3%); the positives look templated and the set is small, see [`docs/EVALUATION_MESSAGES.md`](docs/EVALUATION_MESSAGES.md). There is no end-to-end accuracy figure.
- Intelligence scope:
  - CERT Polska focuses on threats to users in Poland;
  - URLhaus covers malware downloads, not phishing;
  - Google Safe Browsing runs only when the operator sets `GSB_API_KEY` (non-commercial terms; Google receives the scheme, host and path of analysed addresses); without it the report says "unavailable";
  - OpenPhish is disabled unless the operator enables it after confirming its terms are met; the report then says "not checked";
  - a no-hit means unknown.
- Certificate Transparency: the lookup asks a monitoring service (Cert Spotter, then crt.sh) what it has indexed. It does not verify SCT signatures or inclusion proofs, can lag the logs, and is reported as unavailable or inconclusive when the service is slow, rate limited or returns partial data; it never raises a verdict on its own.
- One page is fetched without running scripts, so cloaked phishing kits can look harmless. There is no screenshot or visual comparison.
- The brand list is curated (43 brands) and incomplete; some banks' new `.bank.in` domains are not yet listed.
- E-mail authentication results are taken from the pasted headers as recorded by the receiving server. Whoever pastes the message could edit them, and DKIM signatures are not re-verified.
- Revocation status:
  - OCSP is checked when the certificate lists a responder, and only signed, fresh responses count;
  - CRLs are not checked;
  - otherwise status is reported as unknown, never as "not revoked".
- The free AI model is rate-limited (HTTP 429 seen in testing). The local model is slower (about 15–45 s), and without either the report says "AI unavailable".
- The chain is a local anvil instance. Integrity holds under the contract's rules, but anvil's developer RPCs can rewrite local state. It proves a report has not changed, not that it is true.
- The optional browser companion (`extension/`) checks pages and links when you ask. Its opt-in warning mode looks at the address only, and the warning races the page load, so it is not a guaranteed block.

## Disclosures
- Open-source components and data sources are listed with licences in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
- At runtime the product uses AI models (Gemini Flash Lite; optionally a free OpenRouter model or local Qwen3 4B) for explanations only.
- Development was assisted by AI coding tools.

Licence: Apache License 2.0 for original code in this repository (see `LICENSE` and `NOTICE`); third-party components keep their own licences.
