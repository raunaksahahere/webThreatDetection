# Architecture and security methodology

## 1. Components

```
 Browser (React dashboard, served by the API)
     │  X-WTD-Token, JSON only, fetched content shown as text
     ▼
 FastAPI backend (backend/wtd)
  ├─ pipeline.py ── url_rules ── intel (CERT Polska, URLhaus) ── classify ── correlate ── ai/explain
  │       │                                                                    │
  │       ▼                                                                    ▼
  │  inspector.py  (child process: rlimits, scrubbed env, wall-clock kill)   OpenRouter free model → local Ollama
  │       └─ fetcher.py ── netguard.py (ada-url, IANA blocklist, DNS validation, pinned IP connect)
  │                         └─ Internet (only validated public addresses)
  ├─ store.py (SQLite, WAL)
  └─ registry/ (canonical.py, service.py, chain.py) ──► anvil (chain 31337) ── ThreatReportRegistry.sol
                                                            ▲
 verifier/verify.mjs (Node + viem) — independent: recomputes the commitment and reads contract storage
```

One backend, one datastore, one analysis pipeline, one contract. No queues, vector databases or model training.

## 2. Analysis stages (URL)
1. **Parse and normalise** with ada-url, the WHATWG parser browsers use. Decimal, hex and short IPv4 forms, percent-encoded hosts, `\@` tricks and IDNs resolve to the host a browser would contact.
2. **Static URL indicators** (`checks/url_rules.py`): homographs against a curated brand list, typosquats (Damerau distance on the confusable skeleton), brand-in-domain, brand-in-subdomain, wrong suffix, shorteners, shared hosting, embedded redirects, keywords, IP literals and user-info tricks.
3. **Intelligence first** (`intel.py`): CERT Polska (phishing domains, local copy refreshed in the background) and URLhaus (malware URLs and hosts, live with the operator's key). **An authoritative listing means the site is not visited.**
4. **Isolated inspection** (`inspector.py` → `fetcher.py`): one GET per hop, at most 5 redirects. Each hop is re-parsed, policy-checked and DNS-validated, and the TCP connection goes only to the validated IP while keeping SNI and Host. TLS chains are captured from that same connection. Limits:
   - 25 s total; 5 s connect and 8 s read;
   - 1 MB body; 2 MB decompressed;
   - non-text content is never downloaded.

   HTML is tokenised (never rendered or executed) into features: forms, sensitive fields, external actions, mixed content, script sources, iframes, brand mentions.
5. **TLS trust** (`checks/tls_checks.py`): independent path verification (`cryptography` 50, Mozilla roots via certifi) with isolated diagnostics:
   - expiry, hostname mismatch, untrusted or self-signed chain;
   - weak keys and signatures;
   - over-long lifetime (CA/B Forum SC-081: 200 days after 2026-03-15);
   - embedded SCTs.

   **Distrust matching** checks fingerprints, SPKI hashes and issuer+serial against the Chromium SPKI blocklist, Mozilla OneCRL, the curated eMudhra fingerprints (Bugzilla 2083449), and a labelled synthetic demo list.

   **Revocation (OCSP):** when the leaf lists a responder, the inspector sends an RFC 6960 GET request.
   - The responder URL is attacker-controlled, so the request goes through the same request policy (8 s, 64 KB, one redirect).
   - The response's signature and freshness are verified.
   - Revoked for key/CA compromise is a trust incident; other revocation reasons count as configuration problems.
   - Otherwise status is "unavailable", which is not a risk signal. CRLs are not fetched.
6. **DNS and age** (`checks/dns_checks.py`): NS/MX/SPF/DMARC records, and the RDAP registration date via the IANA bootstrap (`unavailable` where a TLD has no RDAP).
7. **Website security posture** (`checks/web_checks.py`): HSTS, CSP, XCTO, framing, Referrer-Policy, cookie flags, HTTP→HTTPS, mixed content, SRI, version disclosure, directory listing. These are reported with impact and remediation but **excluded from the threat classification**.
8. **Correlation** (`pipeline.correlate`): deterministic shared indicators (domain, URL, IP, leaf key, brand) and, for messages, payment and contact identifiers (stored as keyed HMACs) plus word-shingle similarity. Only campaign-specific links can raise risk: shared certificate keys, payment or contact identifiers, or near-identical text. Re-checks of the same target, CDN IPs and brand names never do.
9. **Classification** (`classify.py`) → **explanation** (`ai/explain.py`) → persisted report.

Messages (`message/analyse.py`) follow the same path:
- indicator extraction: URLs (including defanged), emails, phones, UPI IDs, crypto wallets, amounts, claimed brands;
- social-engineering rules: urgency, threat, reward, job, investment, impersonation, OTP/PIN requests (negations excluded), payment requests, unusual channels, brand-versus-link mismatch;
- static analysis and intel lookups for extracted links (optionally full URL analyses).

## 3. Classification policy (auditable, first match wins)

| Rule | Result | Condition |
|---|---|---|
| R-CONF-1 | Confirmed Malicious | Authoritative intelligence listing with severity ≥ high (CERT Polska domain match; exact fresh URLhaus URL; URLhaus host whose domain Spamhaus DBL/SURBL list as malicious) |
| R-HIGH-1 | High Risk | ≥ 1 strong finding with severity ≥ high, or ≥ 2 independent moderate findings with severity ≥ high |
| R-INC-1 | Inconclusive | No moderate-or-stronger finding and an essential check failed or was unavailable |
| R-SUS-1 | Suspicious | ≥ 1 moderate finding with severity ≥ medium, or ≥ 3 weak findings with severity ≥ low |
| R-LOW-1 | Low Risk | Otherwise, with all essential checks succeeded |

How the rules are applied:
- **Strength scale:** weak (language, keywords, AI observations, missing headers), moderate (structural signals with benign explanations), strong (homograph of a protected brand, credential form posting elsewhere, distrusted CA), authoritative (listing in an authoritative source).
- **Signal grouping:** certificate configuration problems count as one group.
- **What never lowers a result:** a valid certificate, an official-domain match, or a missing intelligence listing. Contradictions are listed in the report.
- **Coverage:** shown as counts, never as a probability.
- **URLhaus host listings:**
  - mass-abused platforms (≥ 1000 URLs, shared hosting, official brand domains, `abused_legit` per DBL) are context only;
  - other hosts with online malware are strong;
  - offline-only history is weak.

## 4. Report and finding schema
`backend/wtd/models.py` is the single source (`docs/report.schema.json` is generated from it).
- **Every finding has:** id, code, module, title, observed fact, structured evidence, source, provenance (`live`, `cached`, `dataset`, `synthetic`, `ai`), timestamp, severity, strength, impact, recommendation and limitation.
- **Checks** are recorded separately with status `succeeded`, `failed`, `unavailable`, `skipped` or `not_implemented`, plus whether they are essential.
- **No floats** appear anywhere, so canonical hashing is identical across languages.

## 5. Security boundaries
| Boundary | Controls |
|---|---|
| Browser → API | Operator token on every non-health route (constant-time compare). Per-client rate limit. Strict pydantic models with size caps (URL 2048, message 20 000). 422 for non-http(s) schemes. |
| API → inspector | Only `{url}` crosses. Child process with RLIMIT_AS 1 GB, CPU 30 s, 64 files, no file writes, no core dumps, empty env (no API keys), new session; 40 s wall-clock kill. Output capped at 4 MB and validated. |
| Inspector → Internet | ada parse → scheme/port/credential/name policy → DNS A/AAAA → **every** address checked against an explicit IANA special-purpose blocklist (IPv4-mapped, NAT64, 6to4 and Teredo embeddings extracted). Any non-public answer blocks the host (anti-rebinding); the socket connects only to the validated address. Each redirect is re-validated; loops are detected. |
| Backend → intelligence | Fixed endpoints only, never user-controlled. Keys from `.env`. A no-hit is "not listed (unknown)". |
| Backend → AI | Structured findings plus redacted untrusted text in a delimited block. Strict JSON schema, no tools, free models only, `data_collection: deny`. Code validates cited IDs, verbatim quotes and classification consistency; contradicting output is `rejected`. |
| Backend → chain | Only report id hash, commitment, revision and classification code. Raw URLs, messages and personal data stay off-chain (verified by scanning block data in testing). |
| UI | No `dangerouslySetInnerHTML`; analysed URLs shown defanged and not clickable; fetched HTML never rendered. |

What we never do: execute page scripts, download payloads, scan ports, enumerate paths, exploit anything, or fetch a destination already listed as malicious.

## 6. Web3 integrity
See `docs/WEB3.md`. Summary:
- Commitment = `SHA-256(RFC 8785(envelope))`, where the envelope holds the threat report and a 32-byte random salt (prevents confirming a guessed report).
- `reportId = SHA-256("wtd.report-id.v1:" + uuid)`.
- The contract enforces reporter/reviewer roles, ordered append-only revisions, status history with no self-review, and unique commitments.
- `verifier/verify.mjs` independently recomputes the commitment and reads contract storage. A tampered envelope fails.
- The chain shows a report has not changed since registration, **not** that it is true. On a local anvil chain the guarantee rests on the contract's rules: developer RPCs can rewrite local state.

## 7. Deployment
Local, reproducible:
- `scripts/setup.sh`
- `scripts/chain.sh start`
- `scripts/deploy.sh`
- `scripts/api.sh start` (dashboard and API on 127.0.0.1:8000)

State lives in `data/` (SQLite, snapshots, token) and `chain-state/` (anvil state, persisted across restarts). For a public deployment, run the backend in a container as a non-root user with egress firewalled to public addresses as a second layer, and use a real secret for `WTD_API_TOKEN`.
