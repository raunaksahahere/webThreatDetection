# Third-party notices

Versions as installed on 2026-11-08. Licences are each project's own; this file is a summary, not a substitute for the licence texts shipped with each package.

## Software dependencies

| Component | Version | Licence | Used for |
|---|---|---|---|
| ada-url (Python bindings for the Ada WHATWG URL parser) | 4.0.0 | Apache-2.0 (Ada: Apache-2.0 OR MIT) | Browser-equivalent URL parsing |
| h11 | 0.16.0 | MIT | HTTP/1.1 over the pinned socket |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | X.509 parsing and path verification |
| certifi | 2026.10.23 | MPL-2.0 | Mozilla root store for verification (unmodified) |
| tldextract (with bundled Public Suffix List) | 5.4.0 | BSD-3-Clause; PSL data MPL-2.0 | Registrable-domain extraction, offline |
| dnspython | 2.9.2 | ISC | DNS lookups with timeouts |
| idna | 3.20 | BSD-3-Clause | IDNA decoding for display/homograph checks |
| FastAPI / Starlette | 0.162.2 | MIT | HTTP API |
| uvicorn | 0.54.0 | BSD-3-Clause | ASGI server |
| pydantic | 2.14.3 | MIT | Schemas and validation |
| httpx | 0.28.1 | BSD-3-Clause | Calls to fixed intelligence/AI endpoints |
| rfc8785 (Trail of Bits) | 0.1.4 | Apache-2.0 | JSON canonicalization (RFC 8785) |
| web3.py | 8.0.0 | MIT | Registry transactions and reads |
| Foundry (forge, anvil, cast) | 1.9.0 | MIT OR Apache-2.0 | Contract build/test, local chain |
| forge-std | 1.17.0 | MIT OR Apache-2.0 | Solidity test helpers (installed by setup, not committed) |
| viem | 2.57.8 | MIT | Independent verifier chain reads |
| canonicalize (npm) | 2.1.0 | Apache-2.0 | Independent verifier JSON canonicalization |
| React / React DOM | 19.3.1 | MIT | Dashboard |
| Vite, @vitejs/plugin-react | 8.3.5 / 6.1.2 | MIT | Dashboard build |
| TypeScript | 7.0.2 | Apache-2.0 | Dashboard type checking |
| lucide-react | 1.60.0 | ISC | Icons |
| Fontsource: Archivo, JetBrains Mono, Atkinson Hyperlegible Next | 5.3.0 | SIL Open Font License 1.1 (fonts); MIT (packages) | Dashboard typography |

## Data and intelligence sources

| Source | How it is used | Terms / attribution |
|---|---|---|
| **Chromium SPKI blocklist** (`backend/wtd/data/distrust/chromium_cert_verify_proc_blocklist.inc`, snapshot 2026-11-08) | Committed copy; distrusted keys matched by SPKI SHA-256 | © The Chromium Authors, BSD-style licence (header retained in the file) |
| **eMudhra incident fingerprints** (`curated_incidents.json`) | 8 certificate SHA-256 values | Facts from Mozilla Bugzilla 2083449, cross-checked against the Chromium blocklist |
| **Mozilla OneCRL** | Downloaded at setup into `data/` (gitignored); not redistributed | Mozilla Remote Settings public data. Attributed as "Mozilla OneCRL"; licence for redistribution not verified |
| **CERT Polska Warning List** | Downloaded at runtime into `data/` (gitignored) | "May be used by any user for any purpose, including commercial purposes." Attribution not required; no endorsement by NASK-PIB / CERT Polska is implied |
| **URLhaus** (abuse.ch) | Live API lookups with the operator's own Auth-Key; results cached ≤ 30 min in memory; never stored in the repository | abuse.ch terms of use: not-for-profit use; no copying or derivative datasets; data must not be used to train or validate AI models. Source shown as "URLhaus (abuse.ch)" with a link to each entry |
| **IANA RDAP bootstrap** and registry RDAP servers | Domain registration dates | Public registry data |
| **Unicode** | Confusable mapping is a small hand-written subset inspired by UTS #39 | No Unicode data files are redistributed |

## AI providers
- OpenRouter, free model `xingchen-agi/xing4.0-29b-a4b:free`, called with `data_collection: deny`. Only redacted, structured findings are sent. Subject to OpenRouter's and the model provider's terms.
- Optional local model via Ollama: `qwen3:4b` (Apache-2.0).

## Not used
OpenPhish (personal use only), Google Safe Browsing / Web Risk (key or billing required; non-commercial terms), PhishTank (registration closed), and GPL-licensed tools such as Phishing Catcher. No code was copied from them.
