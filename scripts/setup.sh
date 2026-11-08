#!/usr/bin/env bash
# One-time setup from a fresh clone. Requires: uv, Node 20+ (tested on 24), Foundry (forge/anvil), curl.
# Optional: Ollama (local AI fallback).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.foundry/bin:$PATH"
mkdir -p data
[ -f .env ] || { cp .env.example .env; echo "created .env from .env.example (add URLHAUS_AUTH_KEY if you have one)"; }

echo "== backend (Python 3.13 via uv)"
(cd backend && uv sync --python 3.13)

echo "== contracts (Foundry)"
if [ ! -d contracts/lib/forge-std ]; then (cd contracts && forge install foundry-rs/forge-std@v1.17.0 --no-git); fi
(cd contracts && forge build)

echo "== verifier and dashboard (npm)"
(cd verifier && npm ci --no-audit --no-fund)
(cd frontend && npm ci --no-audit --no-fund && npm run build)

echo "== intelligence snapshots (fetched, not redistributed)"
curl -sS -m 180 --retry 2 -o data/onecrl.json "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records" \
  && echo "Mozilla OneCRL snapshot saved" || echo "OneCRL download failed (TLS distrust matching will use the Chromium list and curated incidents only)"
echo "CERT Polska list: downloaded in the background on first analysis (the host is slow; ~2.5 MB)."
( curl -sS -m 900 --retry 2 -o data/certpl_domains.tmp https://hole.cert.pl/domains/v2/domains.txt && mv data/certpl_domains.tmp data/certpl_domains.txt ) &

if command -v ollama >/dev/null; then echo "Ollama found. Optional local AI fallback: ollama pull qwen3:4b"; fi
echo
echo "Setup done. Next:"
echo "  scripts/chain.sh start && scripts/deploy.sh   # local chain + registry contract"
echo "  scripts/api.sh start                          # API + dashboard on http://127.0.0.1:8000/"
echo "  cat data/api_token                            # operator token for the dashboard"
