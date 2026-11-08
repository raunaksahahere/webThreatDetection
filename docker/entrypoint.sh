#!/usr/bin/env bash
# Container entrypoint (Render or any Docker host).
#   WTD_CHAIN=embedded (default): start a private anvil chain inside the container and deploy the registry.
#       The chain lives only as long as the container (or the mounted disk at /app/chain-state).
#   WTD_CHAIN=external: use WTD_RPC_URL + WTD_DEPLOYMENT (+ WTD_REPORTER_KEY / WTD_REVIEWER_KEY secrets),
#       e.g. the Sepolia deployment written by scripts/testnet.sh.
set -euo pipefail
cd /app
: "${PORT:=8000}"
mkdir -p data chain-state deployments

if [ "${WTD_CHAIN:-embedded}" = "embedded" ]; then
  scripts/chain.sh start
  scripts/deploy.sh
else
  echo "external chain: ${WTD_RPC_URL:-<WTD_RPC_URL not set>} / ${WTD_DEPLOYMENT:-<WTD_DEPLOYMENT not set>}"
fi

# Threat-list snapshot: the API also refreshes it in the background on first use; start the slow download early.
if [ ! -s data/certpl_domains.txt ]; then
  ( curl -sS -m 900 --retry 2 -o data/certpl_domains.tmp https://hole.cert.pl/domains/v2/domains.txt \
      && mv data/certpl_domains.tmp data/certpl_domains.txt ) >/dev/null 2>&1 &
fi

cd backend
# --proxy-headers: Render terminates TLS and forwards the client address, which the per-client rate limit uses.
exec .venv/bin/uvicorn wtd.api:app --host 0.0.0.0 --port "$PORT" --proxy-headers --forwarded-allow-ips='*' --no-server-header
