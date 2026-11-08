#!/usr/bin/env bash
# Deploy ThreatReportRegistry to the local anvil chain and write deployments/local.json.
#
#   scripts/deploy.sh            deploy unless deployments/local.json already points at live code
#   FORCE=1 scripts/deploy.sh    always deploy a fresh contract
#
# Roles: anvil account #0 = owner/deployer, #1 = reporter (backend signer), #2 = reviewer.
#
# SECURITY: the key below is anvil's well-known default key for account #0, derived from the
# PUBLIC test mnemonic "test test test test test test test test test test test junk". Anyone can
# use it. It is only acceptable on a local dev chain, so this script refuses any chain id but 31337.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RPC="${RPC_URL:-http://127.0.0.1:8545}"
OUT="$ROOT/deployments/local.json"
FOUNDRY_BIN="$(dirname "$(command -v forge || echo "$HOME/.foundry/bin/forge")")"
FORGE="$FOUNDRY_BIN/forge"
CAST="$FOUNDRY_BIN/cast"

DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" # anvil #0, public test key
OWNER="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"    # anvil #0
REPORTER="0x70997970C51812dc3A010C7d01b50e0d17dc79C8" # anvil #1
REVIEWER="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC" # anvil #2

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
CHAIN_ID="$("$CAST" chain-id --rpc-url "$RPC" 2>/dev/null)" ||
  { echo "no chain at $RPC (run scripts/chain.sh start)" >&2; exit 1; }
[[ "$CHAIN_ID" == "31337" ]] ||
  { echo "refusing to deploy with public anvil keys to chain id $CHAIN_ID (only 31337)" >&2; exit 1; }

if [[ -f "$OUT" && "${FORCE:-0}" != "1" ]]; then
  addr="$(jq -r .address "$OUT")"
  code="$("$CAST" code "$addr" --rpc-url "$RPC" 2>/dev/null || echo 0x)"
  if [[ "$(jq -r .chainId "$OUT")" == "$CHAIN_ID" && "$code" != "0x" ]]; then
    echo "already deployed: $addr has code on chain $CHAIN_ID; skipping (FORCE=1 to redeploy)"
    cat "$OUT"; exit 0
  fi
  echo "deployments/local.json points to $addr but there is no code there (chain reset?); redeploying"
fi

cd "$ROOT/contracts"
REPORTER="$REPORTER" REVIEWER="$REVIEWER" "$FORGE" script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast
RUN="broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json"
ADDRESS="$("$CAST" to-check-sum-address "$(jq -r '.transactions[] | select(.transactionType == "CREATE") | .contractAddress' "$RUN")")"
TX="$(jq -r '.transactions[] | select(.transactionType == "CREATE") | .hash' "$RUN")"
BLOCK="$("$CAST" receipt "$TX" blockNumber --rpc-url "$RPC")"
TS="$("$CAST" block "$BLOCK" --field timestamp --rpc-url "$RPC")"

# Sanity-check the deployment before recording it.
[[ "$("$CAST" call "$ADDRESS" 'owner()(address)' --rpc-url "$RPC")" == "$OWNER" ]] || { echo "owner mismatch" >&2; exit 1; }
[[ "$("$CAST" call "$ADDRESS" 'isReporter(address)(bool)' "$REPORTER" --rpc-url "$RPC")" == "true" ]] || { echo "reporter role missing" >&2; exit 1; }
[[ "$("$CAST" call "$ADDRESS" 'isReviewer(address)(bool)' "$REVIEWER" --rpc-url "$RPC")" == "true" ]] || { echo "reviewer role missing" >&2; exit 1; }

mkdir -p "$(dirname "$OUT")"
jq -n --argjson chainId "$CHAIN_ID" --arg address "$ADDRESS" --arg deployTx "$TX" \
  --argjson deployBlock "$BLOCK" --arg owner "$OWNER" --arg reporter "$REPORTER" --arg reviewer "$REVIEWER" \
  --arg deployedAt "$(date -u -d "@$TS" +%Y-%m-%dT%H:%M:%SZ)" \
  '{chainId: $chainId, address: $address, deployTx: $deployTx, deployBlock: $deployBlock,
    owner: $owner, reporter: $reporter, reviewer: $reviewer, deployedAt: $deployedAt}' >"$OUT"
echo "deployed ThreatReportRegistry; wrote $OUT"
cat "$OUT"
