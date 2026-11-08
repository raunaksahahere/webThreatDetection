#!/usr/bin/env bash
# Public testnet (Ethereum Sepolia) deployment of ThreatReportRegistry, so anyone can check registrations on a block
# explorer and run the independent verifier against a chain nobody here controls.
#
#   scripts/testnet.sh keys      create two fresh TESTNET-ONLY keys (reporter/owner, reviewer) in .env.sepolia (mode 600);
#                                prints only the public addresses. Fund the reporter address from a Sepolia faucet.
#   scripts/testnet.sh balance   show both balances
#   scripts/testnet.sh deploy    deploy, grant roles, give the reviewer a little gas, write deployments/sepolia.json
#   WTD_NETWORK=sepolia scripts/api.sh restart    run the API against Sepolia instead of the local chain
#
# Keys never leave this machine, are never printed, and .env.* is gitignored. Use them for test ETH only.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENVF="$ROOT/.env.sepolia"
FOUNDRY_BIN="$(dirname "$(command -v forge || echo "$HOME/.foundry/bin/forge")")"
FORGE="$FOUNDRY_BIN/forge"; CAST="$FOUNDRY_BIN/cast"
RPC_DEFAULT="https://ethereum-sepolia-rpc.publicnode.com"
OUT="$ROOT/deployments/sepolia.json"

load() {
  [[ -f "$ENVF" ]] || { echo "no $ENVF; run: scripts/testnet.sh keys" >&2; exit 1; }
  set -a; source "$ENVF"; set +a
  RPC="${WTD_RPC_URL:-$RPC_DEFAULT}"
  REPORTER="$("$CAST" wallet address --private-key "$WTD_REPORTER_KEY")"
  REVIEWER="$("$CAST" wallet address --private-key "$WTD_REVIEWER_KEY")"
}

case "${1:-}" in
  keys)
    [[ -f "$ENVF" ]] && { echo "$ENVF already exists; refusing to overwrite keys" >&2; exit 1; }
    umask 077
    J="$("$CAST" wallet new --number 2 --json)"
    {
      echo "# Sepolia TESTNET-ONLY keys generated $(date -u +%FT%TZ). Never reuse on mainnet. Never commit."
      echo "WTD_RPC_URL=$RPC_DEFAULT"
      echo "WTD_DEPLOYMENT=$OUT"
      echo "WTD_REPORTER_KEY=$(jq -r '(.data // .)[0].private_key' <<<"$J")"
      echo "WTD_REVIEWER_KEY=$(jq -r '(.data // .)[1].private_key' <<<"$J")"
    } >"$ENVF"
    unset J
    chmod 600 "$ENVF"
    load
    echo "reporter/owner: $REPORTER   <- fund this one (about 0.05 Sepolia ETH is plenty)"
    echo "reviewer:       $REVIEWER   (gets gas from the reporter during deploy)"
    ;;
  balance)
    load
    echo "chain id $("$CAST" chain-id --rpc-url "$RPC")"
    echo "reporter $REPORTER $("$CAST" balance "$REPORTER" --ether --rpc-url "$RPC") ETH"
    echo "reviewer $REVIEWER $("$CAST" balance "$REVIEWER" --ether --rpc-url "$RPC") ETH"
    ;;
  deploy)
    load
    CHAIN_ID="$("$CAST" chain-id --rpc-url "$RPC")"
    [[ "$CHAIN_ID" == "11155111" ]] || { echo "expected Sepolia (11155111), got $CHAIN_ID" >&2; exit 1; }
    cd "$ROOT/contracts"
    REPORTER="$REPORTER" REVIEWER="$REVIEWER" "$FORGE" script script/Deploy.s.sol:Deploy \
      --rpc-url "$RPC" --private-key "$WTD_REPORTER_KEY" --broadcast --slow
    RUN="broadcast/Deploy.s.sol/$CHAIN_ID/run-latest.json"
    ADDRESS="$("$CAST" to-check-sum-address "$(jq -r '.transactions[] | select(.transactionType == "CREATE") | .contractAddress' "$RUN")")"
    TX="$(jq -r '.transactions[] | select(.transactionType == "CREATE") | .hash' "$RUN")"
    BLOCK="$("$CAST" receipt "$TX" blockNumber --rpc-url "$RPC")"
    TS="$("$CAST" block "$BLOCK" --field timestamp --rpc-url "$RPC")"
    [[ "$("$CAST" call "$ADDRESS" 'isReporter(address)(bool)' "$REPORTER" --rpc-url "$RPC")" == "true" ]] || { echo "reporter role missing" >&2; exit 1; }
    [[ "$("$CAST" call "$ADDRESS" 'isReviewer(address)(bool)' "$REVIEWER" --rpc-url "$RPC")" == "true" ]] || { echo "reviewer role missing" >&2; exit 1; }
    "$CAST" send "$REVIEWER" --value 0.003ether --private-key "$WTD_REPORTER_KEY" --rpc-url "$RPC" >/dev/null
    mkdir -p "$(dirname "$OUT")"
    jq -n --argjson chainId "$CHAIN_ID" --arg address "$ADDRESS" --arg deployTx "$TX" --argjson deployBlock "$BLOCK" \
      --arg owner "$REPORTER" --arg reporter "$REPORTER" --arg reviewer "$REVIEWER" \
      --arg deployedAt "$(date -u -d "@$TS" +%Y-%m-%dT%H:%M:%SZ)" --arg explorer "https://sepolia.etherscan.io/address/$ADDRESS" --arg rpc "$RPC" \
      '{chainId: $chainId, network: "sepolia", address: $address, deployTx: $deployTx, deployBlock: $deployBlock,
        owner: $owner, reporter: $reporter, reviewer: $reviewer, deployedAt: $deployedAt, explorer: $explorer, rpc: $rpc}' >"$OUT"
    echo "deployed: $ADDRESS  ($(jq -r .explorer "$OUT"))"
    ;;
  *) sed -n 2,12p "$0"; exit 1;;
esac
