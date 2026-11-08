#!/usr/bin/env bash
# End-to-end demo of the registry + independent verifier on the local anvil chain:
# register vectors[0] -> verify (0) and tampered (1) -> revise with vectors[1] -> verify (2 / 0)
# -> reviewer sets Validated -> restart anvil -> verify again from persisted state.
#
# Needs a chain where the test-vector report is not registered yet (scripts/chain.sh reset gives
# one; that deletes ALL local chain state). Leaves the chain stopped.
#
# SECURITY: the keys below are anvil's well-known default keys for accounts #1 and #2, derived from
# the PUBLIC test mnemonic "test test ... junk". They are only used against chain id 31337.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.foundry/bin:$PATH"
RPC="http://127.0.0.1:8545"
REPORTER_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" # anvil #1, public test key
REVIEWER_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" # anvil #2, public test key
VECTORS="docs/commitment-vectors.json"
RID="$(jq -r .report_id_bytes32 "$VECTORS")"
C0="$(jq -r '.vectors[0].commitment' "$VECTORS")"
C1="$(jq -r '.vectors[1].commitment' "$VECTORS")"
FAILURES=0

step() { printf '\n=== %s\n' "$*"; }
send() { # send <key> <sig> <args...>: prints tx hash, block and status
  local key="$1"; shift
  local out; out="$(cast send --json --rpc-url "$RPC" --private-key "$key" "$ADDR" "$@")" || { echo "cast send failed"; FAILURES=$((FAILURES + 1)); return; }
  echo "tx $(jq -r .transactionHash <<<"$out")  block $(( $(jq -r .blockNumber <<<"$out") ))  status $(jq -r .status <<<"$out")"
}
verify() { # verify <expected exit> <envelope>
  local expected="$1" envelope="$2"
  echo "\$ node verifier/verify.mjs --envelope $envelope"
  node verifier/verify.mjs --envelope "$envelope"
  local code=$?
  echo "exit code: $code (expected $expected)"
  [[ "$code" == "$expected" ]] || FAILURES=$((FAILURES + 1))
}
logs_count() { cast logs --json --rpc-url "$RPC" --from-block 0 --address "$ADDR" 2>/dev/null | jq length; }

step "start chain and deploy"
scripts/chain.sh start || exit 3
scripts/deploy.sh || exit 3
ADDR="$(jq -r .address deployments/local.json)"
[[ "$(cast chain-id --rpc-url "$RPC")" == "31337" ]] || { echo "not chain 31337"; exit 3; }
if [[ "$(cast call --rpc-url "$RPC" "$ADDR" 'revisionCount(bytes32)(uint256)' "$RID")" != "0" ]]; then
  echo "test-vector report is already registered here; run scripts/chain.sh reset (deletes local chain state)"; exit 3
fi

step "register vectors[0] (reportId $RID, commitment $C0, classification 3) from account #1"
send "$REPORTER_KEY" 'register(bytes32,bytes32,uint8)' "$RID" "$C0" 3

step "verify vectors[0] envelope (expect 0) and tampered envelope (expect 1)"
verify 0 verifier/fixtures/vector0.envelope.json
verify 1 verifier/fixtures/tampered.envelope.json

step "revise to vectors[1] (expectedRevision 1, commitment $C1) from account #1"
send "$REPORTER_KEY" 'revise(bytes32,uint256,bytes32,uint8)' "$RID" 1 "$C1" 3

step "verify: vectors[0] is now superseded (expect 2), vectors[1] is latest (expect 0)"
verify 2 verifier/fixtures/vector0.envelope.json
verify 0 verifier/fixtures/vector1.envelope.json

NOTE_HASH="0x$(printf '%s' 'demo review: indicators confirmed' | sha256sum | cut -d' ' -f1)"
step "setStatus(Validated, noteHash $NOTE_HASH) from account #2 (reviewer)"
send "$REVIEWER_KEY" 'setStatus(bytes32,uint8,bytes32)' "$RID" 1 "$NOTE_HASH"
verify 0 verifier/fixtures/vector1.envelope.json

BLOCK_BEFORE="$(cast block-number --rpc-url "$RPC")"
LOGS_BEFORE="$(logs_count)"
DEPLOY_TX="$(jq -r .deployTx deployments/local.json)"
step "restart anvil (state file chain-state/anvil.json)"
echo "before restart: block $BLOCK_BEFORE, contract logs $LOGS_BEFORE"
scripts/chain.sh stop
scripts/chain.sh start || exit 3
echo "after restart:  block $(cast block-number --rpc-url "$RPC"), contract logs $(logs_count)"
echo "deploy tx receipt after restart: $(cast receipt --rpc-url "$RPC" "$DEPLOY_TX" status 2>&1 | head -n 1)"
echo "code at $ADDR after restart: $(cast code --rpc-url "$RPC" "$ADDR" | wc -c) hex chars"
scripts/deploy.sh | head -n 1

step "verify again after restart"
verify 0 verifier/fixtures/vector1.envelope.json
verify 2 verifier/fixtures/vector0.envelope.json
verify 1 verifier/fixtures/tampered.envelope.json

step "stop chain"
scripts/chain.sh stop
echo
if [[ "$FAILURES" == 0 ]]; then echo "E2E: all expectations met"; else echo "E2E: $FAILURES expectation(s) FAILED"; exit 1; fi
