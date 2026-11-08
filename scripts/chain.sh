#!/usr/bin/env bash
# Local development chain for the ThreatReportRegistry (anvil, chain id 31337).
#
#   scripts/chain.sh start    start anvil in the background (idempotent), wait until RPC answers
#   scripts/chain.sh run      run anvil in the foreground (Ctrl-C dumps state and exits)
#   scripts/chain.sh stop     stop the background anvil and wait for it to write its state
#   scripts/chain.sh status   show whether the chain is up
#   scripts/chain.sh reset    stop, then delete the persisted state (next start = fresh chain)
#
# State is persisted to chain-state/anvil.json (on exit and every 10 s). The chain uses
# anvil's default accounts derived from the PUBLIC test mnemonic; it is for local use only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="$ROOT/chain-state"
STATE_FILE="$STATE_DIR/anvil.json"
PID_FILE="$STATE_DIR/anvil.pid"
LOG_FILE="$STATE_DIR/anvil.log"
HOST="127.0.0.1"
PORT="8545"
RPC="http://$HOST:$PORT"
ANVIL="$(command -v anvil || echo "$HOME/.foundry/bin/anvil")"
ANVIL_ARGS=(--chain-id 31337 --state "$STATE_FILE" --state-interval 10 --host "$HOST" --port "$PORT")

rpc() { # rpc <method> -> prints the JSON-RPC result string, fails if the node does not answer
  curl -sf -m 2 -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}" "$RPC" |
    sed -n 's/.*"result":"\([^"]*\)".*/\1/p' | grep .
}

pid_alive() { # true if the pid file names a live anvil process
  [[ -f "$PID_FILE" ]] || return 1
  local pid; pid="$(cat "$PID_FILE")"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && grep -qa anvil "/proc/$pid/cmdline" 2>/dev/null
}

summary() { echo "anvil pid $(cat "$PID_FILE") | rpc $RPC | chain id $(( $(rpc eth_chainId) )) | block $(( $(rpc eth_blockNumber) ))"; }

start() {
  [[ -x "$ANVIL" ]] || { echo "anvil not found (install Foundry or add ~/.foundry/bin to PATH)" >&2; exit 1; }
  if pid_alive && rpc eth_chainId >/dev/null; then echo "already running: $(summary)"; return 0; fi
  if rpc eth_chainId >/dev/null; then
    echo "port $PORT already serves an RPC that this script did not start; stop it first" >&2; exit 1
  fi
  mkdir -p "$STATE_DIR"
  # setsid detaches anvil from this shell's session so it survives the caller exiting.
  setsid bash -c 'echo $$ > "$0"; exec "$@"' "$PID_FILE" "$ANVIL" "${ANVIL_ARGS[@]}" \
    >"$LOG_FILE" 2>&1 </dev/null &
  for _ in $(seq 1 60); do
    if rpc eth_chainId >/dev/null && pid_alive; then echo "started: $(summary)"; echo "log: $LOG_FILE"; return 0; fi
    sleep 0.25
  done
  echo "anvil did not come up; last log lines:" >&2; tail -n 20 "$LOG_FILE" >&2 || true; exit 1
}

stop() {
  if ! pid_alive; then rm -f "$PID_FILE"; echo "not running"; return 0; fi
  local pid; pid="$(cat "$PID_FILE")"
  kill -INT "$pid" # SIGINT = Ctrl-C: anvil dumps --state before exiting
  for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
  if kill -0 "$pid" 2>/dev/null; then echo "anvil still alive after SIGINT; sending SIGTERM" >&2; kill -TERM "$pid"; sleep 1; fi
  rm -f "$PID_FILE"
  echo "stopped (pid $pid); state: $STATE_FILE ($(stat -c %s "$STATE_FILE" 2>/dev/null || echo 0) bytes)"
}

case "${1:-start}" in
  start) start ;;
  run)
    mkdir -p "$STATE_DIR"; echo $$ >"$PID_FILE"
    exec "$ANVIL" "${ANVIL_ARGS[@]}" ;;
  stop) stop ;;
  status) if pid_alive && rpc eth_chainId >/dev/null; then echo "running: $(summary)"; else echo "not running"; exit 1; fi ;;
  reset) stop; rm -f "$STATE_FILE"; echo "state deleted; scripts/deploy.sh will redeploy after the next start" ;;
  *) echo "usage: $0 [start|run|stop|status|reset]" >&2; exit 64 ;;
esac
