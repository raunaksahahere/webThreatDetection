#!/usr/bin/env bash
# Start/stop the WTD API (serves the dashboard too). Usage: scripts/api.sh start|stop|restart|status
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PID="$ROOT/data/api.pid"; LOG="$ROOT/data/api.log"
mkdir -p "$ROOT/data"
start() {
  if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then echo "api already running (pid $(cat "$PID"))"; return; fi
  cd "$ROOT/backend"
  nohup .venv/bin/uvicorn wtd.api:app --host 127.0.0.1 --port "${WTD_PORT:-8000}" >"$LOG" 2>&1 &
  echo $! >"$PID"
  for _ in $(seq 1 30); do curl -s -m 1 -o /dev/null "http://127.0.0.1:${WTD_PORT:-8000}/api/health" && { echo "api running: http://127.0.0.1:${WTD_PORT:-8000}/ (pid $(cat "$PID"))"; return; }; sleep 0.5; done
  echo "api did not become ready; see $LOG"; exit 1
}
stop() {
  if [ -f "$PID" ]; then
    local p; p="$(cat "$PID")"
    kill "$p" 2>/dev/null || true
    for _ in $(seq 1 40); do kill -0 "$p" 2>/dev/null || break; sleep 0.25; done  # wait so a restart never probes the old server
    rm -f "$PID"; echo "api stopped"
  fi
}
case "${1:-start}" in start) start;; stop) stop;; restart) stop; sleep 1; start;; status) [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null && echo running || echo stopped;; esac
