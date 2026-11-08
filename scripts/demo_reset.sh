#!/usr/bin/env bash
# Fresh, uncluttered History for a demo recording. Nothing is deleted: the current database is MOVED to
# data/backup-<timestamp>/. The chain keeps its earlier registrations (append-only); new reports get new ids.
#   scripts/demo_reset.sh            move DB aside, restart API, re-run documented cases + synthetic campaign
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TS="$(date +%Y%m%d-%H%M%S)"
scripts/api.sh stop || true
mkdir -p "data/backup-$TS"
for f in data/wtd.sqlite3 data/wtd.sqlite3-wal data/wtd.sqlite3-shm; do [ -f "$f" ] && mv "$f" "data/backup-$TS/"; done
echo "previous database moved to data/backup-$TS/"
scripts/api.sh start
backend/.venv/bin/python scripts/run_cases.py
backend/.venv/bin/python scripts/seed_campaign.py
echo "ready: open http://127.0.0.1:8000/#/incidents and generate the campaign brief once before recording"
