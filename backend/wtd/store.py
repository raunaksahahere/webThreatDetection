"""SQLite persistence (single file, WAL). Reports are stored as validated JSON."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .models import Report, iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
  completed_at TEXT, input_display TEXT NOT NULL, classification TEXT, report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS analyses_created ON analyses(created_at DESC);
CREATE TABLE IF NOT EXISTS indicators (
  report_id TEXT NOT NULL, type TEXT NOT NULL, match_key TEXT NOT NULL, display TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY (report_id, type, match_key)
);
CREATE INDEX IF NOT EXISTS indicators_key ON indicators(type, match_key);
CREATE TABLE IF NOT EXISTS message_shingles (report_id TEXT PRIMARY KEY, shingles TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS threat_reports (
  report_id TEXT NOT NULL, revision INTEGER NOT NULL, envelope_json TEXT NOT NULL, commitment TEXT NOT NULL,
  record_json TEXT, created_at TEXT NOT NULL, PRIMARY KEY (report_id, revision)
);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)

    def recover_interrupted(self) -> int:
        """Called at startup: analyses that were running when the process stopped are marked interrupted."""
        with self.lock:
            rows = self.conn.execute("SELECT id, report_json FROM analyses WHERE status IN ('queued','running')").fetchall()
            for rid, js in rows:
                r = Report.model_validate_json(js)
                r.status = "interrupted"
                r.error = "The server stopped before this analysis finished. Submit it again."
                r.completed_at = iso()
                self._save_locked(r)
            return len(rows)

    def _save_locked(self, r: Report) -> None:
        cls = r.assessment.classification if r.assessment else None
        self.conn.execute(
            "INSERT INTO analyses(id, kind, status, created_at, completed_at, input_display, classification, report_json) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, completed_at=excluded.completed_at, classification=excluded.classification, report_json=excluded.report_json",
            (r.id, r.kind, r.status, r.created_at, r.completed_at, r.input_display, cls, r.model_dump_json()),
        )

    def save(self, r: Report) -> None:
        with self.lock:
            self._save_locked(r)

    def get(self, rid: str) -> Report | None:
        row = self.conn.execute("SELECT report_json FROM analyses WHERE id=?", (rid,)).fetchone()
        return Report.model_validate_json(row[0]) if row else None

    def list(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, kind, status, created_at, input_display, classification FROM analyses ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(zip(("id", "kind", "status", "created_at", "input_display", "classification"), r)) for r in rows]

    # --- indicators / correlation
    def add_indicators(self, rid: str, created_at: str, items: list[tuple[str, str, str]], shingles: list[int] | None = None) -> None:
        with self.lock:
            self.conn.executemany("INSERT OR IGNORE INTO indicators(report_id, type, match_key, display, created_at) VALUES (?,?,?,?,?)",
                                  [(rid, t, k, d, created_at) for t, k, d in items])
            if shingles is not None:
                self.conn.execute("INSERT OR REPLACE INTO message_shingles(report_id, shingles) VALUES (?,?)", (rid, json.dumps(shingles)))

    def matching_indicators(self, rid: str, items: list[tuple[str, str, str]]) -> list[tuple[str, str, str, str]]:
        """Return (other_report_id, type, match_key, display) for indicators shared with other reports."""
        out = []
        for t, k, _ in items:
            out += [(r[0], t, k, r[1]) for r in self.conn.execute(
                "SELECT report_id, display FROM indicators WHERE type=? AND match_key=? AND report_id<>?", (t, k, rid)).fetchall()]
        return out

    def all_shingles(self, exclude: str) -> list[tuple[str, list[int]]]:
        return [(r[0], json.loads(r[1])) for r in self.conn.execute("SELECT report_id, shingles FROM message_shingles WHERE report_id<>?", (exclude,))]

    def indicator_edges(self) -> list[tuple[str, str, str, str]]:
        return self.conn.execute(
            "SELECT a.report_id, b.report_id, a.type, a.display FROM indicators a JOIN indicators b "
            "ON a.type=b.type AND a.match_key=b.match_key AND a.report_id<b.report_id WHERE a.type IN ('domain','ip','email','phone','upi','crypto_wallet','cert_spki','url')"
        ).fetchall()

    # --- threat reports / registry
    def save_threat_report(self, rid: str, revision: int, envelope: dict, commitment: str, record: dict | None) -> None:
        with self.lock:
            self.conn.execute("INSERT OR REPLACE INTO threat_reports(report_id, revision, envelope_json, commitment, record_json, created_at) VALUES (?,?,?,?,?,?)",
                              (rid, revision, json.dumps(envelope, ensure_ascii=False), commitment, json.dumps(record) if record else None, iso()))

    def threat_reports(self, rid: str) -> list[dict]:
        rows = self.conn.execute("SELECT revision, envelope_json, commitment, record_json FROM threat_reports WHERE report_id=? ORDER BY revision", (rid,)).fetchall()
        return [{"revision": r[0], "envelope": json.loads(r[1]), "commitment": r[2], "record": json.loads(r[3]) if r[3] else None} for r in rows]
