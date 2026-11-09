"""Persistence: Postgres (Neon) when DATABASE_URL is set, otherwise a local SQLite file (WAL).
Reports are stored as validated JSON. Every statement is written once in the common SQL subset (`?` placeholders,
ON CONFLICT upserts) and the `?` is translated for Postgres."""
from __future__ import annotations

import atexit
import contextlib
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
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
CREATE TABLE IF NOT EXISTS reviews (
  report_id TEXT NOT NULL, tx_hash TEXT NOT NULL, status TEXT NOT NULL, note TEXT NOT NULL, note_hash TEXT NOT NULL,
  reviewer TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (report_id, tx_hash)
);
CREATE TABLE IF NOT EXISTS campaign_briefs (cluster_id TEXT PRIMARY KEY, brief_json TEXT NOT NULL, created_at TEXT NOT NULL);
"""


PG_EXTRA = ["ALTER TABLE analyses ADD COLUMN IF NOT EXISTS seq BIGSERIAL"]  # stable tie-break for same-second reports (SQLite has rowid)


class Store:
    def __init__(self, path: Path, database_url: str | None = None):
        self.pg = bool(database_url)
        if self.pg:
            from psycopg.rows import tuple_row
            from psycopg_pool import ConnectionPool

            # Neon suspends idle compute and its pooler (PgBouncer) drops idle sockets: keep few connections, recycle
            # them quickly, test each one on checkout, and avoid server-side prepared statements (pooler-safe).
            self.lock = contextlib.nullcontext()
            self.pool = ConnectionPool(database_url, min_size=1, max_size=8, max_idle=120, max_lifetime=600, open=False, timeout=30,
                                       check=ConnectionPool.check_connection,
                                       kwargs={"autocommit": True, "prepare_threshold": None, "row_factory": tuple_row, "connect_timeout": 15})
            self.pool.open(wait=True, timeout=60)
            atexit.register(self.pool.close)
            with self.pool.connection() as c:
                for stmt in [x.strip() for x in SCHEMA.split(";") if x.strip()] + PG_EXTRA:
                    c.execute(stmt)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.path = path
            self.lock = threading.Lock()
            self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.executescript(SCHEMA)

    def _run(self, sql: str, params: tuple = (), fetch: str | None = None, many: list[tuple] | None = None):
        """Run one statement (or one statement over many parameter tuples); fetch = 'one' | 'all' | None."""
        if self.pg:
            sql = sql.replace("?", "%s")
            with self.pool.connection() as c:
                cur = c.cursor()
                if many is not None:
                    if many:
                        cur.executemany(sql, many)
                else:
                    cur.execute(sql, params)
                return cur.fetchone() if fetch == "one" else cur.fetchall() if fetch == "all" else None
        if many is not None:
            self.conn.executemany(sql, many)
            return None
        cur = self.conn.execute(sql, params)
        return cur.fetchone() if fetch == "one" else cur.fetchall() if fetch == "all" else None

    def recover_interrupted(self) -> int:
        """Called at startup: analyses that were running when the process stopped are marked interrupted.
        On a shared Postgres only analyses older than 10 minutes count, so a second instance (e.g. a local dev server)
        starting up does not mark another instance's in-flight analyses as interrupted."""
        with self.lock:
            sql = "SELECT id, report_json FROM analyses WHERE status IN ('queued','running')"
            params: tuple = ()
            if self.pg:
                sql += " AND created_at < ?"
                params = (iso(datetime.now(timezone.utc) - timedelta(minutes=10)),)
            rows = self._run(sql, params, "all")
            for rid, js in rows:
                r = Report.model_validate_json(js)
                r.status = "interrupted"
                r.error = "The server stopped before this analysis finished. Submit it again."
                r.completed_at = iso()
                self._save_locked(r)
            return len(rows)

    def _save_locked(self, r: Report) -> None:
        cls = r.assessment.classification if r.assessment else None
        self._run(
            "INSERT INTO analyses(id, kind, status, created_at, completed_at, input_display, classification, report_json) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, completed_at=excluded.completed_at, classification=excluded.classification, report_json=excluded.report_json",
            (r.id, r.kind, r.status, r.created_at, r.completed_at, r.input_display, cls, r.model_dump_json()),
        )

    def save(self, r: Report) -> None:
        with self.lock:
            self._save_locked(r)

    def get(self, rid: str) -> Report | None:
        row = self._run("SELECT report_json FROM analyses WHERE id=?", (rid,), "one")
        return Report.model_validate_json(row[0]) if row else None

    def list(self, limit: int = 50) -> list[dict]:
        tie = "seq" if self.pg else "rowid"
        rows = self._run(
            f"SELECT id, kind, status, created_at, input_display, classification FROM analyses ORDER BY created_at DESC, {tie} DESC LIMIT ?", (limit,), "all"
        )
        return [dict(zip(("id", "kind", "status", "created_at", "input_display", "classification"), r)) for r in rows]

    # --- indicators / correlation
    def add_indicators(self, rid: str, created_at: str, items: list[tuple[str, str, str]], shingles: list[int] | None = None) -> None:
        with self.lock:
            self._run("INSERT INTO indicators(report_id, type, match_key, display, created_at) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING",
                      many=[(rid, t, k, d, created_at) for t, k, d in items])
            if shingles is not None:
                self._run("INSERT INTO message_shingles(report_id, shingles) VALUES (?,?) ON CONFLICT(report_id) DO UPDATE SET shingles=excluded.shingles",
                          (rid, json.dumps(shingles)))

    def matching_indicators(self, rid: str, items: list[tuple[str, str, str]]) -> list[tuple[str, str, str, str]]:
        """Return (other_report_id, type, match_key, display) for indicators shared with other reports."""
        out = []
        for t, k, _ in items:
            out += [(r[0], t, k, r[1]) for r in self._run(
                "SELECT report_id, display FROM indicators WHERE type=? AND match_key=? AND report_id<>?", (t, k, rid), "all")]
        return out

    def all_shingles(self, exclude: str) -> list[tuple[str, list[int]]]:
        return [(r[0], json.loads(r[1])) for r in self._run("SELECT report_id, shingles FROM message_shingles WHERE report_id<>?", (exclude,), "all")]

    def indicator_edges(self) -> list[tuple[str, str, str, str]]:
        return [tuple(r) for r in self._run(
            "SELECT a.report_id, b.report_id, a.type, a.display FROM indicators a JOIN indicators b "
            "ON a.type=b.type AND a.match_key=b.match_key AND a.report_id<b.report_id WHERE a.type IN ('domain','ip','email','phone','upi','crypto_wallet','cert_spki','url')",
            fetch="all")]

    # --- threat reports / registry
    def save_threat_report(self, rid: str, revision: int, envelope: dict, commitment: str, record: dict | None) -> None:
        with self.lock:
            self._run("INSERT INTO threat_reports(report_id, revision, envelope_json, commitment, record_json, created_at) VALUES (?,?,?,?,?,?) "
                      "ON CONFLICT(report_id, revision) DO UPDATE SET envelope_json=excluded.envelope_json, commitment=excluded.commitment, record_json=excluded.record_json, created_at=excluded.created_at",
                      (rid, revision, json.dumps(envelope, ensure_ascii=False), commitment, json.dumps(record) if record else None, iso()))

    def threat_reports(self, rid: str) -> list[dict]:
        rows = self._run("SELECT revision, envelope_json, commitment, record_json FROM threat_reports WHERE report_id=? ORDER BY revision", (rid,), "all")
        return [{"revision": r[0], "envelope": json.loads(r[1]), "commitment": r[2], "record": json.loads(r[3]) if r[3] else None} for r in rows]

    # --- AI campaign briefs (cluster id is a hash of the member report ids, so a changed cluster gets a new id)
    def save_brief(self, cluster_id: str, brief: dict) -> None:
        with self.lock:
            self._run("INSERT INTO campaign_briefs(cluster_id, brief_json, created_at) VALUES (?,?,?) "
                      "ON CONFLICT(cluster_id) DO UPDATE SET brief_json=excluded.brief_json, created_at=excluded.created_at",
                      (cluster_id, json.dumps(brief, ensure_ascii=False), iso()))

    def get_brief(self, cluster_id: str) -> dict | None:
        row = self._run("SELECT brief_json FROM campaign_briefs WHERE cluster_id=?", (cluster_id,), "one")
        return json.loads(row[0]) if row else None

    # --- reviewer decisions: the note text stays off-chain; only its SHA-256 is on-chain
    def save_review(self, rid: str, rec: dict) -> None:
        with self.lock:
            self._run("INSERT INTO reviews(report_id, tx_hash, status, note, note_hash, reviewer, created_at) VALUES (?,?,?,?,?,?,?) "
                      "ON CONFLICT(report_id, tx_hash) DO UPDATE SET status=excluded.status, note=excluded.note, note_hash=excluded.note_hash, reviewer=excluded.reviewer, created_at=excluded.created_at",
                      (rid, rec["tx_hash"], rec["status"], rec["note"], rec["note_hash"], rec["reviewer"], iso()))

    def reviews(self, rid: str) -> list[dict]:
        rows = self._run("SELECT tx_hash, status, note, note_hash, reviewer, created_at FROM reviews WHERE report_id=? ORDER BY created_at", (rid,), "all")
        return [dict(zip(("tx_hash", "status", "note", "note_hash", "reviewer", "created_at"), r)) for r in rows]
