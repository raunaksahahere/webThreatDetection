"""Access mode and public-demo quotas.

Default: every API call except /api/health and /api/quota needs the operator token (X-WTD-Token).

WTD_PUBLIC_DEMO=1 opens the dashboard to anyone (for judging/demos):
- No token needed. The operator token still works and lifts the quotas below.
- Analyses are limited per browser session (X-WTD-Session: a random id the dashboard keeps in sessionStorage)
  and per visitor address per UTC day, because a new tab is a new session. The per-minute rate limit still applies.
- On-chain write actions (register, revise, review) stay open only on the local/embedded demo chain (chain id 31337);
  on any public chain they still need the operator token, since they spend real testnet funds.
Counters live in memory and reset when the server restarts.
"""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone

SESSION_RE = re.compile(r"[A-Za-z0-9-]{16,64}")


def public_demo() -> bool:
    return os.environ.get("WTD_PUBLIC_DEMO", "0").strip() == "1"


def session_limit() -> int:
    return max(1, int(os.environ.get("WTD_PUBLIC_SESSION_LIMIT", "15")))


def daily_limit() -> int:
    return max(1, int(os.environ.get("WTD_PUBLIC_DAILY_LIMIT", "60")))


def local_chain() -> bool:
    """True when the registry deployment is the local/embedded anvil chain (no real funds involved)."""
    from .config import SETTINGS

    try:
        return json.loads(SETTINGS.deployment_file.read_text()).get("chainId") == 31337
    except (OSError, ValueError):
        return False


def session_key(raw: str | None, ip: str) -> str:
    raw = (raw or "").strip()
    return f"s:{raw}" if SESSION_RE.fullmatch(raw) else f"ip:{ip}"


class QuotaExceeded(Exception):
    pass


class Quota:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.sessions: dict[str, int] = {}
        self.daily: dict[tuple[str, str], int] = {}

    @staticmethod
    def _day() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _snapshot(self, sk: str, ip: str) -> dict:
        s_used, d_used = self.sessions.get(sk, 0), self.daily.get((ip, self._day()), 0)
        s_lim, d_lim = session_limit(), daily_limit()
        return {"session": {"used": s_used, "limit": s_lim, "remaining": max(0, s_lim - s_used)},
                "daily": {"used": d_used, "limit": d_lim, "remaining": max(0, d_lim - d_used)},
                "remaining": max(0, min(s_lim - s_used, d_lim - d_used))}

    def snapshot(self, sk: str, ip: str) -> dict:
        with self.lock:
            return self._snapshot(sk, ip)

    def take(self, sk: str, ip: str) -> dict:
        """Reserve one analysis or raise QuotaExceeded. Returns the snapshot after the reservation."""
        with self.lock:
            day = self._day()
            if self.sessions.get(sk, 0) >= session_limit():
                raise QuotaExceeded(f"This public demo allows {session_limit()} analyses per browser session, and this session has used them all. "
                                    "Closing this tab ends the session; the daily limit per visitor still applies.")
            if self.daily.get((ip, day), 0) >= daily_limit():
                raise QuotaExceeded(f"This public demo allows {daily_limit()} analyses per visitor per day (UTC), and that limit is reached. Try again tomorrow.")
            self.sessions[sk] = self.sessions.get(sk, 0) + 1
            self.daily[(ip, day)] = self.daily.get((ip, day), 0) + 1
            if len(self.sessions) > 50_000:  # bound memory under abuse: forget the oldest half
                for k in list(self.sessions)[:25_000]:
                    del self.sessions[k]
            if len(self.daily) > 50_000:
                self.daily = {k: v for k, v in self.daily.items() if k[1] == day}
            return self._snapshot(sk, ip)

    def refund(self, sk: str, ip: str) -> None:
        with self.lock:
            day = self._day()
            if self.sessions.get(sk, 0) > 0:
                self.sessions[sk] -= 1
            if self.daily.get((ip, day), 0) > 0:
                self.daily[(ip, day)] -= 1

    def reset(self) -> None:
        with self.lock:
            self.sessions.clear()
            self.daily.clear()


QUOTA = Quota()
