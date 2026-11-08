"""Configuration from environment and the project .env file (never logged)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def _secret_file(name: str, nbytes: int = 32) -> str:
    DATA.mkdir(parents=True, exist_ok=True)
    p = DATA / name
    if not p.exists():
        p.write_text(secrets.token_hex(nbytes))
        p.chmod(0o600)
    return p.read_text().strip()


@dataclass(frozen=True)
class Settings:
    api_token: str
    hmac_key: bytes
    db_path: Path
    ai_enabled: bool
    ai_model: str
    ai_local_model: str
    ai_timeout_s: int
    rpc_url: str
    deployment_file: Path
    reporter_key: str | None
    max_analyses_per_minute: int


def load() -> Settings:
    if os.environ.get("WTD_NETWORK"):  # e.g. WTD_NETWORK=sepolia loads .env.sepolia (keys, RPC, deployment) first
        _load_dotenv(ROOT / f".env.{os.environ['WTD_NETWORK']}")
    _load_dotenv(ROOT / ".env")
    token = os.environ.get("WTD_API_TOKEN") or _secret_file("api_token", 24)
    return Settings(
        api_token=token,
        hmac_key=bytes.fromhex(_secret_file("indicator_hmac.key")),
        db_path=Path(os.environ.get("WTD_DB", DATA / "wtd.sqlite3")),
        ai_enabled=os.environ.get("WTD_AI_ENABLED", "1") != "0",
        ai_model=os.environ.get("WTD_AI_MODEL", "xingchen-agi/xing4.0-29b-a4b:free"),
        ai_local_model=os.environ.get("WTD_AI_LOCAL_MODEL", "qwen3:4b"),
        ai_timeout_s=int(os.environ.get("WTD_AI_TIMEOUT", "45")),
        rpc_url=os.environ.get("WTD_RPC_URL", "http://127.0.0.1:8545"),
        deployment_file=Path(os.environ.get("WTD_DEPLOYMENT", ROOT / "deployments" / "local.json")),
        reporter_key=os.environ.get("WTD_REPORTER_KEY"),
        max_analyses_per_minute=int(os.environ.get("WTD_RATE_PER_MIN", "12")),
    )


SETTINGS = load()
