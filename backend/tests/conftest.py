"""Test configuration: isolated database, AI disabled by default, fixed operator token."""
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="wtd-test-")
# Tests use a throwaway SQLite file, never a developer's Neon database. WTD_TEST_DATABASE_URL opts in to running them on a disposable Postgres.
os.environ["DATABASE_URL"] = os.environ.get("WTD_TEST_DATABASE_URL", "")
os.environ["WTD_DB"] = os.path.join(_tmp, "test.sqlite3")
os.environ["WTD_AI_ENABLED"] = "0"
os.environ["WTD_API_TOKEN"] = "test-token"
os.environ["WTD_RATE_PER_MIN"] = "1000"
os.environ["URLHAUS_AUTH_KEY"] = ""  # pinned, not just removed: config loads .env for unset names, which would bring a real key back
# Pinned (not just removed) so values in a developer's local .env cannot leak in: config loads .env only for unset keys.
os.environ["WTD_PUBLIC_DEMO"] = "0"
os.environ["GEMINI_API_KEY"] = ""
os.environ["WTD_AI_PROVIDERS"] = "gemini,openrouter,local"
os.environ.pop("WTD_GEMINI_MODELS", None)
# No test may reach a third-party service by accident: CT lookups and the extra intelligence sources are off unless a test enables them.
os.environ["WTD_CT"] = "0"
os.environ["GSB_API_KEY"] = ""
os.environ["WTD_OPENPHISH"] = "0"
