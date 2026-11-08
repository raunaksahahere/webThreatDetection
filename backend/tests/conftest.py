"""Test configuration: isolated database, AI disabled by default, fixed operator token."""
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="wtd-test-")
os.environ["WTD_DB"] = os.path.join(_tmp, "test.sqlite3")
os.environ["WTD_AI_ENABLED"] = "0"
os.environ["WTD_API_TOKEN"] = "test-token"
os.environ["WTD_RATE_PER_MIN"] = "1000"
os.environ.pop("URLHAUS_AUTH_KEY", None)
# Pinned (not just removed) so values in a developer's local .env cannot leak in: config loads .env only for unset keys.
os.environ["WTD_PUBLIC_DEMO"] = "0"
os.environ["GEMINI_API_KEY"] = ""
os.environ["WTD_AI_PROVIDERS"] = "gemini,openrouter,local"
os.environ.pop("WTD_GEMINI_MODELS", None)
