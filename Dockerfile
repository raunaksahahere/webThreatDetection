# WTD API (+ the dashboard on the same origin) for Render or any Docker host.
# Build:  docker build -t wtd .
# Run:    docker run -p 8000:8000 -e WTD_API_TOKEN=change-me wtd     → http://127.0.0.1:8000/
# Pinned to the versions verified locally (Foundry 1.9.0, Node 24, Python 3.13, uv 0.12.21).

# ---- 1. contract build (Foundry) ---------------------------------------------------------------
FROM ghcr.io/foundry-rs/foundry:v1.9.0 AS chain
USER root
WORKDIR /src/contracts
COPY contracts/foundry.toml ./
COPY contracts/src ./src
COPY contracts/script ./script
COPY contracts/test ./test
RUN forge install foundry-rs/forge-std@v1.17.0 --no-git && forge build

# ---- 2. dashboard build (same-origin; the separate Vercel build sets VITE_API_BASE) -------------
FROM node:24-slim AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 3. runtime ---------------------------------------------------------------------------------
FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:0.12.21 /uv /usr/local/bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends curl jq ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 wtd
# anvil/cast/forge for the embedded demo chain and the deploy script
COPY --from=chain /usr/local/bin/anvil /usr/local/bin/cast /usr/local/bin/forge /usr/local/bin/
WORKDIR /app
COPY backend/pyproject.toml backend/uv.lock backend/
RUN cd backend && UV_PROJECT_ENVIRONMENT=/app/backend/.venv uv sync --frozen --no-dev --python /usr/local/bin/python3.13 --no-install-project
COPY backend/wtd backend/wtd
# Install the project itself (editable .pth → /app/backend): the isolated inspector child runs `python -I -m wtd.inspector`, which ignores the cwd.
RUN cd backend && UV_PROJECT_ENVIRONMENT=/app/backend/.venv uv sync --frozen --no-dev --python /usr/local/bin/python3.13
COPY scripts scripts
COPY docker docker
COPY deployments deployments
COPY --from=chain /src/contracts contracts
COPY --from=web /src/frontend/dist frontend/dist
COPY verifier verifier
COPY docs/report.schema.json docs/commitment-vectors.json docs/
# Mozilla OneCRL snapshot (optional; distrust matching still has the Chromium list and curated incidents without it)
RUN mkdir -p data chain-state deployments \
    && (curl -sS -m 120 -o data/onecrl.json "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records" || rm -f data/onecrl.json) \
    && chown -R wtd:wtd /app
USER wtd
ENV PYTHONUNBUFFERED=1 PORT=8000 WTD_AI_LOCAL_MODEL=none
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD curl -fsS "http://127.0.0.1:${PORT}/api/health" || exit 1
ENTRYPOINT ["/app/docker/entrypoint.sh"]
