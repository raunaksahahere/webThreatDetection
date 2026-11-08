"""HTTP API (see docs/INTERFACES.md §2). Serves the built dashboard from frontend/dist."""
from __future__ import annotations

import hmac
import logging
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import intel, pipeline
from .config import ROOT, SETTINGS
from .models import iso
from .netguard import UrlRejected, defang, parse_url

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("wtd.api")
app = FastAPI(title="WTD — Web Threat Detection & Digital Trust Intelligence", version="0.1.0", docs_url="/api/docs", redoc_url=None)
_hits: dict[str, deque] = defaultdict(deque)


@app.on_event("startup")
def _startup() -> None:
    n = pipeline.STORE.recover_interrupted()
    if n:
        log.info("marked %d unfinished analyses as interrupted", n)
    intel.CERTPL.load_local()
    log.info("API token file: data/api_token (or WTD_API_TOKEN). Dashboard: http://127.0.0.1:8000/")


def require_token(request: Request) -> None:
    tok = request.headers.get("x-wtd-token", "")
    if not hmac.compare_digest(tok.encode(), SETTINGS.api_token.encode()):
        raise HTTPException(401, "missing or invalid X-WTD-Token")


def rate_limit(request: Request) -> None:
    key = request.client.host if request.client else "unknown"
    q = _hits[key]
    now = time.monotonic()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= SETTINGS.max_analyses_per_minute:
        raise HTTPException(429, "rate limit: too many analyses per minute")
    q.append(now)


class UrlSubmission(BaseModel):
    kind: Literal["url"]
    url: str = Field(min_length=1, max_length=2048)


class MessageSubmission(BaseModel):
    kind: Literal["message"]
    text: str = Field(min_length=1, max_length=150_000)  # raw e-mail source can be large; only redacted excerpts are stored
    investigate_links: bool = True


class QuickCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class ThreatReportRequest(BaseModel):
    submitter: str = Field(default="wtd-operator", max_length=60)


class ReviseRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=300)


@app.get("/api/health")
def health() -> dict:
    from .registry import chain

    return {"ok": True, "version": app.version, "chain": chain.status(),
            "ai": {"provider": "openrouter (free model)" if SETTINGS.ai_enabled else "disabled", "model": SETTINGS.ai_model,
                   "status": "configured" if SETTINGS.ai_enabled else "disabled"},
            "intel": {"urlhaus": "configured" if intel.urlhaus_key() else "not configured",
                      "certpl": f"{len(intel.CERTPL.domains)} domains" if intel.CERTPL.domains else "not loaded"}}


@app.post("/api/analyses", status_code=202, dependencies=[Depends(require_token), Depends(rate_limit)])
def submit(body: UrlSubmission | MessageSubmission) -> dict:
    try:
        if body.kind == "url":
            r = pipeline.submit_url(body.url)
        else:
            from .message import analyse as msg

            r = msg.submit_message(body.text, body.investigate_links)
    except UrlRejected as e:
        raise HTTPException(422, str(e))
    return {"id": r.id, "status": r.status}


_quick_hits: dict[str, list[float]] = {}
_quick_cache: dict[str, tuple[float, dict]] = {}


@app.post("/api/quick-check", dependencies=[Depends(require_token)])
def quick_check(body: QuickCheckRequest, request: Request) -> dict:
    """Fast address-only verdict for the browser companion's opt-in real-time mode.

    URL rules + the local CERT Polska snapshot only: no page fetch, no DNS, and no third-party lookup, so browsing
    history never leaves this machine. Results are cached for 10 minutes; nothing is stored in the database."""
    import time as _t

    from .checks import url_rules
    from .classify import classify
    from .models import CheckResult as _CR

    now = _t.monotonic()
    key = request.client.host if request.client else "unknown"
    hits = [t for t in _quick_hits.get(key, []) if now - t < 60]
    if len(hits) >= 300:
        raise HTTPException(429, "quick-check rate limit")
    _quick_hits[key] = hits + [now]
    try:
        p = parse_url(body.url)
    except UrlRejected as e:
        raise HTTPException(422, str(e))
    cached = _quick_cache.get(p.href)
    if cached and now - cached[0] < 600:
        return {**cached[1], "cached": True}
    fs, _ = url_rules.analyse_url(p)
    io = intel.lookup(p.href, [p.host], set(url_rules.brand_data()["shared_hosting"]), remote=False)
    checks = [_CR(name="url.rules", module="url", status="succeeded", essential=True)] + io.checks
    a = classify(fs + io.findings, checks)
    res = {"url": defang(p.href), "classification": a.classification, "rule_id": a.rule_id, "rule_text": a.rule_text,
           "findings": [{"code": f.code, "title": f.title, "severity": f.severity, "strength": f.strength}
                        for f in fs + io.findings if f.severity != "info"][:6],
           "scope": "Address and local threat-list check only; the page was not fetched and nothing was sent to third parties.",
           "checked_at": iso(), "cached": False}
    _quick_cache[p.href] = (now, res)
    if len(_quick_cache) > 5000:
        _quick_cache.clear()
    return res


@app.get("/api/analyses", dependencies=[Depends(require_token)])
def list_analyses(limit: int = 50) -> list[dict]:
    return pipeline.STORE.list(min(max(limit, 1), 200))


@app.get("/api/analyses/{rid}", dependencies=[Depends(require_token)])
def get_analysis(rid: str) -> JSONResponse:
    r = pipeline.STORE.get(rid)
    if not r:
        raise HTTPException(404, "analysis not found")
    return JSONResponse(r.model_dump(mode="json"))


@app.post("/api/analyses/{rid}/threat-report", dependencies=[Depends(require_token)])
def register(rid: str, body: ThreatReportRequest) -> dict:
    from .registry import service

    return service.register(rid, body.submitter)


@app.post("/api/analyses/{rid}/threat-report/revise", dependencies=[Depends(require_token)])
def revise(rid: str, body: ReviseRequest) -> dict:
    from .registry import service

    return service.revise(rid, body.reason)


class ReviewRequest(BaseModel):
    status: str = Field(pattern="^(Validated|Disputed|Retracted)$")
    note: str = Field(default="", max_length=500)


@app.post("/api/analyses/{rid}/threat-report/review", dependencies=[Depends(require_token)])
def review(rid: str, body: ReviewRequest) -> dict:
    """Independent reviewer decision, signed by the reviewer account (contract forbids reviewing your own report)."""
    from .registry import service

    return service.review(rid, body.status, body.note)


@app.get("/api/analyses/{rid}/threat-report", dependencies=[Depends(require_token)])
def get_threat_report(rid: str) -> dict:
    from .registry import service

    return service.get(rid)


@app.get("/api/analyses/{rid}/threat-report/download", dependencies=[Depends(require_token)])
def download(rid: str) -> JSONResponse:
    from .registry import service

    env = service.latest_envelope(rid)
    return JSONResponse(env, headers={"Content-Disposition": f'attachment; filename="wtd-threat-report-{rid[:8]}.json"'})


@app.get("/api/analyses/{rid}/verify", dependencies=[Depends(require_token)])
def verify(rid: str) -> dict:
    from .registry import service

    return service.verify(rid)


@app.get("/api/incidents", dependencies=[Depends(require_token)])
def incidents_list() -> list[dict]:
    from . import incidents

    out = incidents.clusters()
    for c in out:
        c["has_brief"] = pipeline.STORE.get_brief(c["cluster_id"]) is not None
    return out


@app.get("/api/incidents/{cid}/brief", dependencies=[Depends(require_token)])
def incident_brief(cid: str) -> dict:
    b = pipeline.STORE.get_brief(cid)
    if not b:
        raise HTTPException(404, "no brief for this cluster yet")
    return b


@app.post("/api/incidents/{cid}/brief", dependencies=[Depends(require_token), Depends(rate_limit)])
def incident_brief_create(cid: str) -> dict:
    """Generate (or regenerate) the AI campaign brief for a cluster. Synchronous: free/local models take 10-60 s."""
    from . import incidents
    from .ai import campaign

    c = incidents.get(cid)
    if not c:
        raise HTTPException(404, "unknown cluster (clusters change as reports are added)")
    b = campaign.brief(c)
    if b["status"] in ("ok", "rejected"):
        pipeline.STORE.save_brief(cid, b)
    return b


DIST = ROOT / "frontend" / "dist"
if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        f = (DIST / path).resolve()
        if path and f.is_file() and DIST.resolve() in f.parents:
            return FileResponse(f)
        return FileResponse(DIST / "index.html")
