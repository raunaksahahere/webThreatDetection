"""Threat-report registration and app-side verification (the independent check is verifier/verify.mjs)."""
from __future__ import annotations

import hashlib

from fastapi import HTTPException

from ..models import RegistryRecord, iso
from ..pipeline import STORE
from . import chain
from .canonical import CLASS_CODES, THREAT_REPORT_SCHEMA, commitment, digest, make_envelope, report_id_bytes32

COMMITTED_INDICATOR_TYPES = {"domain", "url", "ip", "brand", "cert_spki", "email", "phone", "upi", "crypto_wallet"}


def build_threat_report(r, submitter: str, revision: int = 0, reason: str | None = None) -> dict:
    a = r.assessment
    tr = {
        "schema": THREAT_REPORT_SCHEMA,
        "report_id": r.id,
        "created_at": r.created_at,
        "kind": r.kind,
        "classification": a.classification,
        "rule_id": a.rule_id,
        # Displays only: URLs/domains are defanged; personal identifiers are masked (raw values never leave the store).
        "indicators": [{"type": i.type, "value": i.display} for i in r.indicators if i.type in COMMITTED_INDICATOR_TYPES][:30],
        "findings": [{"id": f.id, "code": f.code, "severity": f.severity, "strength": f.strength, "title": f.title}
                     for f in r.findings if not f.code.startswith("web.") and f.severity != "info"][:25],
        "evidence_digest": digest(r.model_dump(mode="json", exclude={"registry", "ai"})),
        "summary": " ".join([a.rule_text] + a.rationale[:3])[:1000],
        "submitter": submitter[:60],
    }
    if revision:
        tr["revision"] = revision
        tr["revision_reason"] = (reason or "")[:300]
    return tr


def _report_or_404(rid: str):
    r = STORE.get(rid)
    if not r:
        raise HTTPException(404, "analysis not found")
    if r.status != "complete" or not r.assessment:
        raise HTTPException(409, "analysis is not complete")
    return r


def _record(res: dict, rid_b32: str, com: str) -> RegistryRecord:
    return RegistryRecord(chain_id=res["chain_id"], contract=res["contract"], report_id_hex=rid_b32, commitment=com, revision=res["revision"],
                          tx_hash=res["tx_hash"], block_number=res["block_number"], registered_at=res["registered_at"],
                          canonicalization="wtd.commitment.v1: sha256(RFC8785(envelope))")


def register(rid: str, submitter: str) -> dict:
    r = _report_or_404(rid)
    if STORE.threat_reports(rid):
        raise HTTPException(409, "already registered; publish a revision instead")
    tr = build_threat_report(r, submitter)
    env = make_envelope(tr)
    com = commitment(env)
    rid_b32 = report_id_bytes32(r.id)
    try:
        res = chain.register(rid_b32, com, CLASS_CODES[r.assessment.classification])
    except chain.ChainUnavailable as e:
        raise HTTPException(503, f"blockchain unavailable: {e}")
    rec = _record(res, rid_b32, com)
    STORE.save_threat_report(rid, 0, env, com, rec.model_dump())
    r.registry.append(rec)
    STORE.save(r)
    return {"threat_report": tr, "envelope": env, "commitment": com, "record": rec.model_dump()}


def revise(rid: str, reason: str) -> dict:
    r = _report_or_404(rid)
    prev = STORE.threat_reports(rid)
    if not prev:
        raise HTTPException(409, "not registered yet")
    n = len(prev)
    tr = build_threat_report(r, prev[0]["envelope"]["threat_report"]["submitter"], revision=n, reason=reason)
    env = make_envelope(tr)
    com = commitment(env)
    rid_b32 = report_id_bytes32(r.id)
    try:
        res = chain.revise(rid_b32, n, com, CLASS_CODES[r.assessment.classification])
    except chain.ChainUnavailable as e:
        raise HTTPException(503, f"blockchain unavailable: {e}")
    rec = _record(res, rid_b32, com)
    STORE.save_threat_report(rid, n, env, com, rec.model_dump())
    r.registry.append(rec)
    STORE.save(r)
    return {"threat_report": tr, "envelope": env, "commitment": com, "record": rec.model_dump()}


def latest_envelope(rid: str) -> dict:
    trs = STORE.threat_reports(rid)
    if not trs:
        raise HTTPException(404, "no registered threat report")
    return trs[-1]["envelope"]


def get(rid: str) -> dict:
    trs = STORE.threat_reports(rid)
    if not trs:
        raise HTTPException(404, "no registered threat report")
    try:
        onchain = chain.read(report_id_bytes32(rid))
    except chain.ChainUnavailable as e:
        onchain = {"error": str(e)}
    return {"envelope": trs[-1]["envelope"], "commitment": trs[-1]["commitment"], "records": [t["record"] for t in trs], "onchain": onchain,
            "reviews": STORE.reviews(rid)}


REVIEW_STATUSES = ("Validated", "Disputed", "Retracted")


def review(rid: str, status: str, note: str) -> dict:
    """Record a reviewer decision on-chain (status + SHA-256 of the note); the note text stays off-chain."""
    if status not in REVIEW_STATUSES:
        raise HTTPException(422, f"status must be one of {', '.join(REVIEW_STATUSES)}")
    note = note.strip()
    if status != "Validated" and not note:
        raise HTTPException(422, "a note explaining the dispute or retraction is required")
    if not STORE.threat_reports(rid):
        raise HTTPException(409, "not registered yet")
    note_hash = "0x" + hashlib.sha256(note.encode("utf-8")).hexdigest()
    try:
        res = chain.set_status(report_id_bytes32(rid), status, note_hash)
    except chain.ChainUnavailable as e:
        raise HTTPException(503, f"blockchain unavailable: {e}")
    except Exception as e:  # revert, e.g. self-review or missing reviewer role
        raise HTTPException(409, f"review rejected by the contract: {str(e)[:160]}")
    rec = {"tx_hash": res["tx_hash"], "status": status, "note": note, "note_hash": note_hash, "reviewer": res["from"],
           "block_number": res["block_number"], "chain_id": res["chain_id"]}
    STORE.save_review(rid, rec)
    return rec


def verify(rid: str) -> dict:
    env = latest_envelope(rid)
    recomputed = commitment(env)
    try:
        oc = chain.read(report_id_bytes32(rid))
    except chain.ChainUnavailable as e:
        raise HTTPException(503, f"blockchain unavailable: {e}")
    revs = oc["revisions"]
    matched = next((rv["index"] for rv in revs if rv["commitment"] == recomputed), None)
    latest = revs[-1]["index"] if revs else None
    return {"match": matched is not None and matched == latest, "matched_revision": matched, "latest_revision": latest,
            "recomputed": recomputed, "onchain_latest": revs[-1]["commitment"] if revs else None,
            "status": oc.get("current_status") or (oc["status_history"][-1]["status"] if oc["status_history"] else None), "checked_at": iso(),
            "note": "App-side check. For an independent check run: node verifier/verify.mjs --envelope <downloaded file>"}
