"""Versioned canonicalization and commitment (wtd.commitment.v1). See docs/INTERFACES.md §3."""
from __future__ import annotations

import hashlib
import secrets
from typing import Any

import rfc8785

COMMITMENT_SCHEMA = "wtd.commitment.v1"
THREAT_REPORT_SCHEMA = "wtd.threat-report.v1"
REPORT_ID_PREFIX = "wtd.report-id.v1:"
CLASS_CODES = {"Inconclusive": 0, "Low Risk": 1, "Suspicious": 2, "High Risk": 3, "Confirmed Malicious": 4}


def _no_floats(obj: Any, path: str = "$") -> None:
    if isinstance(obj, float):
        raise ValueError(f"floats are not allowed in committed documents ({path})")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _no_floats(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _no_floats(v, f"{path}[{i}]")


def canonical_bytes(obj: Any) -> bytes:
    _no_floats(obj)
    return rfc8785.dumps(obj)


def make_envelope(threat_report: dict, salt_hex: str | None = None) -> dict:
    salt = salt_hex or secrets.token_hex(32)
    if len(salt) != 64 or any(c not in "0123456789abcdef" for c in salt):
        raise ValueError("salt must be 64 lowercase hex characters")
    return {"schema": COMMITMENT_SCHEMA, "salt": salt, "threat_report": threat_report}


def commitment(envelope: dict) -> str:
    if envelope.get("schema") != COMMITMENT_SCHEMA:
        raise ValueError("unsupported commitment schema")
    return "0x" + hashlib.sha256(canonical_bytes(envelope)).hexdigest()


def report_id_bytes32(report_id: str) -> str:
    return "0x" + hashlib.sha256((REPORT_ID_PREFIX + report_id).encode("utf-8")).hexdigest()


def digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()
