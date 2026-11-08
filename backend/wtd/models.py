"""Single source of truth for report, finding, and check schemas.

Every module (checks, AI, persistence, API, UI types, registry) uses these models.
Rules:
- No floats anywhere in persisted or committed documents (JSON canonicalization
  of floats differs between implementations). Use ints (ms, bytes, counts) and strings.
- Every important finding carries: id, observed fact, source, timestamp, severity,
  evidence strength, impact, recommendation, limitation, provenance.
- Check outcomes are tracked separately from findings: succeeded / failed /
  unavailable / skipped / not_implemented. Missing evidence is never a clean result.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "wtd.report.v1"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Strength(str, Enum):
    """How much a finding can carry the classification on its own.

    weak: language or heuristic signal (urgency, keyword, missing header).
    moderate: structural signal with a plausible benign explanation (new domain, lookalike).
    strong: specific, hard-to-explain signal (homograph of a protected brand, credential form
            posting to a third party, chain to a distrusted CA).
    authoritative: listing in an authoritative intelligence source with an exact match.
    """

    weak = "weak"
    moderate = "moderate"
    strong = "strong"
    authoritative = "authoritative"


class Provenance(str, Enum):
    live = "live"  # observed during this analysis
    cached = "cached"  # reused from a previous lookup (see evidence.cached_at)
    dataset = "dataset"  # matched against a documented local dataset snapshot
    synthetic = "synthetic"  # deliberately constructed demo/test fixture
    ai = "ai"  # produced by a language model and validated against the input


class Module(str, Enum):
    url = "url"
    dns = "dns"
    intel = "intel"
    tls = "tls"
    web = "web"
    content = "content"
    message = "message"
    correlation = "correlation"
    ai = "ai"


class CheckStatus(str, Enum):
    succeeded = "succeeded"
    failed = "failed"  # attempted, errored (timeout, refused, parse error)
    unavailable = "unavailable"  # dependency not configured or provider down
    skipped = "skipped"  # not applicable or blocked by policy (e.g. SSRF guard)
    not_implemented = "not_implemented"


class Classification(str, Enum):
    low = "Low Risk"
    suspicious = "Suspicious"
    high = "High Risk"
    confirmed = "Confirmed Malicious"
    inconclusive = "Inconclusive"


EvidenceValue = str | int | bool | None | list[str] | list[int] | list[dict[str, Any]] | dict[str, Any]


class Finding(StrictModel):
    id: str = Field(description="Unique within the report, e.g. 'url.homograph' or 'tls.expired#2'")
    code: str = Field(description="Stable rule code, e.g. 'url.homograph'")
    module: Module
    title: str
    observed: str = Field(description="The observed fact in plain language")
    evidence: dict[str, EvidenceValue] = Field(default_factory=dict)
    source: str = Field(description="Check or provider that produced the finding")
    provenance: Provenance = Provenance.live
    observed_at: str
    severity: Severity
    strength: Strength
    impact: str
    recommendation: str
    limitation: str


class CheckResult(StrictModel):
    name: str = Field(description="e.g. 'intel.urlhaus', 'tls.handshake'")
    module: Module
    status: CheckStatus
    essential: bool = Field(description="Essential checks gate Low Risk; missing ones force Inconclusive")
    detail: str = ""
    duration_ms: int = 0


class Hop(StrictModel):
    index: int
    url: str
    host: str
    ip: str | None = None
    status: int | None = None
    location: str | None = None
    blocked_reason: str | None = None
    tls_version: str | None = None
    duration_ms: int = 0


class Indicator(StrictModel):
    type: Literal["url", "domain", "ip", "email", "phone", "upi", "crypto_wallet", "brand", "cert_spki"]
    display: str = Field(description="Safe display value (defanged URL, masked phone/email)")
    match_key: str = Field(description="Normalized value, or keyed HMAC for personal identifiers")
    hashed: bool = False


class Coverage(StrictModel):
    applicable: int
    succeeded: int
    failed: int
    unavailable: int
    skipped: int
    essential_missing: list[str]


class Assessment(StrictModel):
    classification: Classification
    rule_id: str
    rule_text: str
    basis_finding_ids: list[str]
    rationale: list[str]
    contradictions: list[str]
    coverage: Coverage


class AIPoint(StrictModel):
    finding_ids: list[str]
    explanation: str


class AIObservation(StrictModel):
    technique: str
    quote: str
    rationale: str
    quote_verified: bool


class AIResult(StrictModel):
    status: Literal["ok", "unavailable", "failed", "disabled", "rejected"]
    provider: str | None = None
    model: str | None = None
    latency_ms: int | None = None
    summary: str | None = None
    points: list[AIPoint] = Field(default_factory=list)
    observations: list[AIObservation] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    uncertainty: str | None = None
    injection_attempt_observed: bool | None = None
    validation_notes: list[str] = Field(default_factory=list)
    error: str | None = None


class CorrelationLink(StrictModel):
    other_report_id: str
    other_created_at: str
    other_classification: str
    shared: list[str] = Field(description="Shared indicator types and display values")
    method: Literal["exact_indicator", "message_similarity", "brand_pattern", "infrastructure"]
    score: int | None = Field(default=None, description="Similarity in percent (0-100) for message_similarity only")


class RegistryRecord(StrictModel):
    chain_id: int
    contract: str
    report_id_hex: str
    commitment: str
    revision: int
    tx_hash: str
    block_number: int
    registered_at: str
    canonicalization: str


class Report(StrictModel):
    schema_version: Literal["wtd.report.v1"] = SCHEMA_VERSION
    id: str
    kind: Literal["url", "message"]
    status: Literal["queued", "running", "complete", "failed", "interrupted"]
    created_at: str
    completed_at: str | None = None
    input_display: str = Field(description="Defanged URL, or a redacted excerpt for messages")
    input_sha256: str
    subject: dict[str, EvidenceValue] = Field(default_factory=dict)
    redirects: list[Hop] = Field(default_factory=list)
    tls: dict[str, EvidenceValue] | None = None
    web: dict[str, EvidenceValue] | None = None
    indicators: list[Indicator] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    checks: list[CheckResult] = Field(default_factory=list)
    assessment: Assessment | None = None
    ai: AIResult | None = None
    correlations: list[CorrelationLink] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    registry: list[RegistryRecord] = Field(default_factory=list)
    error: str | None = None
