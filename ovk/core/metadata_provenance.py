"""Typed and authenticated acquisition provenance for critical repository metadata."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Literal

from pydantic import BaseModel, Field

from ovk.core.bundle import content_digest

PROVENANCE_SCHEMA_VERSION = "ovk.metadata_acquisition.v1"
SIGNATURE_ALGORITHM = "hmac-sha256"
TRUSTED_PROVENANCE_KINDS: frozenset[str] = frozenset(
    {"protected_base_workflow", "signed_service", "maintainer_supplied"}
)


class AcquisitionSignature(BaseModel):
    algorithm: Literal["hmac-sha256"] = SIGNATURE_ALGORITHM
    key_id: str
    digest: str


class MetadataAcquisitionRecord(BaseModel):
    """Digest-bound record describing how control-plane metadata was acquired."""

    schema_version: Literal["ovk.metadata_acquisition.v1"] = PROVENANCE_SCHEMA_VERSION
    collector_id: str
    collector_version: str
    source_type: Literal["branch_protection"]
    repository: str
    branch: str
    base_sha: str | None = None
    head_sha: str | None = None
    collected_at: str
    payload_digest: str
    authentication_method: str
    provenance_kind: str
    source_endpoint: str | None = None
    signature: AcquisitionSignature | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)


def branch_metadata_payload(data: dict[str, Any]) -> dict[str, Any]:
    before = data.get("before") if isinstance(data.get("before"), dict) else {}
    after = data.get("after") if isinstance(data.get("after"), dict) else {}
    return {"before": before, "after": after}


def expected_branch_metadata_digest(data: dict[str, Any]) -> str:
    return content_digest(branch_metadata_payload(data))


def _unsigned_record_payload(record: MetadataAcquisitionRecord | dict[str, Any]) -> dict[str, Any]:
    payload = record.model_dump(mode="json") if isinstance(record, MetadataAcquisitionRecord) else dict(record)
    payload.pop("signature", None)
    return payload


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_acquisition_record(
    record: MetadataAcquisitionRecord | dict[str, Any],
    *,
    key: str,
    key_id: str = "ovk-metadata-v1",
) -> MetadataAcquisitionRecord:
    """Authenticate an acquisition record using a protected collector key."""
    if not key:
        raise ValueError("metadata signing key must be non-empty")
    unsigned = _unsigned_record_payload(record)
    digest = hmac.new(key.encode("utf-8"), _canonical_bytes(unsigned), hashlib.sha256).hexdigest()
    unsigned["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "digest": digest,
    }
    return MetadataAcquisitionRecord.model_validate(unsigned)


def verify_acquisition_signature(
    record: MetadataAcquisitionRecord,
    *,
    key: str | None,
) -> bool:
    if not key or record.signature is None:
        return False
    if record.signature.algorithm != SIGNATURE_ALGORITHM:
        return False
    unsigned = _unsigned_record_payload(record)
    expected = hmac.new(
        key.encode("utf-8"),
        _canonical_bytes(unsigned),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, record.signature.digest)


def parse_acquisition_record(data: dict[str, Any]) -> MetadataAcquisitionRecord | None:
    raw = data.get("_ovk_acquisition")
    if not isinstance(raw, dict):
        return None
    try:
        return MetadataAcquisitionRecord.model_validate(raw)
    except Exception:
        return None


def acquisition_is_trusted(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    verification_key: str | None,
    allowed_provenance_kinds: set[str] | frozenset[str] | None = None,
) -> tuple[bool, list[str], MetadataAcquisitionRecord | None]:
    """Validate provenance, content binding and authentication against material."""
    record = parse_acquisition_record(data)
    reasons: list[str] = []
    if record is None:
        return False, ["typed metadata acquisition record missing or invalid"], None

    allowed = frozenset(allowed_provenance_kinds or TRUSTED_PROVENANCE_KINDS)
    if record.provenance_kind not in TRUSTED_PROVENANCE_KINDS:
        reasons.append(f"untrusted provenance kind: {record.provenance_kind}")
    if record.provenance_kind not in allowed:
        reasons.append(f"provenance kind not allowed by policy: {record.provenance_kind}")
    if record.repository != repo:
        reasons.append(f"repository mismatch: {record.repository} != {repo}")
    if record.head_sha and record.head_sha != head_sha:
        reasons.append(f"head revision mismatch: {record.head_sha} != {head_sha}")
    if base_sha is not None and record.base_sha != base_sha:
        reasons.append(f"base revision mismatch: {record.base_sha} != {base_sha}")
    if record.payload_digest != expected_branch_metadata_digest(data):
        reasons.append("metadata payload digest mismatch")
    if not record.collector_id.strip() or not record.collector_version.strip():
        reasons.append("collector identity incomplete")
    if not record.authentication_method.strip():
        reasons.append("authentication method missing")
    if not verify_acquisition_signature(record, key=verification_key):
        reasons.append("metadata acquisition signature missing or invalid")

    return not reasons, reasons, record


def allowed_provenance_kinds_from_policy(policy: dict[str, Any] | None) -> frozenset[str]:
    """Read an allowlist only; no policy field can directly assert trust."""
    if not isinstance(policy, dict):
        return TRUSTED_PROVENANCE_KINDS
    trust = policy.get("trust")
    if not isinstance(trust, dict):
        return TRUSTED_PROVENANCE_KINDS
    raw = trust.get("allowed_metadata_provenance_kinds")
    if raw is None:
        return TRUSTED_PROVENANCE_KINDS
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(str(item) for item in raw if str(item) in TRUSTED_PROVENANCE_KINDS)
