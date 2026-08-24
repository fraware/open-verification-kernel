"""Typed acquisition provenance for security-critical repository metadata."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from ovk.core.bundle import content_digest

PROVENANCE_SCHEMA_VERSION = "ovk.metadata_acquisition.v1"
TRUSTED_PROVENANCE_KINDS: frozenset[str] = frozenset(
    {"protected_base_workflow", "signed_service", "maintainer_supplied"}
)


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
    extensions: dict[str, Any] = Field(default_factory=dict)


def branch_metadata_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Return exactly the bytes-of-meaning whose acquisition provenance is bound."""
    before = data.get("before") if isinstance(data.get("before"), dict) else {}
    after = data.get("after") if isinstance(data.get("after"), dict) else {}
    return {"before": before, "after": after}


def expected_branch_metadata_digest(data: dict[str, Any]) -> str:
    return content_digest(branch_metadata_payload(data))


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
    allowed_provenance_kinds: set[str] | frozenset[str] | None = None,
) -> tuple[bool, list[str], MetadataAcquisitionRecord | None]:
    """Validate a metadata acquisition record against the actual material.

    Trust is impossible from a policy boolean alone. The record must be typed,
    digest-bound to the supplied before/after metadata, scoped to the repository
    and revisions being verified, and use a provenance kind explicitly accepted
    by the trust policy.
    """
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
    expected_digest = expected_branch_metadata_digest(data)
    if record.payload_digest != expected_digest:
        reasons.append("metadata payload digest mismatch")
    if not record.collector_id.strip() or not record.collector_version.strip():
        reasons.append("collector identity incomplete")
    if not record.authentication_method.strip():
        reasons.append("authentication method missing")
    if record.source_type != "branch_protection":
        reasons.append("unexpected metadata source type")

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
