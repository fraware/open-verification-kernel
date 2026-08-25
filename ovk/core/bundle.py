"""Evidence bundle construction utilities.

``content_digest`` canonicalization (identity version ``ovk.canonical_json.v1``):

* UTF-8 JSON via ``json.dumps``
* object keys sorted lexicographically (``sort_keys=True``)
* separators ``(",", ":")`` with no extra whitespace
* list order is significant and preserved
* ``null`` encodes as JSON null
* numbers use Python's default JSON encoding (not RFC 8785)
* NaN and Infinity are rejected; they are not canonical JSON
* RFC 8785 (JCS) is a future identity-version migration, not this digest
"""

from __future__ import annotations

import json
import math
from hashlib import sha256
from ovk.core.decision import decide_with_reason
from ovk.core.models import EvidenceBundle, VerificationEvidence

CANONICAL_JSON_VERSION = "ovk.canonical_json.v1"


def _reject_nonfinite(value: object, path: str = "$") -> None:
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        raise ValueError(f"non-finite number at {path} is not canonical JSON")
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_nonfinite(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_nonfinite(item, f"{path}[{index}]")


def _stable_json(value: object) -> str:
    _reject_nonfinite(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def content_digest(value: object) -> str:
    """Return a stable SHA-256 digest for a JSON-like value."""
    return sha256(_stable_json(value).encode("utf-8")).hexdigest()


def _validate_bundle_inputs(evidence: list[VerificationEvidence]) -> None:
    subject = evidence[0].subject
    for index, item in enumerate(evidence[1:], start=1):
        if item.subject != subject:
            raise ValueError(f"evidence subject mismatch at index {index}: expected {subject}, got {item.subject}")
    evidence_ids = [item.evidence_id for item in evidence]
    duplicate_ids = sorted({item for item in evidence_ids if evidence_ids.count(item) > 1})
    if duplicate_ids:
        raise ValueError(f"evidence bundle contains duplicate evidence_id values: {', '.join(duplicate_ids)}")


def _bundle_schema_version(evidence: list[VerificationEvidence]) -> str:
    versions = [str(item.schema_version) for item in evidence]
    if versions and all(version.startswith("ovk.evidence.v3") for version in versions):
        return "ovk.bundle.v3"
    if versions and all(version.endswith(".v2") for version in versions):
        return "ovk.bundle.v2"
    return "ovk.bundle.v1"


def make_bundle(
    evidence: list[VerificationEvidence],
    *,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
) -> EvidenceBundle:
    """Create a conservative content-addressed bundle from evidence objects."""
    if not evidence:
        raise ValueError("cannot create an evidence bundle without evidence")
    _validate_bundle_inputs(evidence)

    subject = evidence[0].subject
    evidence_payload = [item.model_dump(mode="json") for item in evidence]
    fingerprint = content_digest({"subject": subject, "evidence": evidence_payload})[:16]
    schema_version = _bundle_schema_version(evidence)

    provisional = EvidenceBundle(
        bundle_id=f"bundle-{fingerprint}",
        schema_version=schema_version,
        subject=subject,
        evidence=evidence,
        decision={"merge_recommendation": "require_human_review", "reason": "pending"},
    )
    decision = decide_with_reason(
        provisional,
        enforce=enforce,
        default_on_unknown=default_on_unknown,
    )
    return EvidenceBundle(
        bundle_id=provisional.bundle_id,
        schema_version=provisional.schema_version,
        subject=subject,
        evidence=evidence,
        decision=decision,
    )


def compute_evidence_digest(evidence: VerificationEvidence | dict) -> str:
    """Compute the integrity digest for one evidence record (see evidence_integrity)."""
    from ovk.core.evidence_integrity import compute_evidence_digest as _compute

    return _compute(evidence)


def verify_evidence_digest(evidence: VerificationEvidence | dict) -> bool:
    """Verify the integrity digest for one evidence record (see evidence_integrity)."""
    from ovk.core.evidence_integrity import verify_evidence_digest as _verify

    return _verify(evidence)
