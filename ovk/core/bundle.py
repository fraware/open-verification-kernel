"""Evidence bundle construction utilities."""

from __future__ import annotations

import json
from hashlib import sha256

from ovk.core.decision import decide_with_reason
from ovk.core.models import EvidenceBundle, VerificationEvidence


def _stable_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def content_digest(value: object) -> str:
    """Return a stable SHA-256 digest for a JSON-like value."""
    return sha256(_stable_json(value).encode("utf-8")).hexdigest()


def make_bundle(
    evidence: list[VerificationEvidence],
    *,
    enforce: bool = True,
    default_on_unknown: str = "require_human_review",
) -> EvidenceBundle:
    """Create a conservative content-addressed bundle from evidence objects."""
    if not evidence:
        raise ValueError("cannot create an evidence bundle without evidence")

    subject = evidence[0].subject
    evidence_payload = [item.model_dump(mode="json") for item in evidence]
    fingerprint = content_digest({"subject": subject, "evidence": evidence_payload})[:16]

    provisional = EvidenceBundle(
        bundle_id=f"bundle-{fingerprint}",
        schema_version="ovk.bundle.v1",
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
