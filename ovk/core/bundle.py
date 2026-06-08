"""Evidence bundle construction utilities."""

from __future__ import annotations

import json
from hashlib import sha256

from ovk.core.models import EvidenceBundle, VerificationEvidence


def _stable_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def content_digest(value: object) -> str:
    """Return a stable SHA-256 digest for a JSON-like value."""
    return sha256(_stable_json(value).encode("utf-8")).hexdigest()


def make_bundle(evidence: list[VerificationEvidence]) -> EvidenceBundle:
    """Create a conservative content-addressed bundle from evidence objects."""
    if not evidence:
        raise ValueError("cannot create an evidence bundle without evidence")

    subject = evidence[0].subject
    status_values = [claim.status.value for item in evidence for claim in item.backend_claims]

    if "fail" in status_values:
        recommendation = "block"
        reason = "one or more verification intents failed"
    elif any(status in {"unknown", "error", "skipped"} for status in status_values):
        recommendation = "require_human_review"
        reason = "one or more verification intents returned an unknown-like result"
    else:
        recommendation = "allow"
        reason = "all evaluated verification intents passed"

    evidence_payload = [item.model_dump(mode="json") for item in evidence]
    fingerprint = content_digest({"subject": subject, "evidence": evidence_payload})[:16]

    return EvidenceBundle(
        bundle_id=f"bundle-{fingerprint}",
        schema_version="ovk.bundle.v1",
        subject=subject,
        evidence=evidence,
        decision={"merge_recommendation": recommendation, "reason": reason},
    )
