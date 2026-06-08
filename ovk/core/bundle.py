"""Evidence bundle construction utilities."""

from __future__ import annotations

from hashlib import sha256

from ovk.core.models import EvidenceBundle, VerificationEvidence


def make_bundle(evidence: list[VerificationEvidence]) -> EvidenceBundle:
    """Create a conservative bundle from one or more evidence objects."""
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

    fingerprint = sha256(
        (str(subject) + "|" + "|".join(item.evidence_id for item in evidence)).encode("utf-8")
    ).hexdigest()[:16]

    return EvidenceBundle(
        bundle_id=f"bundle-{fingerprint}",
        schema_version="ovk.bundle.v1",
        subject=subject,
        evidence=evidence,
        decision={"merge_recommendation": recommendation, "reason": reason},
    )
