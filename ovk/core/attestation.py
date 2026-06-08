"""Verification attestation helpers.

OVK uses an in-toto-style statement shape for portable verification claims.
This module does not sign statements. It produces unsigned predicates that can
later be wrapped by DSSE or the repository's chosen attestation mechanism.
"""

from __future__ import annotations

from typing import Any

from ovk.core.models import EvidenceBundle


PREDICATE_TYPE = "https://openverification.dev/predicate/verification/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def bundle_to_statement(bundle: EvidenceBundle) -> dict[str, Any]:
    """Convert an OVK evidence bundle into an in-toto-style statement."""
    subject = bundle.subject
    repo = subject.get("repo", "unknown/repo")
    head_sha = subject.get("head_sha", "unknown")
    evidence_items = []

    for evidence in bundle.evidence:
        evidence_items.append(
            {
                "intent_id": evidence.intent.get("intent_id"),
                "title": evidence.intent.get("title"),
                "claims": [claim.model_dump(mode="json") for claim in evidence.backend_claims],
                "counterexamples": evidence.counterexamples,
                "decision": evidence.decision,
            }
        )

    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": f"git+https://github.com/{repo}",
                "digest": {"gitCommit": head_sha},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "builder": {"id": "open-verification-kernel"},
            "verification": {
                "bundle_id": bundle.bundle_id,
                "schema_version": bundle.schema_version,
                "evidence": evidence_items,
                "decision": bundle.decision,
                "open_obligations": bundle.open_obligations,
            },
        },
    }
