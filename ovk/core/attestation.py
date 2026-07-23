"""Verification attestation helpers.

OVK uses an in-toto-style statement shape for portable verification claims.
This module does not sign statements. It produces unsigned predicates that can
later be wrapped by DSSE or the repository's chosen attestation mechanism.
"""

from __future__ import annotations

from typing import Any

import sys

from ovk import __version__
from ovk.core.bundle import content_digest
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
                "severity": (evidence.intent.get("risk") or {}).get("severity")
                if isinstance(evidence.intent.get("risk"), dict)
                else None,
                "claims": [claim.model_dump(mode="json") for claim in evidence.backend_claims],
                "counterexamples": evidence.counterexamples,
                "decision": evidence.decision,
                "obligation_id": evidence.obligation_id,
                "routing_id": evidence.routing_id,
                "compiler": evidence.compiler,
                "coverage": evidence.coverage,
                "materials": evidence.materials,
                "requested_backends": evidence.requested_backends,
                "eligible_backends": evidence.eligible_backends,
                "selected_backends": evidence.selected_backends,
                "executed_backends": evidence.executed_backends,
                "aggregation_policy": evidence.aggregation_policy,
                "routing_enforced": evidence.routing_enforced,
                "open_artifacts": [
                    item
                    for item in (evidence.generated_artifacts or [])
                    if isinstance(item, dict)
                    and item.get("kind")
                    in {
                        "backend_disagreement",
                        "quality_error",
                        "incomplete_abstraction",
                        "backend_provenance",
                    }
                ],
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
            "builder": {
                "id": "open-verification-kernel",
                "version": __version__,
                "runtime": f"python/{sys.version.split()[0]}",
            },
            "verification": {
                "bundle_id": bundle.bundle_id,
                "bundle_digest": content_digest(bundle.model_dump(mode="json")),
                "schema_version": bundle.schema_version,
                "evidence": evidence_items,
                "decision": bundle.decision,
                "open_obligations": bundle.open_obligations,
            },
        },
    }
