"""Backend strategy execution for the self-protection path."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Literal

from ovk.adapters.opa import evaluate_self_protection
from ovk.adapters.opa.evidence import opa_raw_to_evidence
from ovk.adapters.opa.optional_runner import run_opa_policy
from ovk.core.bundle import make_bundle
from ovk.core.models import EvidenceBundle, VerificationEvidence


BackendStrategy = Literal["deterministic", "opa", "both"]


SELF_PROTECTION_POLICY_PATH = Path("adapters/opa/policies/self_protection.rego")


def normalize_backend_strategy(strategy: str) -> BackendStrategy:
    """Normalize and validate the backend strategy string."""
    normalized = strategy.strip().lower()
    if normalized not in {"deterministic", "opa", "both"}:
        raise ValueError(f"unsupported backend strategy: {strategy}")
    return normalized  # type: ignore[return-value]


def _run_opa_evidence(
    structured_input: dict,
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
) -> VerificationEvidence:
    """Run optional OPA and normalize the result into OVK evidence."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as handle:
        json.dump(structured_input, handle)
        input_path = Path(handle.name)

    try:
        raw = run_opa_policy(
            policy_path=SELF_PROTECTION_POLICY_PATH,
            input_path=input_path,
        )
    finally:
        input_path.unlink(missing_ok=True)

    actor = structured_input.get("actor", {}) if isinstance(structured_input.get("actor"), dict) else {}
    return opa_raw_to_evidence(
        raw,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        actor_type=str(actor.get("type", "unknown")),
        agent=str(actor.get("id", "unknown")),
        task=str(structured_input.get("task", "unknown")),
    )


def run_self_protection_backends(
    structured_input: dict,
    *,
    strategy: str = "deterministic",
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> EvidenceBundle:
    """Run selected self-protection backend strategy and return an evidence bundle.

    Strategy semantics:
    - deterministic: use the deterministic evaluator only;
    - opa: use optional OPA only, with unavailable OPA returning unknown;
    - both: run deterministic and optional OPA, with bundle decision semantics applying fail/unknown dominance.
    """
    selected = normalize_backend_strategy(strategy)
    evidence: list[VerificationEvidence] = []

    if selected in {"deterministic", "both"}:
        evidence.append(
            evaluate_self_protection(
                structured_input,
                repo=repo,
                head_sha=head_sha,
                base_sha=base_sha,
            )
        )

    if selected in {"opa", "both"}:
        evidence.append(
            _run_opa_evidence(
                structured_input,
                repo=repo,
                head_sha=head_sha,
                base_sha=base_sha,
            )
        )

    return make_bundle(evidence)
