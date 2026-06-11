"""Evaluate pre-built backend fixture payloads used in benchmarks and pilots."""

from __future__ import annotations

from typing import Any, Callable

from ovk.core.models import VerificationEvidence


BackendEvaluator = Callable[..., VerificationEvidence]


def _cedar(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None) -> VerificationEvidence:
    from ovk.adapters.cedar.evidence import evaluate_cedar_policy

    return evaluate_cedar_policy(data, repo=repo, head_sha=head_sha, base_sha=base_sha)


def _tla(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None) -> VerificationEvidence:
    from ovk.adapters.tla.evidence import evaluate_tla_state_machine

    return evaluate_tla_state_machine(data, repo=repo, head_sha=head_sha, base_sha=base_sha)


def _kani(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None) -> VerificationEvidence:
    from ovk.adapters.kani.evidence import evaluate_kani_harness

    return evaluate_kani_harness(data, repo=repo, head_sha=head_sha, base_sha=base_sha)


def _dafny(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None) -> VerificationEvidence:
    from ovk.adapters.dafny.evidence import evaluate_dafny_obligation

    return evaluate_dafny_obligation(data, repo=repo, head_sha=head_sha, base_sha=base_sha)


def _verus(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None) -> VerificationEvidence:
    from ovk.adapters.verus.evidence import evaluate_verus_harness

    return evaluate_verus_harness(data, repo=repo, head_sha=head_sha, base_sha=base_sha)


def _lean(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None) -> VerificationEvidence:
    from ovk.adapters.lean.evidence import evaluate_lean_obligation

    return evaluate_lean_obligation(data, repo=repo, head_sha=head_sha, base_sha=base_sha)


def _cbmc(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None) -> VerificationEvidence:
    from ovk.adapters.cbmc.evidence import evaluate_cbmc_harness

    return evaluate_cbmc_harness(data, repo=repo, head_sha=head_sha, base_sha=base_sha)


def _alloy(data: dict[str, Any], *, repo: str, head_sha: str, base_sha: str | None) -> VerificationEvidence:
    from ovk.adapters.alloy.evidence import evaluate_alloy_model

    return evaluate_alloy_model(data, repo=repo, head_sha=head_sha, base_sha=base_sha)


BACKEND_INTENT_EVALUATORS: dict[str, BackendEvaluator] = {
    "cedar-policy-check": _cedar,
    "tla-state-check": _tla,
    "kani-harness-check": _kani,
    "dafny-obligation-check": _dafny,
    "verus-harness-check": _verus,
    "lean-proof-check": _lean,
    "cbmc-harness-check": _cbmc,
    "cbmc-buffer-bounds": _cbmc,
    "cbmc-no-integer-overflow-quota": _cbmc,
    "cbmc-no-unchecked-buffer-copy": _cbmc,
    "cbmc-no-use-after-free-auth-cache": _cbmc,
    "alloy-model-check": _alloy,
}


def evaluate_backend_fixture(
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
    intent_id: str | None = None,
) -> VerificationEvidence:
    """Dispatch a backend fixture payload by ``intent_id`` (payload or override)."""
    resolved_intent = str(intent_id or data.get("intent_id", "")).strip()
    evaluator = BACKEND_INTENT_EVALUATORS.get(resolved_intent)
    if evaluator is None:
        supported = ", ".join(sorted(BACKEND_INTENT_EVALUATORS))
        raise ValueError(f"unsupported backend fixture intent: {resolved_intent!r} (supported: {supported})")
    return evaluator(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
