"""Typed profile mutations for verifier-assurance (immutable; no production overwrite)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping

from ovk.assurance.errors import MutationError
from ovk.assurance.pcs_export import build_mutation_manifest, profile_ref_from_profile
from ovk.assurance.pcs_hash import attach_nested_integrity, sha256_digest
from ovk.assurance.pcs_validate import require_valid_pcs_artifact

SUPPORTED_MUTATION_CLASSES = frozenset(
    {
        "remove_success_predicate",
        "remove_process_predicate",
        "remove_authority_predicate",
        "change_threshold",
        "reduce_test_subset",
        "alter_timeout",
        "suppress_error",
        "change_rubric",
        "change_prompt",
        "ensemble_quorum",
        "hidden_state_access",
        "policy_bundle",
        "abstention",
        "other",
    }
)

_DEFAULT_EFFECTS: dict[str, str] = {
    "alter_timeout": "Changes execution timeout; may increase indeterminate_execution_error on slow checks.",
    "change_threshold": "Changes acceptance threshold; may flip accept/reject boundary.",
    "reduce_test_subset": "Reduces evaluated test subset; weakens observational coverage.",
    "remove_success_predicate": "Removes success predicate; acceptance becomes weaker or indeterminate.",
    "remove_process_predicate": "Removes process predicate checks from the profile configuration.",
    "remove_authority_predicate": "Removes authority predicate checks from the profile configuration.",
    "suppress_error": "Suppresses error surfaces; forbidden for production profiles.",
    "change_rubric": "Changes evaluation rubric digest binding.",
    "change_prompt": "Changes prompt digest binding for model-judge verifiers.",
    "ensemble_quorum": "Changes ensemble quorum requirements.",
    "hidden_state_access": "Alters hidden-state access declaration.",
    "policy_bundle": "Swaps or mutates policy bundle digest.",
    "abstention": "Alters abstention allowance.",
    "other": "Other typed mutation applied to immutable profile copy.",
}


def _refuse_production_overwrite(out_path: Path, production_profile_path: Path | None) -> None:
    if production_profile_path is None:
        return
    try:
        if out_path.resolve() == production_profile_path.resolve():
            raise MutationError(
                f"refusing to overwrite production profile path: {production_profile_path}"
            )
    except FileNotFoundError:
        # resolve() on missing parents can still compare; keep explicit string compare fallback
        if str(out_path) == str(production_profile_path):
            raise MutationError(
                f"refusing to overwrite production profile path: {production_profile_path}"
            )


def _apply_mutation_to_profile(
    profile: dict[str, Any],
    mutation_class: str,
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    mutated = copy.deepcopy(profile)
    mutated.pop("integrity", None)

    config = dict(mutated.get("canonical_configuration") or {})
    configuration = dict(mutated.get("configuration") or {})

    if mutation_class == "alter_timeout":
        if "timeout_ms" not in parameters:
            raise MutationError("alter_timeout requires parameters.timeout_ms")
        timeout_ms = int(parameters["timeout_ms"])
        if timeout_ms < 1:
            raise MutationError("timeout_ms must be >= 1")
        config["timeout_ms"] = timeout_ms
        controls = dict(mutated.get("execution_controls") or {})
        controls["timeout_ms"] = timeout_ms
        mutated["execution_controls"] = controls
        configuration["resource_limit_digest"] = sha256_digest({"timeout_ms": timeout_ms})
    elif mutation_class == "change_threshold":
        if "threshold" not in parameters:
            raise MutationError("change_threshold requires parameters.threshold")
        threshold = parameters["threshold"]
        # Canonical JSON forbids floats — store decimal string when needed.
        if isinstance(threshold, float):
            threshold = format(threshold, "f").rstrip("0").rstrip(".") or "0"
        config["threshold"] = threshold
        configuration["threshold_digest"] = sha256_digest({"threshold": threshold})
    elif mutation_class == "reduce_test_subset":
        subset = parameters.get("test_ids") or parameters.get("subset") or []
        if not isinstance(subset, list) or not subset:
            raise MutationError("reduce_test_subset requires non-empty parameters.test_ids")
        config["test_suite"] = {"test_ids": list(subset)}
        configuration["test_suite_digest"] = sha256_digest(config["test_suite"])
    elif mutation_class == "policy_bundle":
        policy = parameters.get("policy")
        if policy is None:
            raise MutationError("policy_bundle requires parameters.policy")
        config["policy"] = policy
        configuration["policy_digest"] = sha256_digest(policy)
    elif mutation_class == "change_prompt":
        prompt = parameters.get("prompt")
        if prompt is None:
            raise MutationError("change_prompt requires parameters.prompt")
        config["prompt"] = prompt
        configuration["prompt_digest"] = sha256_digest(prompt)
    elif mutation_class == "change_rubric":
        rubric = parameters.get("rubric")
        if rubric is None:
            raise MutationError("change_rubric requires parameters.rubric")
        config["rubric"] = rubric
        configuration["rubric_digest"] = sha256_digest(rubric)
    elif mutation_class == "abstention":
        if "allows_abstention" not in parameters:
            raise MutationError("abstention requires parameters.allows_abstention")
        mechanism = dict(mutated.get("mechanism") or {})
        mechanism["allows_abstention"] = bool(parameters["allows_abstention"])
        mutated["mechanism"] = mechanism
    elif mutation_class in {
        "remove_success_predicate",
        "remove_process_predicate",
        "remove_authority_predicate",
        "suppress_error",
        "ensemble_quorum",
        "hidden_state_access",
        "other",
    }:
        mutations = list(config.get("_mutations") or [])
        mutations.append({"class": mutation_class, "parameters": dict(parameters)})
        config["_mutations"] = mutations
    else:
        raise MutationError(f"unsupported mutation class: {mutation_class!r}")

    # Rebind config digest after material change.
    configuration["config_digest"] = sha256_digest(config)
    mutated["canonical_configuration"] = config
    mutated["configuration"] = configuration

    # New immutable identity
    base_id = str(mutated.get("verifier_profile_id") or "vp")
    mutated["verifier_profile_id"] = f"{base_id}-mut-{mutation_class}"
    return attach_nested_integrity(mutated)


def mutate_profile(
    profile: Mapping[str, Any] | Path | str,
    *,
    mutation_class: str,
    parameters: Mapping[str, Any] | None = None,
    out_path: Path | str | None = None,
    production_profile_path: Path | str | None = None,
    supported_dimensions: list[str] | None = None,
    expected_effect: str | None = None,
    rationale: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Apply a typed mutation, producing a NEW sealed profile and mutation manifest.

    Always sets ``production_prohibition=True``. Refuses overwrite of the
    production profile path.
    """
    if mutation_class not in SUPPORTED_MUTATION_CLASSES:
        raise MutationError(f"unsupported mutation class: {mutation_class!r}")

    if supported_dimensions is not None and mutation_class not in supported_dimensions:
        raise MutationError(
            f"mutation {mutation_class!r} is not in adapter supported dimensions: "
            f"{sorted(supported_dimensions)}"
        )

    if isinstance(profile, (str, Path)):
        base = json.loads(Path(profile).read_text(encoding="utf-8"))
    else:
        base = dict(profile)
    if not isinstance(base, dict):
        raise MutationError("profile must be a JSON object")
    require_valid_pcs_artifact(base, artifact_type="VerifierProfile.v1")

    params = dict(parameters or {})
    mutated = _apply_mutation_to_profile(base, mutation_class, params)
    require_valid_pcs_artifact(mutated, artifact_type="VerifierProfile.v1")

    if mutated["integrity"]["artifact_digest"] == base["integrity"]["artifact_digest"]:
        raise MutationError("mutation did not change profile digest (no-op refused)")

    effect = expected_effect or _DEFAULT_EFFECTS.get(mutation_class, _DEFAULT_EFFECTS["other"])
    mutation_id = f"mut-{mutation_class}-{mutated['integrity']['artifact_digest'][7:15]}"
    manifest = build_mutation_manifest(
        mutation_id=mutation_id,
        base_profile_ref=profile_ref_from_profile(base),
        mutated_profile_ref=profile_ref_from_profile(mutated),
        mutation_class=mutation_class,
        expected_effect=effect,
        parameters=params or None,
        supported_by_adapter=supported_dimensions is None or mutation_class in supported_dimensions,
        rationale=rationale,
    )

    if out_path is not None:
        out = Path(out_path)
        prod = Path(production_profile_path) if production_profile_path is not None else None
        _refuse_production_overwrite(out, prod)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(mutated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        manifest_path = out.with_suffix(".mutation.json")
        if prod is not None:
            _refuse_production_overwrite(manifest_path, prod)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return mutated, manifest
