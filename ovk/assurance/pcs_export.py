"""Map OVK assurance snapshots/results to sealed PCS VA artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from ovk.assurance.pcs_hash import attach_nested_integrity, sha256_digest
from ovk.assurance.snapshot import ConfigurationSnapshot
from ovk.assurance.source import producer_fields, resolve_source_commit, resolve_source_repo


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _profile_id(snapshot: ConfigurationSnapshot) -> str:
    return f"vp-{snapshot.backend_id}-{snapshot.content_digest[7:15]}"


def snapshot_to_verifier_profile(
    snapshot: ConfigurationSnapshot,
    *,
    source_commit: str | None = None,
    source_repo: str | None = None,
    created_at: str | None = None,
    seal: bool = True,
) -> dict[str, Any]:
    """Build a VerifierProfile.v1 dict from a ConfigurationSnapshot and seal it."""
    commit = source_commit or resolve_source_commit()
    repo = source_repo or resolve_source_repo()
    producer = producer_fields()
    implementation_digest = sha256_digest(
        {
            "adapter_id": snapshot.adapter_id,
            "adapter_version": snapshot.adapter_version,
            "backend_id": snapshot.backend_id,
        }
    )
    profile: dict[str, Any] = {
        "schema_version": "v1",
        "artifact_type": "VerifierProfile.v1",
        "verifier_profile_id": _profile_id(snapshot),
        "created_at": created_at or snapshot.created_at or _utc_now_iso(),
        **producer,
        "source_repo": repo,
        "source_commit": commit,
        "implementation": {
            "name": snapshot.implementation_name or snapshot.backend_id,
            "version": snapshot.adapter_version,
            "language": "python",
            "entry_point": snapshot.entry_point or snapshot.adapter_id,
            "implementation_digest": implementation_digest,
            "normalization_implementation_version": "ovk.normalize.v1",
        },
        "configuration": {
            "config_digest": snapshot.config_digest,
            "policy_digest": snapshot.policy_digest,
            "model_digest": snapshot.model_digest,
            "prompt_digest": snapshot.prompt_digest,
            "resource_limit_digest": snapshot.resource_limit_digest,
            "rubric_digest": snapshot.rubric_digest,
            "test_suite_digest": snapshot.test_suite_digest,
            "threshold_digest": snapshot.threshold_digest,
            "ensemble_digest": snapshot.ensemble_digest,
        },
        "mechanism": {
            "mechanism_class": snapshot.mechanism_class or "other",
            "determinism": snapshot.determinism,
            "allows_abstention": snapshot.allows_abstention,
            "description": f"OVK assurance snapshot for backend {snapshot.backend_id}",
        },
        "claim_surface": {
            "supported_claim_ids": list(snapshot.supported_claim_ids)
            or [f"claim.{snapshot.backend_id}"],
            "guarantee_class": snapshot.guarantee_class,
            "out_of_scope_claim_ids": list(snapshot.out_of_scope_claim_ids),
        },
        "applicability": {
            "status": "active",
            "valid_from": created_at or snapshot.created_at or _utc_now_iso(),
        },
        "assumptions": list(snapshot.assumptions) or ["configuration digests bind material inputs"],
        "known_blind_spots": list(snapshot.known_blind_spots)
        or ["Profile binds digests only; does not assert checker correctness"],
        "canonical_configuration": dict(snapshot.config),
        "redacted_environment": dict(snapshot.redacted_environment),
    }
    if snapshot.decision_space:
        profile["claim_surface"]["decision_space"] = list(snapshot.decision_space)
    if snapshot.external_dependencies:
        profile["external_dependencies"] = list(snapshot.external_dependencies)
    if snapshot.timeout_ms is not None:
        profile["execution_controls"] = {"timeout_ms": int(snapshot.timeout_ms)}
    profile["limitations_notice"] = (
        "Profile binds configuration and digests only; it does not claim "
        "checker correctness beyond recorded results."
    )
    if seal:
        return attach_nested_integrity(profile)
    return profile


def build_verification_result(
    *,
    verification_result_id: str,
    profile: Mapping[str, Any],
    decision: str,
    execution_status: str,
    claim_ids: list[str],
    raw_backend_output_digest: str,
    normalized_result_digest: str,
    check_groups: list[dict[str, Any]] | None = None,
    resource_limits: dict[str, Any] | None = None,
    guarantee_class: str | None = None,
    declared_input_guarantee_class: str | None = None,
    normalization_applied: bool = True,
    normalizer_version: str = "ovk.normalize.v1",
    invocation_ref: dict[str, Any] | None = None,
    input_bundle_digest: str | None = None,
    assumptions: list[dict[str, Any]] | None = None,
    limits: list[dict[str, Any]] | None = None,
    source_commit: str | None = None,
    source_repo: str | None = None,
    created_at: str | None = None,
    seal: bool = True,
) -> dict[str, Any]:
    """Build a VerificationResult.v1 dict and optionally seal it."""
    profile_digest = profile.get("integrity", {}).get("artifact_digest")
    if not isinstance(profile_digest, str):
        body = {k: v for k, v in profile.items() if k != "integrity"}
        profile_digest = sha256_digest(body)
    producer = producer_fields()
    resolved_guarantee = guarantee_class or profile.get("claim_surface", {}).get(
        "guarantee_class", "observational"
    )
    result: dict[str, Any] = {
        "schema_version": "v1",
        "artifact_type": "VerificationResult.v1",
        "verification_result_id": verification_result_id,
        "created_at": created_at or _utc_now_iso(),
        **producer,
        "source_repo": source_repo or resolve_source_repo(),
        "source_commit": source_commit or resolve_source_commit(),
        "verifier_profile": {
            "verifier_profile_id": profile["verifier_profile_id"],
            "profile_digest": profile_digest,
        },
        "claim_ids": list(claim_ids),
        "raw_backend_output_digest": raw_backend_output_digest,
        "normalized_result_digest": normalized_result_digest,
        "normalization_applied": normalization_applied,
        "normalizer_version": normalizer_version,
        "check_groups": list(check_groups or []),
        "resource_limits": dict(resource_limits or {}),
        "execution_status": execution_status,
        "decision": decision,
        "guarantee_class": resolved_guarantee,
    }
    if declared_input_guarantee_class is not None:
        result["declared_input_guarantee_class"] = declared_input_guarantee_class
    if invocation_ref is not None:
        result["invocation_ref"] = dict(invocation_ref)
    if input_bundle_digest is not None:
        result["input_bundle_digest"] = input_bundle_digest
    if assumptions is not None:
        result["assumptions"] = list(assumptions)
    if limits is not None:
        result["limits"] = list(limits)
    if seal:
        return attach_nested_integrity(result)
    return result


def build_invocation_record_artifact(
    invocation: Mapping[str, Any],
    *,
    seal: bool = True,
) -> dict[str, Any]:
    """Ensure an invocation dict is a sealed VerifierInvocationRecord.v1."""
    payload = dict(invocation)
    payload.setdefault("schema_version", "v1")
    payload.setdefault("artifact_type", "VerifierInvocationRecord.v1")
    payload.setdefault("canonicalization_version", "v1")
    producer = producer_fields()
    payload.setdefault("producer", producer["producer"])
    payload.setdefault("producer_version", producer["producer_version"])
    if seal:
        return attach_nested_integrity(payload)
    return payload


def build_replay_report(
    *,
    replay_id: str,
    original_invocation_ref: dict[str, Any],
    profile_ref: dict[str, Any],
    replay_status: str,
    determinism: str,
    original_raw_digest: str,
    replay_raw_digest: str,
    original_normalized_digest: str,
    replay_normalized_digest: str,
    drift: dict[str, Any],
    replay_invocation_ref: dict[str, Any] | None = None,
    indeterminate_reason: str | None = None,
    failure_reason: str | None = None,
    created_at: str | None = None,
    seal: bool = True,
) -> dict[str, Any]:
    """Build a sealed VerifierReplayReport.v1."""
    producer = producer_fields()
    report: dict[str, Any] = {
        "schema_version": "v1",
        "artifact_type": "VerifierReplayReport.v1",
        "canonicalization_version": "v1",
        "replay_id": replay_id,
        "original_invocation_ref": dict(original_invocation_ref),
        "profile_ref": dict(profile_ref),
        "replay_status": replay_status,
        "determinism": determinism,
        "original_raw_digest": original_raw_digest,
        "replay_raw_digest": replay_raw_digest,
        "original_normalized_digest": original_normalized_digest,
        "replay_normalized_digest": replay_normalized_digest,
        "drift": dict(drift),
        **producer,
        "created_at": created_at or _utc_now_iso(),
    }
    if replay_invocation_ref is not None:
        report["replay_invocation_ref"] = dict(replay_invocation_ref)
    if indeterminate_reason is not None:
        report["indeterminate_reason"] = indeterminate_reason
    if failure_reason is not None:
        report["failure_reason"] = failure_reason
    if seal:
        return attach_nested_integrity(report)
    return report


def build_mutation_manifest(
    *,
    mutation_id: str,
    base_profile_ref: dict[str, Any],
    mutated_profile_ref: dict[str, Any],
    mutation_class: str,
    expected_effect: str,
    parameters: dict[str, Any] | None = None,
    supported_by_adapter: bool | None = None,
    rationale: str | None = None,
    created_at: str | None = None,
    seal: bool = True,
) -> dict[str, Any]:
    """Build a sealed VerifierMutationManifest.v1 (production_prohibition always true)."""
    producer = producer_fields()
    manifest: dict[str, Any] = {
        "schema_version": "v1",
        "artifact_type": "VerifierMutationManifest.v1",
        "canonicalization_version": "v1",
        "mutation_id": mutation_id,
        "base_profile_ref": dict(base_profile_ref),
        "mutated_profile_ref": dict(mutated_profile_ref),
        "mutation_class": mutation_class,
        "expected_effect": expected_effect,
        "production_prohibition": True,
        **producer,
        "created_at": created_at or _utc_now_iso(),
    }
    if parameters is not None:
        manifest["parameters"] = dict(parameters)
    if supported_by_adapter is not None:
        manifest["supported_by_adapter"] = supported_by_adapter
    if rationale is not None:
        manifest["rationale"] = rationale
    if seal:
        return attach_nested_integrity(manifest)
    return manifest


def profile_ref_from_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    digest = profile.get("integrity", {}).get("artifact_digest")
    if not isinstance(digest, str):
        raise ValueError("profile missing integrity.artifact_digest")
    return {
        "artifact_type": "VerifierProfile.v1",
        "verifier_profile_id": profile["verifier_profile_id"],
        "profile_digest": digest,
    }


def invocation_ref_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Build a PCS opaque invocation_ref (id + digest only; no artifact_type)."""
    digest = record.get("integrity", {}).get("artifact_digest")
    if not isinstance(digest, str):
        raise ValueError("invocation missing integrity.artifact_digest")
    return {
        "invocation_id": record["invocation_id"],
        "invocation_digest": digest,
    }
