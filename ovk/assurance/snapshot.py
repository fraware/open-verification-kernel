"""Immutable configuration snapshots for verifier-assurance."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

from ovk.assurance.pcs_hash import sha256_digest
from ovk.assurance.redaction import redact_environment, redact_mapping


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ConfigurationSnapshot(BaseModel):
    """Immutable configuration snapshot bound by content digests."""

    model_config = ConfigDict(frozen=True)

    snapshot_id: str
    backend_id: str
    adapter_id: str
    adapter_version: str
    created_at: str
    config: dict[str, Any] = Field(default_factory=dict)
    config_digest: str
    policy_digest: str | None = None
    model_digest: str | None = None
    prompt_digest: str | None = None
    resource_limit_digest: str | None = None
    rubric_digest: str | None = None
    test_suite_digest: str | None = None
    threshold_digest: str | None = None
    ensemble_digest: str | None = None
    redacted_environment: dict[str, Any] = Field(default_factory=dict)
    content_digest: str
    mechanism_class: str | None = None
    determinism: str = "deterministic"
    allows_abstention: bool = True
    guarantee_class: str = "observational"
    decision_space: list[str] = Field(default_factory=list)
    supported_claim_ids: list[str] = Field(default_factory=list)
    out_of_scope_claim_ids: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    known_blind_spots: list[str] = Field(default_factory=list)
    external_dependencies: list[dict[str, Any]] = Field(default_factory=list)
    entry_point: str | None = None
    implementation_name: str | None = None
    timeout_ms: int | None = None
    mutation_dimensions: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


def _optional_digest(value: Any | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and value.startswith("sha256:"):
        return value
    return sha256_digest(value)


def build_configuration_snapshot(
    *,
    backend_id: str,
    adapter_id: str,
    adapter_version: str,
    config: Mapping[str, Any] | None = None,
    environment: Mapping[str, str] | None = None,
    policy: Any | None = None,
    model: Any | None = None,
    prompt: Any | None = None,
    resource_limits: Any | None = None,
    rubric: Any | None = None,
    test_suite: Any | None = None,
    threshold: Any | None = None,
    ensemble: Any | None = None,
    mechanism_class: str | None = None,
    determinism: str = "deterministic",
    allows_abstention: bool = True,
    guarantee_class: str = "observational",
    decision_space: list[str] | None = None,
    supported_claim_ids: list[str] | None = None,
    out_of_scope_claim_ids: list[str] | None = None,
    assumptions: list[str] | None = None,
    known_blind_spots: list[str] | None = None,
    external_dependencies: list[dict[str, Any]] | None = None,
    entry_point: str | None = None,
    implementation_name: str | None = None,
    timeout_ms: int | None = None,
    mutation_dimensions: list[str] | None = None,
    extra: Mapping[str, Any] | None = None,
    created_at: str | None = None,
) -> ConfigurationSnapshot:
    """Build an immutable snapshot; material config changes yield a new digest."""
    cleaned_config, _ = redact_mapping(dict(config or {}))
    # Prefer explicit timeout from config when present.
    resolved_timeout = timeout_ms
    if resolved_timeout is None and isinstance(cleaned_config.get("timeout_ms"), int):
        resolved_timeout = int(cleaned_config["timeout_ms"])

    config_digest = sha256_digest(cleaned_config)
    env_block = redact_environment(environment)

    policy_digest = _optional_digest(policy if policy is not None else cleaned_config.get("policy"))
    model_digest = _optional_digest(model if model is not None else cleaned_config.get("model"))
    prompt_digest = _optional_digest(prompt if prompt is not None else cleaned_config.get("prompt"))
    resource_limit_digest = _optional_digest(
        resource_limits if resource_limits is not None else cleaned_config.get("resource_limits")
    )
    if resource_limit_digest is None and resolved_timeout is not None:
        resource_limit_digest = sha256_digest({"timeout_ms": resolved_timeout})
    rubric_digest = _optional_digest(rubric if rubric is not None else cleaned_config.get("rubric"))
    test_suite_digest = _optional_digest(
        test_suite if test_suite is not None else cleaned_config.get("test_suite")
    )
    threshold_digest = _optional_digest(
        threshold if threshold is not None else cleaned_config.get("threshold")
    )
    ensemble_digest = _optional_digest(
        ensemble if ensemble is not None else cleaned_config.get("ensemble")
    )

    body = {
        "backend_id": backend_id,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "config": cleaned_config,
        "config_digest": config_digest,
        "policy_digest": policy_digest,
        "model_digest": model_digest,
        "prompt_digest": prompt_digest,
        "resource_limit_digest": resource_limit_digest,
        "rubric_digest": rubric_digest,
        "test_suite_digest": test_suite_digest,
        "threshold_digest": threshold_digest,
        "ensemble_digest": ensemble_digest,
        "redacted_environment": env_block,
        "mechanism_class": mechanism_class,
        "determinism": determinism,
        "timeout_ms": resolved_timeout,
        "extra": dict(extra or {}),
    }
    content = sha256_digest(body)
    snapshot_id = f"snap-{content[7:23]}"
    return ConfigurationSnapshot(
        snapshot_id=snapshot_id,
        backend_id=backend_id,
        adapter_id=adapter_id,
        adapter_version=adapter_version,
        created_at=created_at or _utc_now_iso(),
        config=cleaned_config,
        config_digest=config_digest,
        policy_digest=policy_digest,
        model_digest=model_digest,
        prompt_digest=prompt_digest,
        resource_limit_digest=resource_limit_digest,
        rubric_digest=rubric_digest,
        test_suite_digest=test_suite_digest,
        threshold_digest=threshold_digest,
        ensemble_digest=ensemble_digest,
        redacted_environment=env_block,
        content_digest=content,
        mechanism_class=mechanism_class,
        determinism=determinism,
        allows_abstention=allows_abstention,
        guarantee_class=guarantee_class,
        decision_space=list(decision_space or []),
        supported_claim_ids=list(supported_claim_ids or []),
        out_of_scope_claim_ids=list(out_of_scope_claim_ids or []),
        assumptions=list(assumptions or []),
        known_blind_spots=list(known_blind_spots or []),
        external_dependencies=list(external_dependencies or []),
        entry_point=entry_point,
        implementation_name=implementation_name or backend_id,
        timeout_ms=resolved_timeout,
        mutation_dimensions=list(mutation_dimensions or []),
        extra=dict(extra or {}),
    )


def snapshot_from_adapter(
    adapter: Any,
    config: Mapping[str, Any] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
) -> ConfigurationSnapshot:
    """Build a snapshot via the adapter's ``snapshot_config`` when available."""
    if hasattr(adapter, "snapshot_config") and callable(adapter.snapshot_config):
        result = adapter.snapshot_config(config, environment=environment)
        if isinstance(result, ConfigurationSnapshot):
            return result
        if isinstance(result, dict):
            return ConfigurationSnapshot.model_validate(result)
        raise TypeError("snapshot_config must return ConfigurationSnapshot or dict")

    manifest = adapter.manifest()
    assurance = getattr(manifest, "assurance", None)
    mechanism = None
    determinism = "deterministic"
    allows_abstention = True
    guarantee_class = "observational"
    decision_space: list[str] = []
    supported_claim_ids: list[str] = []
    out_of_scope: list[str] = []
    entry_point = None
    implementation_name = None
    mutation_dimensions: list[str] = []
    external_deps: list[dict[str, Any]] = []
    known_limits: list[str] = []
    if assurance is not None:
        mechanism = assurance.mechanism_class
        determinism = assurance.determinism
        allows_abstention = assurance.abstention.allows_abstention
        guarantee_class = assurance.decision_semantics.guarantee_class
        decision_space = list(assurance.decision_semantics.decision_space)
        supported_claim_ids = list(assurance.decision_semantics.supported_claim_ids)
        out_of_scope = list(assurance.decision_semantics.out_of_scope_claim_ids)
        entry_point = assurance.verifier_identity.entry_point
        implementation_name = assurance.verifier_identity.implementation_name
        mutation_dimensions = list(assurance.mutation_dimensions)
        external_deps = [dep.model_dump(mode="json", exclude_none=True) for dep in assurance.external_dependencies]
        known_limits = list(assurance.known_limits)

    return build_configuration_snapshot(
        backend_id=str(adapter.backend_id),
        adapter_id=str(adapter.adapter_id),
        adapter_version=str(adapter.adapter_version),
        config=config,
        environment=environment,
        mechanism_class=mechanism,
        determinism=determinism,
        allows_abstention=allows_abstention,
        guarantee_class=guarantee_class,
        decision_space=decision_space,
        supported_claim_ids=supported_claim_ids,
        out_of_scope_claim_ids=out_of_scope,
        assumptions=list(getattr(manifest, "assumptions", []) or []),
        known_blind_spots=known_limits or list(getattr(manifest, "limits", []) or []),
        external_dependencies=external_deps,
        entry_point=entry_point,
        implementation_name=implementation_name,
        mutation_dimensions=mutation_dimensions,
    )
