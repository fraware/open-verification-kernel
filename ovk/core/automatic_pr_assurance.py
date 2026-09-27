"""Automatic source-derived Assurance Diff for ordinary pull-request checks.

This layer composes existing validated primitives:
- governed base GuaranteeSpec manifest;
- governed base FastAPI Protected Effect extraction profile;
- exact base/head Git source materials;
- source-to-Assurance-IR extraction;
- sealed Protected Effect evidence and strict evidence reuse;
- durable GuaranteeAssuranceSnapshot admission; and
- Code Diff + Guarantee Diff + Assurance Diff review composition.

Protected Effect evidence remains shadow/non-controlling. Failure to acquire trusted
materials, semantic authority, or signing identity produces an unavailable
Assurance Diff; it never manufactures PASS evidence.
"""

from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Literal

from pydantic import BaseModel, Field

from ovk import __version__ as OVK_VERSION
from ovk.adapters.z3.resource_binding import (
    RESOURCE_BINDING_CHECKER_ID,
    RESOURCE_BINDING_CHECKER_VERSION,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
)
from ovk.core.attestation_signing import signing_key_from_environment
from ovk.core.bundle import content_digest
from ovk.core.guarantee_assurance_state import (
    GuaranteeAssuranceSnapshot,
    build_guarantee_assurance_snapshot,
)
from ovk.core.guarantee_manifest import (
    GovernedGuaranteeContext,
    load_governed_guarantee_context,
)
from ovk.core.incremental_protected_effect_execution import (
    execute_incremental_protected_effect_assurance,
)
from ovk.core.pr_assurance_review import (
    PullRequestAssuranceReview,
    build_pull_request_assurance_review,
    render_pull_request_assurance_review_markdown,
)
from ovk.core.protected_effect_evaluation import (
    ProtectedEffectIntegrityEvaluation,
    evaluate_protected_effect_integrity,
)
from ovk.core.protected_effect_evidence import (
    PROTECTED_EFFECT_CHECKER_ID,
    PROTECTED_EFFECT_CHECKER_VERSION,
    ProtectedEffectEvidenceCache,
    ProtectedEffectReusePolicy,
    ProtectedEffectRuntimeFingerprint,
    build_execution_fingerprint,
    protected_effect_evaluation_to_evidence,
)
from ovk.core.protected_effect_profile import (
    GovernedProtectedEffectProfileContext,
    ProtectedEffectProfileConfig,
    load_governed_protected_effect_profile_context,
)
from ovk.core.result_cache import DEFAULT_CACHE_DIR, HardenedResultCache


AutomaticAssuranceStatus = Literal[
    "complete",
    "not_applicable",
    "unavailable",
    "error",
]


class AutomaticPullRequestAssuranceResult(BaseModel):
    """Auditable result of automatic source-derived pull-request assurance."""

    status: AutomaticAssuranceStatus
    reason_codes: list[str] = Field(default_factory=list)
    review: PullRequestAssuranceReview | None = None
    markdown: str = ""

    policy_digest: str | None = None
    guarantee_manifest_digest: str | None = None
    source_profile_digest: str | None = None

    source_file_count: int = 0
    source_paths: list[str] = Field(default_factory=list)
    base_assurance_ir_digest: str | None = None
    head_assurance_ir_digest: str | None = None
    base_coverage_status: str | None = None
    head_coverage_status: str | None = None
    base_coverage_unsupported_constructs: list[str] = Field(
        default_factory=list
    )
    head_coverage_unsupported_constructs: list[str] = Field(
        default_factory=list
    )
    base_coverage_assumptions: list[str] = Field(default_factory=list)
    head_coverage_assumptions: list[str] = Field(default_factory=list)

    base_fresh_effects: list[str] = Field(default_factory=list)
    base_reused_effects: list[str] = Field(default_factory=list)
    head_fresh_effects: list[str] = Field(default_factory=list)
    head_reused_effects: list[str] = Field(default_factory=list)

    profile_active_source: str | None = None
    profile_governance_review_required: bool = False
    profile_semantic_changed: bool | None = None
    profile_warning: str | None = None


class _CurrentEvidenceResult(BaseModel):
    evidence: list[Any] = Field(default_factory=list)
    fresh_effects: list[str] = Field(default_factory=list)
    reused_effects: list[str] = Field(default_factory=list)


def _run_git(
    args: list[str],
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None


def _revision_exists(revision: str) -> bool:
    completed = _run_git(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"]
    )
    return completed is not None and completed.returncode == 0


def _paths_at_revision(revision: str) -> list[str] | None:
    completed = _run_git(
        ["git", "ls-tree", "-r", "--name-only", revision]
    )
    if completed is None or completed.returncode != 0:
        return None
    return sorted(
        path.strip()
        for path in completed.stdout.splitlines()
        if path.strip()
    )


def _matches_any(path: str, patterns: list[str]) -> bool:
    candidate = PurePosixPath(path)
    return any(candidate.match(pattern) for pattern in patterns)


def _read_revision_file(
    revision: str,
    path: str,
) -> str | None:
    completed = _run_git(["git", "show", f"{revision}:{path}"])
    if completed is None or completed.returncode != 0:
        return None
    return completed.stdout


def _load_exact_source_materials(
    *,
    repo: str,
    base_sha: str,
    head_sha: str,
    profile: ProtectedEffectProfileConfig,
) -> tuple[AuthMaterials | None, list[str]]:
    """Load exact base/head files selected by the trusted source profile."""

    reasons: list[str] = []
    if not _revision_exists(base_sha):
        reasons.append("base_revision_unavailable")
    if not _revision_exists(head_sha):
        reasons.append("head_revision_unavailable")
    if reasons:
        return None, reasons

    base_paths = _paths_at_revision(base_sha)
    head_paths = _paths_at_revision(head_sha)
    if base_paths is None:
        reasons.append("base_tree_unavailable")
    if head_paths is None:
        reasons.append("head_tree_unavailable")
    if reasons:
        return None, reasons

    selected = sorted(
        {
            path
            for path in (base_paths or []) + (head_paths or [])
            if _matches_any(path, profile.source_paths)
        }
    )
    if len(selected) > profile.max_files:
        return None, ["source_file_limit_exceeded"]

    base_files: dict[str, str] = {}
    head_files: dict[str, str] = {}
    total_bytes = 0

    base_set = set(base_paths or [])
    head_set = set(head_paths or [])
    for path in selected:
        if path in base_set:
            text = _read_revision_file(base_sha, path)
            if text is None:
                return None, [f"base_source_unavailable:{path}"]
            base_files[path] = text
            total_bytes += len(text.encode("utf-8"))
        if path in head_set:
            text = _read_revision_file(head_sha, path)
            if text is None:
                return None, [f"head_source_unavailable:{path}"]
            head_files[path] = text
            total_bytes += len(text.encode("utf-8"))
        if total_bytes > profile.max_total_bytes:
            return None, ["source_byte_limit_exceeded"]

    if not selected:
        return None, ["source_profile_matched_no_files"]

    return (
        AuthMaterials(
            base_files=base_files,
            head_files=head_files,
            repo=repo,
            base_revision=base_sha,
            head_revision=head_sha,
        ),
        [],
    )


def _compile_base_and_head_ir(
    materials: AuthMaterials,
    profile: ProtectedEffectProfileConfig,
):
    runtime_profile = profile.runtime_profile()
    extractor = FastApiDependencyEffectExtractor()

    base_materials = AuthMaterials(
        base_files=dict(materials.base_files),
        head_files=dict(materials.base_files),
        repo=materials.repo,
        base_revision=materials.base_revision,
        head_revision=materials.base_revision,
    )
    base_ir = extractor.compile(base_materials, runtime_profile)
    head_ir = extractor.compile(materials, runtime_profile)
    return base_ir, head_ir


def _default_runtime_fingerprint() -> ProtectedEffectRuntimeFingerprint | None:
    """Return a strict reusable runtime identity only with worker-image identity.

    Fresh checks do not require this value. Historical reuse does.
    """

    worker_image_digest = os.environ.get("OVK_WORKER_IMAGE_DIGEST", "").strip()
    if not worker_image_digest:
        return None

    try:
        import z3  # type: ignore

        z3_version: str | None = z3.get_version_string()
        native_execution = True
    except Exception:
        z3_version = None
        native_execution = False

    environment_payload = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "ovk_version": OVK_VERSION,
    }
    tool_payload = {
        "protected_effect_checker_id": PROTECTED_EFFECT_CHECKER_ID,
        "protected_effect_checker_version": PROTECTED_EFFECT_CHECKER_VERSION,
        "resource_binding_checker_id": RESOURCE_BINDING_CHECKER_ID,
        "resource_binding_checker_version": RESOURCE_BINDING_CHECKER_VERSION,
        "z3_version": z3_version,
    }
    return ProtectedEffectRuntimeFingerprint(
        environment_digest=content_digest(environment_payload),
        tool_digest=content_digest(tool_payload),
        worker_image_digest=worker_image_digest,
        native_execution=native_execution,
    )


def _materialize_current_ir_evidence(
    ir,
    *,
    policy_digest: str,
    cache: ProtectedEffectEvidenceCache | None,
    runtime_provider: Callable[
        [str],
        ProtectedEffectRuntimeFingerprint | None,
    ],
    signing_key: bytes,
) -> _CurrentEvidenceResult:
    """Reuse eligible evidence for one exact IR and freshly verify all misses."""

    evidence_by_effect: dict[str, Any] = {}
    fresh_ids: list[str] = []
    reused_ids: list[str] = []
    runtime_by_effect: dict[str, ProtectedEffectRuntimeFingerprint | None] = {}

    for effect in sorted(
        ir.protected_effects,
        key=lambda item: item.protected_effect_id,
    ):
        effect_id = effect.protected_effect_id
        runtime = runtime_provider(effect_id)
        runtime_by_effect[effect_id] = runtime
        reused = None
        if runtime is not None and cache is not None:
            reused = cache.reuse_for_head(
                head_ir=ir,
                protected_effect_id=effect_id,
                policy_digest=policy_digest,
                current_runtime_fingerprint=runtime,
                reuse_policy=ProtectedEffectReusePolicy(
                    require_signature=True
                ),
                signature_key=signing_key,
                signing_key=signing_key,
            )
        if reused is not None:
            evidence_by_effect[effect_id] = reused
            reused_ids.append(effect_id)
        else:
            fresh_ids.append(effect_id)

    if fresh_ids:
        evaluations = evaluate_protected_effect_integrity(
            ir,
            protected_effect_ids=fresh_ids,
        )
        by_id: dict[str, ProtectedEffectIntegrityEvaluation] = {
            item.protected_effect_id: item
            for item in evaluations
        }
        if set(by_id) != set(fresh_ids):
            raise ValueError(
                "base Protected Effect evaluator result set mismatch"
            )

        for effect_id in fresh_ids:
            evaluation = by_id[effect_id]
            runtime = runtime_by_effect[effect_id]
            fingerprint = (
                build_execution_fingerprint(
                    evaluation,
                    environment_digest=runtime.environment_digest,
                    tool_digest=runtime.tool_digest,
                    worker_image_digest=runtime.worker_image_digest,
                    native_execution=runtime.native_execution,
                )
                if runtime is not None
                else None
            )
            evidence = protected_effect_evaluation_to_evidence(
                ir,
                evaluation,
                policy_digest=policy_digest,
                execution_fingerprint=fingerprint,
                signing_key=signing_key,
            )
            evidence_by_effect[effect_id] = evidence
            if (
                evaluation.status == "pass"
                and fingerprint is not None
                and cache is not None
            ):
                try:
                    cache.put(
                        ir=ir,
                        protected_effect_id=effect_id,
                        policy_digest=policy_digest,
                        execution_fingerprint=fingerprint,
                        evidence=evidence,
                        reuse_policy=ProtectedEffectReusePolicy(
                            require_signature=True
                        ),
                        signature_key=signing_key,
                    )
                except Exception:
                    # Cache writes are optimization only; fresh evidence remains valid.
                    pass

    expected = {
        item.protected_effect_id
        for item in ir.protected_effects
    }
    if set(evidence_by_effect) != expected:
        raise ValueError(
            "current IR evidence does not cover every Protected Effect"
        )

    return _CurrentEvidenceResult(
        evidence=[
            evidence_by_effect[effect_id]
            for effect_id in sorted(evidence_by_effect)
        ],
        fresh_effects=sorted(fresh_ids),
        reused_effects=sorted(reused_ids),
    )


def _assurance_policy_digest(
    *,
    verification_policy: dict[str, Any] | None,
    governance: GovernedGuaranteeContext,
    profile: ProtectedEffectProfileConfig,
) -> str:
    assert governance.active_manifest is not None
    return content_digest(
        {
            "kind": "ovk.protected_effect_assurance_policy.v1",
            "verification_policy": verification_policy or {},
            "guarantee_manifest_digest": (
                governance.active_manifest.manifest_digest
            ),
            "protected_effect_profile_digest": profile.profile_digest,
            "protected_effect_checker": {
                "id": PROTECTED_EFFECT_CHECKER_ID,
                "version": PROTECTED_EFFECT_CHECKER_VERSION,
            },
        }
    )


def _render_profile_governance(
    context: GovernedProtectedEffectProfileContext,
) -> str:
    lines = [
        "### Protected Effect Source Profile",
        "",
        f"Active source: `{context.active_source}`",
        f"Profile available: `{context.profile_available}`",
        (
            "Governance review required: "
            f"`{context.governance_review_required}`"
        ),
    ]
    if context.active_profile is not None:
        lines.append(
            f"Active profile digest: `{context.active_profile.profile_digest}`"
        )
    if context.semantic_profile_changed is not None:
        lines.append(
            "Proposed semantic profile change: "
            f"`{context.semantic_profile_changed}`"
        )
    if context.change_detection_mismatch:
        lines.append(
            "Change metadata mismatch: profile content changed although its "
            "repository path was not reported as changed."
        )
    if context.warning:
        lines.append(f"Warning: {context.warning}")
    lines.extend(
        [
            "",
            (
                "The trusted base profile governs source extraction for this "
                "pull request. Head profile edits are proposals only."
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def build_automatic_pull_request_assurance(
    *,
    repo: str,
    base_sha: str,
    head_sha: str,
    changed_files: list[str],
    verification_policy: dict[str, Any] | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    use_cache: bool = True,
    signing_key: bytes | None = None,
    runtime_fingerprint_provider: Callable[
        [str],
        ProtectedEffectRuntimeFingerprint | None,
    ] | None = None,
) -> AutomaticPullRequestAssuranceResult:
    """Produce source-derived three-diff review under trusted base semantics."""

    governance = load_governed_guarantee_context(
        changed_files=changed_files,
        base_sha=base_sha,
    )
    profile_context = load_governed_protected_effect_profile_context(
        changed_files=changed_files,
        base_sha=base_sha,
    )

    review_blockers: list[str] = []
    if not governance.assurance_target_available:
        review_blockers.append("trusted_guarantee_manifest_unavailable")

    specs = (
        governance.require_assurance_specs()
        if governance.assurance_target_available
        else []
    )
    if not specs:
        review = build_pull_request_assurance_review(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            changed_files=changed_files,
            governance=governance,
        )
        markdown = (
            render_pull_request_assurance_review_markdown(review)
            + "\n"
            + _render_profile_governance(profile_context)
        )
        return AutomaticPullRequestAssuranceResult(
            status="not_applicable",
            reason_codes=["no_active_guarantees"],
            review=review,
            markdown=markdown,
            guarantee_manifest_digest=(
                governance.active_manifest.manifest_digest
                if governance.active_manifest is not None
                else None
            ),
            profile_active_source=profile_context.active_source,
            profile_governance_review_required=(
                profile_context.governance_review_required
            ),
            profile_semantic_changed=profile_context.semantic_profile_changed,
            profile_warning=profile_context.warning,
        )

    if not profile_context.profile_available:
        review_blockers.append("trusted_protected_effect_profile_unavailable")

    selected_key = (
        signing_key
        if signing_key is not None
        else signing_key_from_environment()
    )
    if selected_key is None:
        review_blockers.append("evidence_signing_key_unavailable")

    if review_blockers:
        review = build_pull_request_assurance_review(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            changed_files=changed_files,
            governance=governance,
        )
        markdown = (
            render_pull_request_assurance_review_markdown(review)
            + "\n"
            + _render_profile_governance(profile_context)
            + "\nAutomatic source assurance unavailable: "
            + ", ".join(sorted(set(review_blockers)))
            + "\n"
        )
        return AutomaticPullRequestAssuranceResult(
            status="unavailable",
            reason_codes=sorted(set(review_blockers)),
            review=review,
            markdown=markdown,
            guarantee_manifest_digest=(
                governance.active_manifest.manifest_digest
                if governance.active_manifest is not None
                else None
            ),
            profile_active_source=profile_context.active_source,
            profile_governance_review_required=(
                profile_context.governance_review_required
            ),
            profile_semantic_changed=profile_context.semantic_profile_changed,
            profile_warning=profile_context.warning,
        )

    assert selected_key is not None
    profile = profile_context.require_active_profile()
    materials, acquisition_reasons = _load_exact_source_materials(
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        profile=profile,
    )
    if materials is None:
        review = build_pull_request_assurance_review(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            changed_files=changed_files,
            governance=governance,
        )
        reasons = sorted(set(acquisition_reasons))
        markdown = (
            render_pull_request_assurance_review_markdown(review)
            + "\n"
            + _render_profile_governance(profile_context)
            + "\nAutomatic source assurance unavailable: "
            + ", ".join(reasons)
            + "\n"
        )
        return AutomaticPullRequestAssuranceResult(
            status="unavailable",
            reason_codes=reasons,
            review=review,
            markdown=markdown,
            guarantee_manifest_digest=governance.active_manifest.manifest_digest,
            source_profile_digest=profile.profile_digest,
            profile_active_source=profile_context.active_source,
            profile_governance_review_required=(
                profile_context.governance_review_required
            ),
            profile_semantic_changed=profile_context.semantic_profile_changed,
            profile_warning=profile_context.warning,
        )

    try:
        base_ir, head_ir = _compile_base_and_head_ir(materials, profile)
        policy_digest = _assurance_policy_digest(
            verification_policy=verification_policy,
            governance=governance,
            profile=profile,
        )
        cache = (
            ProtectedEffectEvidenceCache(HardenedResultCache(cache_dir))
            if use_cache
            else None
        )
        runtime_provider = (
            runtime_fingerprint_provider
            if runtime_fingerprint_provider is not None
            else (lambda _effect_id: _default_runtime_fingerprint())
        )

        base_execution = _materialize_current_ir_evidence(
            base_ir,
            policy_digest=policy_digest,
            cache=cache,
            runtime_provider=runtime_provider,
            signing_key=selected_key,
        )
        base_snapshot: GuaranteeAssuranceSnapshot = (
            build_guarantee_assurance_snapshot(
                base_ir,
                specs,
                base_execution.evidence,
                policy_digest=policy_digest,
                signature_key=selected_key,
            )
        )

        head_execution = execute_incremental_protected_effect_assurance(
            base_ir,
            head_ir,
            policy_digest=policy_digest,
            runtime_fingerprint_provider=runtime_provider,
            evidence_cache=cache,
            reuse_policy=ProtectedEffectReusePolicy(
                require_signature=True
            ),
            signature_key=selected_key,
            signing_key=selected_key,
        )
        head_snapshot = build_guarantee_assurance_snapshot(
            head_ir,
            specs,
            head_execution.evidence,
            policy_digest=policy_digest,
            signature_key=selected_key,
        )

        review = build_pull_request_assurance_review(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            changed_files=changed_files,
            governance=governance,
            base_snapshot=base_snapshot,
            head_snapshot=head_snapshot,
        )
        markdown = (
            render_pull_request_assurance_review_markdown(review)
            + "\n"
            + _render_profile_governance(profile_context)
        )
        return AutomaticPullRequestAssuranceResult(
            status="complete",
            review=review,
            markdown=markdown,
            policy_digest=policy_digest,
            guarantee_manifest_digest=governance.active_manifest.manifest_digest,
            source_profile_digest=profile.profile_digest,
            source_file_count=len(materials.paths),
            source_paths=materials.paths,
            base_assurance_ir_digest=base_ir.assurance_ir_digest,
            head_assurance_ir_digest=head_ir.assurance_ir_digest,
            base_coverage_status=base_ir.coverage.status,
            head_coverage_status=head_ir.coverage.status,
            base_coverage_unsupported_constructs=list(
                base_ir.coverage.unsupported_constructs
            ),
            head_coverage_unsupported_constructs=list(
                head_ir.coverage.unsupported_constructs
            ),
            base_coverage_assumptions=list(base_ir.coverage.assumptions),
            head_coverage_assumptions=list(head_ir.coverage.assumptions),
            base_fresh_effects=base_execution.fresh_effects,
            base_reused_effects=base_execution.reused_effects,
            head_fresh_effects=head_execution.fresh_effects,
            head_reused_effects=head_execution.reused_effects,
            profile_active_source=profile_context.active_source,
            profile_governance_review_required=(
                profile_context.governance_review_required
            ),
            profile_semantic_changed=profile_context.semantic_profile_changed,
            profile_warning=profile_context.warning,
        )
    except Exception as error:
        review = build_pull_request_assurance_review(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            changed_files=changed_files,
            governance=governance,
        )
        reason = f"{type(error).__name__}:{error}"
        markdown = (
            render_pull_request_assurance_review_markdown(review)
            + "\n"
            + _render_profile_governance(profile_context)
            + "\nAutomatic source assurance error: "
            + reason
            + "\n"
        )
        return AutomaticPullRequestAssuranceResult(
            status="error",
            reason_codes=[reason],
            review=review,
            markdown=markdown,
            guarantee_manifest_digest=governance.active_manifest.manifest_digest,
            source_profile_digest=profile.profile_digest,
            profile_active_source=profile_context.active_source,
            profile_governance_review_required=(
                profile_context.governance_review_required
            ),
            profile_semantic_changed=profile_context.semantic_profile_changed,
            profile_warning=profile_context.warning,
        )
