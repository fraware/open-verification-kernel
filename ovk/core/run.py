"""Execute verification plans (`ovk run`)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk.core.context import RepositoryContext, build_repository_context
from ovk.core.kernel import KernelResult, execute_kernel
from ovk.core.lane_compiler import build_plan_from_inputs
from ovk.core.models import EvidenceBundle
from ovk.core.router import VerificationBudget


@dataclass(frozen=True)
class RunResult:
    """Result of executing a verification plan."""

    bundle: EvidenceBundle
    plan: dict[str, Any]
    ranked_intents: list[dict[str, Any]]
    routing: list[dict[str, Any]]
    obligations: list[dict[str, Any]]
    elapsed_ms: float


def _kernel_to_run(result: KernelResult) -> RunResult:
    return RunResult(
        bundle=result.bundle,
        plan=result.plan,
        ranked_intents=result.ranked_intents,
        routing=result.routing,
        obligations=result.obligations,
        elapsed_ms=result.elapsed_ms,
    )


def run_from_plan_dict(
    plan: dict[str, Any],
    *,
    context: RepositoryContext,
    diff_text: str | None = None,
    budget: VerificationBudget | None = None,
    metadata: dict[str, Any] | None = None,
    check_metadata_path: Path | None = None,
    github_event_path: Path | None = None,
    use_cache: bool = True,
    parallel: bool = True,
) -> RunResult:
    """Execute a plan with routing metadata and lane evaluation."""
    result = execute_kernel(
        changed_files=context.changed_files,
        diff_text=diff_text,
        metadata=metadata,
        check_metadata_path=check_metadata_path,
        github_event_path=github_event_path,
        context=context,
        budget=budget,
        use_cache=use_cache,
        parallel=parallel,
    )
    # Preserve caller-supplied plan fields (e.g. from `ovk plan` JSON) for traceability.
    merged_plan = {**plan, **{key: result.plan[key] for key in result.plan if key not in plan}}
    return RunResult(
        bundle=result.bundle,
        plan=merged_plan,
        ranked_intents=result.ranked_intents,
        routing=result.routing,
        obligations=result.obligations,
        elapsed_ms=result.elapsed_ms,
    )


def run_from_changed_files(
    changed_files: list[str],
    *,
    diff_text: str | None = None,
    context: RepositoryContext | None = None,
    budget: VerificationBudget | None = None,
    github_event_path: Path | None = None,
    check_metadata_path: Path | None = None,
    use_cache: bool = True,
    parallel: bool = True,
) -> RunResult:
    """Build and execute a verification plan from changed files."""
    ctx = context or build_repository_context(
        changed_files=changed_files,
        github_event_path=github_event_path,
        check_metadata_path=check_metadata_path,
    )
    plan = build_plan_from_inputs(changed_files=changed_files, diff_text=diff_text)
    return run_from_plan_dict(
        plan,
        context=ctx,
        diff_text=diff_text,
        budget=budget,
        github_event_path=github_event_path,
        check_metadata_path=check_metadata_path,
        use_cache=use_cache,
        parallel=parallel,
    )
