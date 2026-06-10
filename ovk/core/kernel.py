"""Kernel orchestration: infer → rank → route → compile → run → decide."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk.core.adapter_runtime import execute_obligations
from ovk.core.bundle import make_bundle
from ovk.core.capabilities import CapabilityRegistry
from ovk.core.compilation_evidence import compilation_failure_evidence
from ovk.core.context import RepositoryContext, budget_from_policy, build_repository_context
from ovk.core.intent_registry import IntentRegistry
from ovk.core.lane_compiler import build_plan_from_inputs
from ovk.core.models import EvidenceBundle
from ovk.core.obligation_compiler import ObligationCompilerRegistry
from ovk.core.render import render_bundle_markdown
from ovk.core.repo_memory import router_historical_priors
from ovk.core.surface_routing import surface_backend_bonuses
from ovk.core.result_cache import DEFAULT_CACHE_DIR
from ovk.core.risk_ranker import rank_intents
from ovk.core.router import VerificationBudget, route_intent


@dataclass(frozen=True)
class KernelResult:
    """Full kernel execution result."""

    bundle: EvidenceBundle
    plan: dict[str, Any]
    context: RepositoryContext
    ranked_intents: list[dict[str, Any]]
    routing: list[dict[str, Any]]
    obligations: list[dict[str, Any]]
    markdown: str
    elapsed_ms: float


def _routing_for_plan(
    plan: dict[str, Any],
    *,
    context: RepositoryContext,
    budget: VerificationBudget | None,
    template_dir: Path,
    adapter_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Build ranked routing decisions for all candidate intents."""
    intent_registry = IntentRegistry.from_directory(template_dir)
    capability_registry = CapabilityRegistry.from_directory(adapter_dir)
    historical = router_historical_priors()
    effective_budget = budget or budget_from_policy(context.policy)
    bonuses = surface_backend_bonuses(context.changed_files)

    ranked = rank_intents(plan.get("candidate_intents", []), context=context)
    routing: list[dict[str, Any]] = []
    routing_by_intent: dict[str, dict[str, Any]] = {}

    for item in ranked:
        intent_id = item["intent_id"]
        intent = intent_registry.get(intent_id)
        if intent is None:
            continue
        decision = route_intent(
            intent,
            capability_registry.all(),
            budget=effective_budget,
            historical_priors=historical,
            surface_bonuses=bonuses,
        )
        routing.append(decision)
        routing_by_intent[intent_id] = decision

    return routing, routing_by_intent


def execute_kernel(
    *,
    changed_files: list[str] | None = None,
    diff_text: str | None = None,
    metadata: dict[str, Any] | None = None,
    check_metadata_path: Path | None = None,
    github_event_path: Path | None = None,
    context: RepositoryContext | None = None,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
    budget: VerificationBudget | None = None,
    cache_dir: Path | None = DEFAULT_CACHE_DIR,
    use_cache: bool = True,
    parallel: bool = True,
    template_dir: Path = Path("templates"),
    adapter_dir: Path = Path("adapters"),
) -> KernelResult:
    """Run the full OVK kernel pipeline for a repository change."""
    started = time.perf_counter()
    plan = build_plan_from_inputs(changed_files=changed_files, diff_text=diff_text)

    ctx = context or build_repository_context(
        changed_files=plan.get("changed_files", changed_files or []),
        github_event_path=github_event_path,
        check_metadata_path=check_metadata_path,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
    )

    routing, routing_by_intent = _routing_for_plan(
        plan,
        context=ctx,
        budget=budget,
        template_dir=template_dir,
        adapter_dir=adapter_dir,
    )

    compiler = ObligationCompilerRegistry.default()
    obligations = compiler.compile(
        plan,
        context=ctx,
        diff_text=diff_text,
        metadata=metadata,
        check_metadata_path=check_metadata_path,
        github_event_path=github_event_path,
    )

    if not obligations:
        bundle = make_bundle(
            [
                compilation_failure_evidence(
                    repo=ctx.repo,
                    head_sha=ctx.head_sha,
                    base_sha=ctx.base_sha,
                    intents=list(plan.get("candidate_intents", [])),
                    reason="No lane inputs could be compiled for the detected change surfaces.",
                )
            ]
        )
    else:
        evidence_items = execute_obligations(
            obligations,
            routing_by_intent,
            repo=ctx.repo,
            head_sha=ctx.head_sha,
            base_sha=ctx.base_sha,
            cache_dir=cache_dir,
            use_cache=use_cache,
            parallel=parallel,
        )
        bundle = make_bundle(evidence_items)

    ranked = rank_intents(plan.get("candidate_intents", []), context=ctx)
    elapsed_ms = (time.perf_counter() - started) * 1000
    return KernelResult(
        bundle=bundle,
        plan=plan,
        context=ctx,
        ranked_intents=ranked,
        routing=routing,
        obligations=obligations,
        markdown=render_bundle_markdown(bundle),
        elapsed_ms=elapsed_ms,
    )
