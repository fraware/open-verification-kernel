"""MCP server surface for Open Verification Kernel."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ovk.adapters.workflow.diff_extract import workflow_inputs_from_diff
from ovk.adapters.workflow.yaml_extract import workflow_yaml_to_ci_secrets_input
from ovk.core.bundle import make_bundle
from ovk.core.changed_files import load_changed_files
from ovk.core.decision import decide
from ovk.core.diff_parser import is_unified_diff
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.models import EvidenceBundle
from ovk.core.multi_lane import evaluate_lane
from ovk.core.planner import plan_from_changed_files, plan_from_diff_text
from ovk.core.release_metadata import release_metadata
from ovk.paths import resource_path


TOOLS = [
    "ovk.extract_intents",
    "ovk.plan_from_diff",
    "ovk.extract_workflow_yaml",
    "ovk.extract_workflows_from_diff",
    "ovk.rank_intents",
    "ovk.list_capabilities",
    "ovk.select_backends",
    "ovk.compile_obligation",
    "ovk.run_verification",
    "ovk.explain_result",
    "ovk.generate_regression_artifact",
    "ovk.create_evidence_bundle",
    "ovk.get_merge_recommendation",
]


def extract_intents(changed_files: list[str] | str | Path) -> dict[str, Any]:
    """Extract candidate intents from changed file paths."""
    if isinstance(changed_files, (str, Path)):
        path = Path(changed_files)
        text = path.read_text(encoding="utf-8")
        if is_unified_diff(text):
            plan = plan_from_diff_text(text)
        else:
            plan = plan_from_changed_files(load_changed_files(path))
    else:
        plan = plan_from_changed_files(changed_files)
    payload = {
        "intents": plan.get("candidate_intents", []),
        "intent_plans": plan.get("intent_plans", []),
        "surfaces": plan.get("surfaces", []),
    }
    if plan.get("workflow_inputs"):
        payload["workflow_inputs"] = plan["workflow_inputs"]
    return payload


def plan_from_diff(diff_text: str, *, trust_context: str = "untrusted_fork_pr") -> dict[str, Any]:
    """Create a verification plan from unified diff text."""
    return plan_from_diff_text(diff_text, trust_context=trust_context)


def extract_workflow_yaml(yaml_text: str, *, workflow_id: str = "workflow") -> dict[str, Any]:
    """Convert workflow YAML into a CI secrets lane input."""
    return workflow_yaml_to_ci_secrets_input(yaml_text, workflow_id=workflow_id)


def extract_workflows_from_diff(diff_text: str, *, trust_context: str = "untrusted_fork_pr") -> dict[str, Any]:
    """Extract CI secrets lane inputs from workflow files in a unified diff."""
    return {
        "workflow_inputs": workflow_inputs_from_diff(diff_text, trust_context=trust_context),
    }


def list_capabilities() -> dict[str, Any]:
    """Return release metadata and installed backend capability manifests."""
    from ovk.core.capabilities import CapabilityRegistry

    metadata = release_metadata()
    registry = CapabilityRegistry.from_directory(resource_path("adapters"))
    return {
        **metadata,
        "release": metadata,
        "capabilities": registry.all(),
    }


def run_verification(lane: str, input_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    """Run a lane or backend evaluator and return evidence JSON."""
    evidence = evaluate_lane(
        lane,
        input_data,
        repo=str(kwargs.get("repo", "unknown/repo")),
        head_sha=str(kwargs.get("head_sha", "unknown")),
        base_sha=kwargs.get("base_sha"),
        input_format=str(kwargs.get("input_format", "infra")),
        policy_path=Path(str(kwargs["policy_path"])) if kwargs.get("policy_path") else None,
    )
    return evidence.model_dump(mode="json")


def create_evidence_bundle(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    """Create an evidence bundle from evidence dicts."""
    from ovk.core.models import VerificationEvidence

    evidence = [VerificationEvidence.model_validate(item) for item in evidence_items]
    return make_bundle(evidence).model_dump(mode="json")


def get_merge_recommendation(evidence_bundle: dict[str, Any]) -> dict[str, Any]:
    """Compute merge recommendation from an evidence bundle."""
    bundle = EvidenceBundle.model_validate(evidence_bundle)
    recommendation = decide(bundle, enforce=True)
    quality = build_evidence_quality_report(bundle)
    return {
        "merge_recommendation": recommendation.value,
        "quality_passed": quality.passed,
        "quality_issues": [issue.to_dict() for issue in quality.issues],
    }


def explain_result(evidence_bundle: dict[str, Any]) -> dict[str, Any]:
    """Summarize evidence bundle decisions, counterexamples, and repair hints."""
    from ovk.core.counterexample_translator import repair_hint_for_counterexample

    bundle = EvidenceBundle.model_validate(evidence_bundle)
    counterexamples = [
        counterexample
        for evidence in bundle.evidence
        for counterexample in evidence.counterexamples
    ]
    repair_hints = [repair_hint_for_counterexample(item) for item in counterexamples]
    return {
        "bundle_id": bundle.bundle_id,
        "decision": bundle.decision,
        "merge_recommendation": bundle.decision.get("merge_recommendation", "require_human_review"),
        "counterexamples": counterexamples,
        "repair_hints": repair_hints,
        "repair_plan": {
            "blocked": bundle.decision.get("merge_recommendation") == "block",
            "actions": repair_hints,
        },
    }


def rank_intents_tool(changed_files: list[str] | None = None, diff_text: str | None = None) -> dict[str, Any]:
    """Rank candidate intents by risk."""
    from ovk.core.context import build_repository_context
    from ovk.core.risk_ranker import rank_intents

    if diff_text:
        plan = plan_from_diff_text(diff_text)
        files = plan.get("changed_files", [])
    else:
        plan = plan_from_changed_files(changed_files or [])
        files = changed_files or []
    context = build_repository_context(changed_files=files)
    ranked = rank_intents(plan.get("candidate_intents", []), context=context)
    return {"plan": plan, "ranked_intents": ranked}


def compile_obligation(
    changed_files: list[str] | None = None,
    diff_text: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Compile lane obligations from a plan."""
    from ovk.core.context import build_repository_context
    from ovk.core.obligation_compiler import compile_obligations

    if diff_text:
        plan = plan_from_diff_text(diff_text)
        files = plan.get("changed_files", [])
    else:
        plan = plan_from_changed_files(changed_files or [])
        files = changed_files or []
    context = build_repository_context(
        changed_files=files,
        repo=str(kwargs.get("repo", "unknown/repo")),
        head_sha=str(kwargs.get("head_sha", "unknown")),
        base_sha=kwargs.get("base_sha"),
    )
    obligations = compile_obligations(plan, context=context, diff_text=diff_text)
    return {"obligations": obligations}


def select_backends(
    intent_id: str,
    *,
    changed_files: list[str] | None = None,
) -> dict[str, Any]:
    """Select backends for one intent using capability manifests and repo memory."""
    from ovk.core.capabilities import CapabilityRegistry
    from ovk.core.intent_registry import IntentRegistry
    from ovk.core.repo_memory import router_historical_priors
    from ovk.core.router import route_intent
    from ovk.core.surface_routing import surface_backend_bonuses

    intents = IntentRegistry.from_directory(resource_path("templates"))
    capabilities = CapabilityRegistry.from_directory(resource_path("adapters"))
    intent = intents.get(intent_id)
    if intent is None:
        raise ValueError(f"unknown intent: {intent_id}")
    bonuses = surface_backend_bonuses(changed_files or [])
    return route_intent(
        intent,
        capabilities.all(),
        historical_priors=router_historical_priors(),
        surface_bonuses=bonuses,
    )


def generate_regression_artifact(evidence_bundle: dict[str, Any]) -> dict[str, Any]:
    """Generate regression artifacts from bundle counterexamples."""
    from ovk.core.counterexample_translator import generate_regression_artifacts

    bundle = EvidenceBundle.model_validate(evidence_bundle)
    return {"artifacts": generate_regression_artifacts(bundle)}
