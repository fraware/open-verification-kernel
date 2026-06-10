import json
from pathlib import Path

from ovk.core.context import budget_from_policy, build_repository_context
from ovk.core.kernel import execute_kernel
from ovk.core.obligation_compiler import ObligationCompilerRegistry
from ovk.core.router import route_intent
from ovk.core.capabilities import CapabilityRegistry


COMBINED_DIFF = Path("examples/multi_surface/pr_combined.diff")


def test_kernel_multi_surface_runs_only_affected_lanes() -> None:
    diff_text = COMBINED_DIFF.read_text(encoding="utf-8")
    result = execute_kernel(diff_text=diff_text, use_cache=False, repo="test/repo", head_sha="deadbeef")
    lanes = {obligation["lane"] for obligation in result.obligations}
    assert "ci_secrets" in lanes
    assert "infrastructure" in lanes
    assert "authorization" in lanes
    assert "deployment" not in lanes
    assert len(result.bundle.evidence) == len(result.obligations)
    assert result.routing
    assert result.ranked_intents


def test_kernel_attaches_routing_metadata_to_evidence() -> None:
    diff_text = COMBINED_DIFF.read_text(encoding="utf-8")
    result = execute_kernel(diff_text=diff_text, use_cache=False, repo="test/repo", head_sha="deadbeef")
    routed = [
        artifact
        for evidence in result.bundle.evidence
        for artifact in evidence.generated_artifacts
        if artifact.get("kind") == "backend_routing"
    ]
    assert routed
    assert routed[0]["selected"]


def test_budget_from_policy_denies_expensive_backends() -> None:
    policy = {
        "budget": {
            "max_wall_time_seconds": 10,
            "denied_backends": ["dafny", "lean"],
        }
    }
    budget = budget_from_policy(policy)
    registry = CapabilityRegistry.from_directory(Path("adapters"))
    intent = json.loads(Path("templates/authorization/no_admin_route_bypass.intent.json").read_text(encoding="utf-8"))
    decision = route_intent(intent, registry.all(), budget=budget)
    rejected = {item["backend"] for item in decision["rejected"]}
    assert "dafny" in rejected or "lean" in rejected


def test_obligation_registry_maps_intents_to_lanes() -> None:
    registry = ObligationCompilerRegistry.default()
    assert registry.lane_for_intent("no-secrets-in-untrusted-context") == "ci_secrets"
    assert registry.lane_for_intent("no-admin-route-bypass") == "authorization"


def test_rank_intents_prioritizes_critical_on_bot_actor() -> None:
    from ovk.core.risk_ranker import rank_intents

    context = build_repository_context(
        changed_files=[".github/workflows/ci.yml", "infra/main.tf", "src/routes/admin.ts"],
        repo="org/repo",
    )
    context.actor_type = "bot"
    ranked = rank_intents(
        [
            "no-public-sensitive-resource",
            "no-secrets-in-untrusted-context",
            "no-admin-route-bypass",
        ],
        context=context,
    )
    assert ranked[0]["intent_id"] in {
        "no-secrets-in-untrusted-context",
        "no-admin-route-bypass",
    }
