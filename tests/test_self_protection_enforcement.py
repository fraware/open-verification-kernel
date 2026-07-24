"""Self-protection vertical-slice enforcement tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.adapters.self_protection import build_self_protection_registry
from ovk.core.adapter_runtime import execute_obligations
from ovk.core.backend_control_plane import BackendControlPlane
from ovk.core.execution_models import ExecutionBudget, ExecutionContext
from ovk.core.models import MergeRecommendation, VerificationStatus
from ovk.core.router import RoutingConfig, route_obligation
from ovk.core.self_protection_compiler import COMPILER_ID, compile_self_protection_obligation


def _load_example(name: str) -> dict:
    path = Path("examples/no_agent_self_approval") / name
    if not path.exists():
        path = Path("ovk/package_data/examples/no_agent_self_approval") / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_self_protection_compiler_requires_base_and_head_metadata() -> None:
    data = _load_example("input_gate_removed.json")
    obligation = compile_self_protection_obligation(
        data,
        repo="r",
        head_sha="head",
        base_sha="base",
        metadata_trusted=True,
    )
    assert obligation.compiler_id == COMPILER_ID
    before = next(item for item in obligation.materials if item.material_id == "self-protection-before")
    after = next(item for item in obligation.materials if item.material_id == "self-protection-after")
    assert before.kind == "branch_protection"
    assert after.kind == "branch_protection"
    assert before.trusted is True
    assert after.trusted is True


def test_missing_base_metadata_is_unknown_coverage() -> None:
    data = {
        "actor": {"type": "ai_agent", "id": "bot"},
        "changed_files": [".github/workflows/ci.yml"],
        "after": {"required_checks": ["ovk-verify"]},
    }
    obligation = compile_self_protection_obligation(data, repo="r", head_sha="h", base_sha="b")
    assert obligation.coverage.status in {"partial", "unknown"}
    assert any("before" in warning for warning in obligation.coverage.warnings)


def test_enforced_self_protection_blocks_gate_removal() -> None:
    data = _load_example("input_gate_removed.json")
    evidence_items = execute_obligations(
        [{"lane": "self_protection", "input": data, "intent_id": "agent-cannot-disable-own-ci-gate"}],
        {},
        repo="example/repo",
        head_sha="abc",
        base_sha="def",
        use_cache=False,
        policy={
            "routing": {
                "enforced_lanes": ["self_protection"],
                "prefer_deterministic": True,
                "allow_fallback": False,
            }
        },
    )
    evidence = evidence_items[0]
    assert evidence.routing_enforced is True
    assert evidence.schema_version == "ovk.evidence.v3"
    assert evidence.decision.get("merge_recommendation") == "block"
    assert evidence.selected_backends
    assert "self-protection-deterministic" in (evidence.selected_backends or []) or "opa-native" in (
        evidence.selected_backends or []
    )


def test_untrusted_metadata_cannot_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    data = (
        _load_example("input_gate_preserved.json")
        if Path("examples/no_agent_self_approval/input_gate_preserved.json").exists()
        or Path("ovk/package_data/examples/no_agent_self_approval/input_gate_preserved.json").exists()
        else {
            "actor": {"type": "ai_agent", "id": "bot"},
            "changed_files": ["README.md"],
            "before": {"required_checks": ["ovk-verify"]},
            "after": {"required_checks": ["ovk-verify"]},
            "ovk_gate_name": "ovk-verify",
        }
    )
    if isinstance(data, str):
        data = _load_example("input_gate_preserved.json")
    evidence_items = execute_obligations(
        [{"lane": "self_protection", "input": data}],
        {},
        repo="example/repo",
        head_sha="abc",
        base_sha="def",
        use_cache=False,
        policy={
            "routing": {"enforced_lanes": ["self_protection"], "prefer_deterministic": True, "metadata_trusted": False},
            "trust": {"metadata_trusted": False},
        },
    )
    evidence = evidence_items[0]
    assert evidence.decision.get("merge_recommendation") != "allow"


def test_opa_unavailable_does_not_implicitly_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    import ovk.adapters.self_protection.opa_adapter as opa_mod

    monkeypatch.setattr(opa_mod, "opa_available", lambda: False)
    data = _load_example("input_gate_removed.json")
    registry = build_self_protection_registry()
    obligation = compile_self_protection_obligation(data, repo="r", head_sha="h", base_sha="b")
    budget = ExecutionBudget(
        total_wall_time_seconds=30,
        per_backend_wall_time_seconds=10,
        max_memory_mb=256,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["opa-native"],
        denied_backends=["self-protection-deterministic"],
    )
    context = ExecutionContext(subject=obligation.subject, budget=budget)
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(max_selected_backends=1, allow_fallback=False),
    )
    assert all(item.backend != "self-protection-deterministic" for item in routing.selected)
    if routing.selected:
        record = BackendControlPlane().execute(obligation, routing, registry=registry)
        assert record.merge_recommendation != MergeRecommendation.ALLOW
        assert record.results[0].status in {VerificationStatus.UNKNOWN, VerificationStatus.ERROR}
    else:
        assert routing.selected == []
