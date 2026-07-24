"""PR7 — isolated deterministic worker tests."""

from __future__ import annotations

import json
from pathlib import Path


from ovk.adapters.authorization.deterministic_adapter import AuthorizationDeterministicAdapter
from ovk.core.backend_control_plane import BackendControlPlane
from ovk.core.deterministic_evaluators import evaluate_deterministic
from ovk.core.execution_budget import LocalSubprocessWorker
from ovk.core.execution_models import ExecutionBudget
from ovk.core.worker_runner import run_evaluator_in_worker


def test_deterministic_adapter_requires_worker() -> None:
    adapter = AuthorizationDeterministicAdapter()
    obligation = adapter.compile(
        __import__(
            "ovk.core.authorization_compiler", fromlist=["compile_authorization_obligation"]
        ).compile_authorization_obligation(
            json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8")),
            repo="r",
            head_sha="h",
        ),
        __import__("ovk.core.routing_pipeline", fromlist=["route_compiled_obligation"]).route_compiled_obligation(
            __import__(
                "ovk.core.authorization_compiler", fromlist=["compile_authorization_obligation"]
            ).compile_authorization_obligation(
                json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8")),
                repo="r",
                head_sha="h",
            ),
            lane="authorization",
        ),
    )
    budget = ExecutionBudget(
        total_wall_time_seconds=30,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
    )
    raw = adapter.run(obligation, budget, worker=None)
    assert raw.termination == "tool_error"
    assert raw.stderr and ("BackendWorker" in raw.stderr or "missing worker" in raw.stderr)


def test_deterministic_worker_runs_in_subprocess() -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    worker = LocalSubprocessWorker()
    outcome = run_evaluator_in_worker(
        worker,
        evaluator_id="authorization-deterministic",
        payload={"input": data, "mode": "deterministic"},
        timeout_seconds=30.0,
    )
    assert not outcome.timed_out
    assert not outcome.worker_rejected
    assert outcome.raw_result["status"] == "fail"


def test_zero_budget_rejected_before_worker_spawn() -> None:
    worker = LocalSubprocessWorker()
    outcome = run_evaluator_in_worker(
        worker,
        evaluator_id="authorization-deterministic",
        payload={"input": {}},
        timeout_seconds=0.0,
    )
    assert outcome.termination == "timeout"
    assert outcome.worker_rejected


def test_control_plane_passes_worker_to_deterministic_adapter() -> None:
    from ovk.adapters.authorization import build_authorization_registry
    from ovk.core.authorization_compiler import compile_authorization_obligation
    from ovk.core.routing_pipeline import route_compiled_obligation

    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    routing = route_compiled_obligation(
        obligation,
        lane="authorization",
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    record = BackendControlPlane(worker=LocalSubprocessWorker()).execute(
        obligation,
        routing,
        registry=build_authorization_registry(),
    )
    assert record.results
    assert record.results[0].status.value == "fail"


def test_evaluator_registry_covers_all_deterministic_backends() -> None:
    for evaluator_id in (
        "authorization-deterministic",
        "self-protection-deterministic",
        "infrastructure-deterministic",
        "ci-secrets-deterministic",
        "deployment-deterministic",
    ):
        result = evaluate_deterministic(evaluator_id, {"input": {}})
        assert "raw_result" in result
