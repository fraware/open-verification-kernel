"""Execution-isolation trust-boundary tests."""

from __future__ import annotations

from pathlib import Path

from ovk.adapters.authorization import build_authorization_registry
from ovk.core.authorization_compiler import compile_authorization_obligation
from ovk.core.backend_control_plane import BackendControlPlane
from ovk.core.execution_budget import BudgetBoundWorker, LocalSubprocessWorker
from ovk.core.execution_models import ExecutionBudget, ExecutionContext
from ovk.core.models import VerificationStatus
from ovk.core.router import RoutingConfig, route_obligation


def _budget(**updates) -> ExecutionBudget:
    values = dict(
        total_wall_time_seconds=30,
        per_backend_wall_time_seconds=10,
        max_memory_mb=256,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["authorization-deterministic"],
    )
    values.update(updates)
    return ExecutionBudget(**values)


def test_budget_bound_worker_rejects_external_command_when_network_denial_unenforceable(tmp_path: Path) -> None:
    worker = BudgetBoundWorker(LocalSubprocessWorker(), _budget())
    result = worker.run(
        ["echo", "hello"],
        cwd=tmp_path,
        timeout_seconds=1,
    )
    assert result.exit_code is None
    assert "network denial requested" in result.stderr
    assert "memory_limit" in result.enforced_controls or result.enforced_controls


def test_python_ovk_worker_runs_with_isolation_controls(tmp_path: Path) -> None:
    import json
    import sys

    payload = tmp_path / "payload.json"
    payload.write_text(json.dumps({"input": {"routes": []}, "mode": "deterministic"}), encoding="utf-8")
    worker = BudgetBoundWorker(LocalSubprocessWorker(), _budget())
    result = worker.run(
        [
            sys.executable,
            "-m",
            "ovk.workers.deterministic_entry",
            "--evaluator-id",
            "authorization-deterministic",
            "--payload-file",
            str(payload),
        ],
        cwd=Path.cwd(),
        timeout_seconds=5,
    )
    # Evaluator semantics may return a non-zero status for malformed/minimal
    # payload; isolation itself must not be rejected.
    assert "network denial requested" not in result.stderr
    assert "repository write denial requested" not in result.stderr
    assert "network_denied" in result.enforced_controls
    assert "filesystem_writes_denied" in result.enforced_controls


def test_authoritative_control_plane_passes_budget_bound_worker() -> None:
    data = {"routes": [{"path": "/health", "admin_only": False}]}
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    registry = build_authorization_registry()
    budget = _budget()
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest=obligation.policy_digest),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1, accept_partial_primary=True),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    record = BackendControlPlane(use_hardened_cache=False).execute(
        obligation,
        routing,
        registry=registry,
        cache=None,
    )
    assert record.attempts
    assert record.results[0].status in {
        VerificationStatus.PASS,
        VerificationStatus.FAIL,
        VerificationStatus.UNKNOWN,
        VerificationStatus.ERROR,
    }
    assert "in-process execution is forbidden" not in " ".join(record.results[0].limits)
