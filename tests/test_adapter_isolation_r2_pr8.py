"""PR8 — native adapter worker isolation tests."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.adapters.authorization.z3_adapter import Z3NativeAuthorizationAdapter
from ovk.adapters.self_protection.opa_adapter import OpaNativeSelfProtectionAdapter
from ovk.core.execution_budget import WorkerResult
from ovk.core.execution_models import ExecutionBudget


def _budget() -> ExecutionBudget:
    return ExecutionBudget(
        total_wall_time_seconds=30,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
    )


def test_z3_adapter_requires_worker() -> None:
    adapter = Z3NativeAuthorizationAdapter()
    from ovk.core.authorization_compiler import compile_authorization_obligation
    from ovk.core.routing_pipeline import route_compiled_obligation

    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    routing = route_compiled_obligation(obligation, lane="authorization")
    compiled = adapter.compile(obligation, routing)
    raw = adapter.run(compiled, _budget(), worker=None)
    assert raw.termination == "tool_error"


def test_opa_adapter_requires_worker() -> None:
    adapter = OpaNativeSelfProtectionAdapter()
    from ovk.core.self_protection_compiler import compile_self_protection_obligation
    from ovk.core.routing_pipeline import route_compiled_obligation

    data = {"before": {"required_check": "ovk"}, "after": {"required_check": None}}
    obligation = compile_self_protection_obligation(data, repo="r", head_sha="h", metadata_trusted=True)
    routing = route_compiled_obligation(obligation, lane="self_protection")
    compiled = adapter.compile(obligation, routing)
    raw = adapter.run(compiled, _budget(), worker=None)
    assert raw.termination == "tool_error"


def test_worker_timeout_enforced_for_z3_not_post_hoc() -> None:
    adapter = Z3NativeAuthorizationAdapter()
    from ovk.core.authorization_compiler import compile_authorization_obligation
    from ovk.core.routing_pipeline import route_compiled_obligation

    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    routing = route_compiled_obligation(obligation, lane="authorization")
    compiled = adapter.compile(obligation, routing)

    class SlowWorker:
        def run(
            self,
            command,
            *,
            cwd,
            env=None,
            timeout_seconds=30.0,
            max_stdout_bytes=1_000_000,
            max_stderr_bytes=1_000_000,
        ):
            return WorkerResult(
                exit_code=None,
                timed_out=True,
                stdout="",
                stderr="timed out",
                cwd=str(cwd),
                command=tuple(command),
            )

    raw = adapter.run(compiled, _budget(), worker=SlowWorker())
    assert raw.termination == "timeout"
    assert raw.raw_result.get("reason") == "worker execution timed out"
