"""Phase A WP-02 isolation tests for SandboxedBackendWorker."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.execution_budget import BudgetBoundWorker, LocalSubprocessWorker
from ovk.core.execution_models import ExecutionBudget
from ovk.core.sandbox_worker import (
    ISOLATION_PROFILE_ID,
    SandboxedBackendWorker,
    build_bwrap_argv,
    production_backend_worker,
    sandbox_available,
)


def _budget(**updates) -> ExecutionBudget:
    values = dict(
        total_wall_time_seconds=5,
        per_backend_wall_time_seconds=5,
        max_memory_mb=256,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["authorization-deterministic"],
    )
    values.update(updates)
    return ExecutionBudget(**values)


def test_sandbox_unavailable_fail_closes_without_claiming_isolation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("ovk.core.sandbox_worker.sandbox_available", lambda: False)
    worker = SandboxedBackendWorker()
    result = worker.run(["echo", "hello"], cwd=tmp_path, timeout_seconds=1)
    assert result.exit_code is None
    assert result.termination_category == "isolation_unenforceable"
    assert result.isolation_profile == ISOLATION_PROFILE_ID
    assert result.enforced_controls == ()
    assert "cannot be claimed" in result.stderr


def test_bwrap_profile_denies_net_write_git_home_and_docker_socket(tmp_path: Path) -> None:
    argv = build_bwrap_argv(
        ["true"],
        cwd=tmp_path,
        scratch=tmp_path / "scratch",
        allow_network=False,
        allow_repository_write=False,
    )
    joined = " ".join(argv)
    assert argv[0] == "bwrap"
    assert "--unshare-net" in argv
    assert "--cap-drop" in argv
    assert "--ro-bind" in argv
    assert "--unshare-pid" in argv
    assert str(tmp_path) in joined


def test_network_enabled_requires_explicit_profile(tmp_path: Path) -> None:
    argv = build_bwrap_argv(
        ["true"],
        cwd=tmp_path,
        scratch=tmp_path / "scratch",
        allow_network=True,
        allow_repository_write=False,
    )
    assert "--unshare-net" not in argv
    worker = SandboxedBackendWorker()
    result = worker.run_with_budget(
        ["true"],
        budget=_budget(allow_network=True),
        cwd=tmp_path,
        timeout_seconds=1,
    )
    if result.termination_category == "isolation_unenforceable":
        assert result.enforced_controls == ()
    else:
        assert "network_enabled_explicit" in result.enforced_controls


def test_local_worker_remains_truthful_for_external_native_tools(tmp_path: Path) -> None:
    worker = BudgetBoundWorker(LocalSubprocessWorker(), _budget())
    result = worker.run(["echo", "hello"], cwd=tmp_path, timeout_seconds=1)
    assert result.exit_code is None
    assert "network denial requested" in result.stderr


def test_production_worker_is_sandbox_only_when_available() -> None:
    worker = production_backend_worker()
    if sandbox_available():
        assert isinstance(worker, SandboxedBackendWorker)
        assert worker.isolation_profile == ISOLATION_PROFILE_ID
    else:
        assert isinstance(worker, LocalSubprocessWorker)


def test_lockfile_records_isolation_profile() -> None:
    payload = json.loads(Path("toolchains/backend-tools.lock.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ovk.backend_tools.lock.v1"
    assert payload["isolation_profile"] == ISOLATION_PROFILE_ID
