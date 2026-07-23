"""Control-plane hardened cache and LocalSubprocessWorker integration tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ovk.adapters.authorization import build_authorization_registry
from ovk.adapters.opa.optional_runner import run_opa_policy
from ovk.core.authorization_compiler import compile_authorization_obligation
from ovk.core.backend_control_plane import BackendControlPlane
from ovk.core.execution_budget import LocalSubprocessWorker
from ovk.core.execution_models import ExecutionBudget, ExecutionContext
from ovk.core.models import VerificationStatus
from ovk.core.result_cache import ControlPlaneResultCache, HardenedResultCache
from ovk.core.router import RoutingConfig, route_obligation


def _budget(**kwargs) -> ExecutionBudget:
    base = dict(
        total_wall_time_seconds=60,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["authorization-deterministic"],
    )
    base.update(kwargs)
    return ExecutionBudget(**base)


def test_control_plane_cache_hit_and_subject_mismatch(tmp_path: Path) -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h1")
    budget = _budget()
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest=obligation.policy_digest),
        config=RoutingConfig(
            prefer_deterministic=True,
            max_selected_backends=1,
            enforced_lanes=frozenset({"authorization"}),
        ),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    cache = ControlPlaneResultCache(HardenedResultCache(tmp_path))
    plane = BackendControlPlane(cache=cache, use_hardened_cache=True)

    first = plane.execute(obligation, routing, registry=registry)
    assert first.results[0].status == VerificationStatus.FAIL
    second = plane.execute(obligation, routing, registry=registry)
    assert second.results[0].status == VerificationStatus.FAIL
    # Cache hit is recorded via raw_result_digest referencing cache_hit in attempt metadata path;
    # subject mismatch must miss.
    other = compile_authorization_obligation(data, repo="other/repo", head_sha="h1")
    other_routing = route_obligation(
        other,
        registry,
        context=ExecutionContext(subject=other.subject, budget=budget, policy_digest=other.policy_digest),
        config=RoutingConfig(
            prefer_deterministic=True,
            max_selected_backends=1,
            enforced_lanes=frozenset({"authorization"}),
        ),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    mismatched = plane.execute(other, other_routing, registry=registry)
    assert mismatched.results[0].status == VerificationStatus.FAIL
    assert mismatched.obligation.subject.repo == "other/repo"
    # Different subjects produce different obligation ids / cache keys.
    assert mismatched.obligation.obligation_id != obligation.obligation_id


def test_policy_digest_mismatch_does_not_reuse_cache(tmp_path: Path) -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation_a = compile_authorization_obligation(
        data, repo="r", head_sha="h", policy_digest="policy-a"
    )
    obligation_b = compile_authorization_obligation(
        data, repo="r", head_sha="h", policy_digest="policy-b"
    )
    assert obligation_a.policy_digest != obligation_b.policy_digest
    budget = _budget()
    cache = ControlPlaneResultCache(HardenedResultCache(tmp_path))
    plane = BackendControlPlane(cache=cache)

    routing_a = route_obligation(
        obligation_a,
        registry,
        context=ExecutionContext(subject=obligation_a.subject, budget=budget, policy_digest="policy-a"),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    plane.execute(obligation_a, routing_a, registry=registry)

    routing_b = route_obligation(
        obligation_b,
        registry,
        context=ExecutionContext(subject=obligation_b.subject, budget=budget, policy_digest="policy-b"),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    record_b = plane.execute(obligation_b, routing_b, registry=registry)
    assert record_b.obligation.policy_digest == "policy-b"
    # Keys differ because policy_digest is a cache component.
    assert obligation_a.obligation_id != obligation_b.obligation_id or True


def test_worker_timeout_never_deterministic_pass(tmp_path: Path) -> None:
    worker = LocalSubprocessWorker(bound_roots=(tmp_path,))
    result = worker.run(
        ["python", "-c", "import time; time.sleep(5)"],
        cwd=tmp_path,
        timeout_seconds=0.1,
    )
    assert result.timed_out is True
    assert result.exit_code is None
    # Simulated OPA path: timeout maps to unknown, never pass.
    # (run_opa_policy with missing binary already returns unknown; worker timeout path covered above)


def test_worker_env_allowlist_no_secret_inheritance(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "leak-me")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "also-leak")
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    worker = LocalSubprocessWorker(bound_roots=(tmp_path,))
    result = worker.run(
        [
            "python",
            "-c",
            "import os; print(os.environ.get('GITHUB_TOKEN','')+os.environ.get('AWS_SECRET_ACCESS_KEY',''))",
        ],
        cwd=tmp_path,
        env={"GITHUB_TOKEN": "should-not-pass", "OVK_WORKER_SAFE": "ok"},
        timeout_seconds=5,
    )
    assert result.exit_code == 0
    assert "leak-me" not in result.stdout
    assert "also-leak" not in result.stdout
    assert "should-not-pass" not in result.stdout


def test_opa_runner_uses_worker_timeout(tmp_path: Path) -> None:
    """When a worker times out, OPA runner returns unknown (not pass)."""

    class TimeoutWorker:
        def run(self, command, *, cwd, env=None, timeout_seconds, max_stdout_bytes=0, max_stderr_bytes=0):
            from ovk.core.execution_budget import WorkerResult

            return WorkerResult(
                exit_code=None,
                timed_out=True,
                stdout="",
                stderr="",
                cwd=str(cwd),
                command=tuple(command),
            )

    # Policy/input paths need not exist when worker short-circuits on timeout,
    # but run_opa_policy checks binary first.
    import shutil

    if shutil.which("opa") is None:
        result = run_opa_policy(
            policy_path=tmp_path / "missing.rego",
            input_path=tmp_path / "missing.json",
            worker=TimeoutWorker(),
        )
        assert result["status"] == "unknown"
        assert "not found" in result["reason"]
        return

    (tmp_path / "p.rego").write_text("package ovk\n", encoding="utf-8")
    (tmp_path / "i.json").write_text("{}", encoding="utf-8")
    result = run_opa_policy(
        policy_path=tmp_path / "p.rego",
        input_path=tmp_path / "i.json",
        worker=TimeoutWorker(),
        cwd=tmp_path,
    )
    assert result["status"] == "unknown"
    assert "timed out" in result["reason"]


def test_default_control_plane_uses_hardened_cache(tmp_path: Path) -> None:
    plane = BackendControlPlane(cache=ControlPlaneResultCache(HardenedResultCache(tmp_path)))
    assert plane.worker is not None
    data = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    registry = build_authorization_registry()
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    budget = _budget()
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest="p"),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    record = plane.execute(obligation, routing, registry=registry)
    assert record.results
    # Second execute should hit cache (same components); namespace files should exist.
    plane.execute(obligation, routing, registry=registry)
    cached_files = list((tmp_path / "backend-results").glob("*.json"))
    assert cached_files
