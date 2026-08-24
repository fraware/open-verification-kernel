"""Execution budget helpers and bounded backend workers."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from ovk.core.backend_ids import normalize_allowed_backends, normalize_denied_backends
from ovk.core.execution_models import ExecutionBudget

__all__ = [
    "BackendWorker",
    "BudgetBoundWorker",
    "ExecutionBudget",
    "LocalSubprocessWorker",
    "WorkerResult",
    "execution_budget_from_policy",
]


def execution_budget_from_policy(policy: dict[str, Any] | None) -> ExecutionBudget:
    policy = policy or {}
    budget_section = policy.get("budget", {})
    if not isinstance(budget_section, dict):
        budget_section = {}
    routing = policy.get("routing", {})
    if not isinstance(routing, dict):
        routing = {}

    allowed_raw = budget_section.get("allowed_backends")
    if allowed_raw is None:
        allowed_raw = policy.get("allowed_backends")
    denied_raw = budget_section.get("denied_backends")
    if denied_raw is None:
        denied_raw = policy.get("denied_backends", [])
    allowed = normalize_allowed_backends(allowed_raw)
    denied = normalize_denied_backends(denied_raw)

    total = float(
        budget_section.get(
            "total_wall_time_seconds",
            budget_section.get("max_wall_time_seconds", policy.get("max_wall_time_seconds", 60.0)),
        )
    )
    per_backend = float(
        budget_section.get(
            "per_backend_wall_time_seconds",
            budget_section.get("max_wall_time_seconds", policy.get("max_wall_time_seconds", 30.0)),
        )
    )
    return ExecutionBudget(
        total_wall_time_seconds=total,
        per_backend_wall_time_seconds=per_backend,
        max_memory_mb=int(budget_section.get("max_memory_mb", policy.get("max_memory_mb", 512))),
        max_parallel_backends=int(budget_section.get("max_parallel_backends", routing.get("max_selected_backends", 2))),
        allow_network=bool(budget_section.get("allow_network", False)),
        allow_repository_write=bool(budget_section.get("allow_repository_write", False)),
        allowed_backends=allowed,
        denied_backends=denied,
    )


@dataclass(frozen=True)
class WorkerResult:
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    cwd: str | None = None
    command: tuple[str, ...] = ()
    isolation_profile: str = "local-subprocess.v1"
    enforced_controls: tuple[str, ...] = ()


class BackendWorker(Protocol):
    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float,
        max_stdout_bytes: int = 1_000_000,
        max_stderr_bytes: int = 1_000_000,
    ) -> WorkerResult: ...


_SECRET_ENV_DENYLIST = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "HOLDOUT_DOWNLOAD_TOKEN",
        "NPM_TOKEN",
        "OPENAI_API_KEY",
        "OVK_SIGNING_KEY",
        "OVK_METADATA_VERIFY_KEY",
        "OVK_METADATA_SIGNING_KEY",
        "PRIVATE_KEY",
        "PYPI_API_TOKEN",
        "SSH_AUTH_SOCK",
    }
)


def _is_python_ovk_worker(command: Sequence[str]) -> bool:
    normalized = [str(part) for part in command]
    return "-m" in normalized and "ovk.workers.deterministic_entry" in normalized


def _memory_preexec(max_memory_mb: int):
    """Return a POSIX pre-exec RLIMIT hook or None on unsupported platforms."""
    if os.name != "posix" or max_memory_mb <= 0:
        return None
    try:
        import resource
    except ImportError:
        return None

    limit = int(max_memory_mb) * 1024 * 1024

    def apply_limits() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

    return apply_limits


@dataclass
class LocalSubprocessWorker:
    """Local worker with explicit truthful enforcement capabilities.

    Base ``run`` enforces timeout, cwd bounds, a minimal environment and output
    caps. ``run_with_budget`` additionally applies a POSIX address-space limit
    and, for OVK's Python evaluator process, enables audit-hook denial of network
    access and filesystem writes. External native commands are rejected when a
    requested isolation control cannot be enforced rather than being mislabeled
    as isolated.
    """

    allowed_env_keys: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR",
                "HOME", "USERPROFILE", "LANG", "LC_ALL", "PYTHONPATH",
                "VIRTUAL_ENV", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH",
                "SSL_CERT_FILE", "SSL_CERT_DIR",
            }
        )
    )
    bound_roots: tuple[Path, ...] = ()

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float,
        max_stdout_bytes: int = 1_000_000,
        max_stderr_bytes: int = 1_000_000,
    ) -> WorkerResult:
        return self._run_internal(
            command,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            preexec_fn=None,
            enforced_controls=("timeout", "environment_allowlist", "output_caps"),
        )

    def run_with_budget(
        self,
        command: Sequence[str],
        *,
        budget: ExecutionBudget,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float,
        max_stdout_bytes: int = 1_000_000,
        max_stderr_bytes: int = 1_000_000,
    ) -> WorkerResult:
        extra = dict(env or {})
        controls = ["timeout", "environment_allowlist", "output_caps"]
        preexec = _memory_preexec(budget.max_memory_mb)
        if preexec is not None:
            controls.append("memory_limit")
        elif budget.max_memory_mb:
            return WorkerResult(
                exit_code=None,
                timed_out=False,
                stdout="",
                stderr="requested memory limit cannot be enforced by local worker on this platform",
                cwd=str(cwd.resolve()),
                command=tuple(command),
                isolation_profile="local-subprocess.v2",
                enforced_controls=tuple(controls),
            )

        python_worker = _is_python_ovk_worker(command)
        if not budget.allow_network:
            if not python_worker:
                return WorkerResult(
                    exit_code=None,
                    timed_out=False,
                    stdout="",
                    stderr="network denial requested but cannot be enforced for external native command",
                    cwd=str(cwd.resolve()),
                    command=tuple(command),
                    isolation_profile="local-subprocess.v2",
                    enforced_controls=tuple(controls),
                )
            extra["OVK_WORKER_DENY_NETWORK"] = "1"
            controls.append("network_denied")
        if not budget.allow_repository_write:
            if not python_worker:
                return WorkerResult(
                    exit_code=None,
                    timed_out=False,
                    stdout="",
                    stderr="repository write denial requested but cannot be enforced for external native command",
                    cwd=str(cwd.resolve()),
                    command=tuple(command),
                    isolation_profile="local-subprocess.v2",
                    enforced_controls=tuple(controls),
                )
            extra["OVK_WORKER_DENY_WRITES"] = "1"
            # The payload file was written by the parent before the worker starts;
            # evaluator execution itself is read-only.
            controls.append("filesystem_writes_denied")

        return self._run_internal(
            command,
            cwd=cwd,
            env=extra,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            preexec_fn=preexec,
            enforced_controls=tuple(controls),
            isolation_profile="local-subprocess.v2",
        )

    def _run_internal(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        preexec_fn,
        enforced_controls: tuple[str, ...],
        isolation_profile: str = "local-subprocess.v1",
    ) -> WorkerResult:
        cwd_resolved = cwd.resolve()
        if self.bound_roots and not any(_is_relative_to(cwd_resolved, root.resolve()) for root in self.bound_roots):
            return WorkerResult(
                exit_code=None, timed_out=False, stdout="",
                stderr=f"cwd {cwd_resolved} is outside bound roots",
                cwd=str(cwd_resolved), command=tuple(command),
                isolation_profile=isolation_profile,
                enforced_controls=enforced_controls,
            )
        if timeout_seconds <= 0:
            return WorkerResult(
                exit_code=None, timed_out=False, stdout="",
                stderr=f"non-positive wall-time budget rejected: {timeout_seconds}",
                cwd=str(cwd_resolved), command=tuple(command),
                isolation_profile=isolation_profile,
                enforced_controls=enforced_controls,
            )

        child_env = self._build_env(env)
        try:
            completed = subprocess.run(
                list(command),
                cwd=str(cwd_resolved),
                env=child_env,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
                preexec_fn=preexec_fn,
                start_new_session=(os.name == "posix"),
            )
        except subprocess.TimeoutExpired as exc:
            stdout, stdout_truncated = _truncate(exc.stdout or b"", max_stdout_bytes)
            stderr, stderr_truncated = _truncate(exc.stderr or b"", max_stderr_bytes)
            return WorkerResult(
                exit_code=None, timed_out=True, stdout=stdout, stderr=stderr,
                stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated,
                cwd=str(cwd_resolved), command=tuple(command),
                isolation_profile=isolation_profile,
                enforced_controls=enforced_controls,
            )

        stdout, stdout_truncated = _truncate(completed.stdout or b"", max_stdout_bytes)
        stderr, stderr_truncated = _truncate(completed.stderr or b"", max_stderr_bytes)
        return WorkerResult(
            exit_code=int(completed.returncode), timed_out=False,
            stdout=stdout, stderr=stderr,
            stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated,
            cwd=str(cwd_resolved), command=tuple(command),
            isolation_profile=isolation_profile,
            enforced_controls=enforced_controls,
        )

    def _build_env(self, extra: Mapping[str, str] | None) -> dict[str, str]:
        allow = {key.upper() for key in self.allowed_env_keys}
        baseline: dict[str, str] = {}
        for key, value in os.environ.items():
            if key.upper() in allow and key.upper() not in _SECRET_ENV_DENYLIST:
                baseline[key] = value
        if extra:
            for key, value in extra.items():
                if key.upper() in _SECRET_ENV_DENYLIST:
                    continue
                baseline[key] = value
        for denied in _SECRET_ENV_DENYLIST:
            for existing in list(baseline):
                if existing.upper() == denied.upper():
                    baseline.pop(existing, None)
        return baseline


@dataclass(frozen=True)
class BudgetBoundWorker:
    """Adapter-facing worker that binds every subprocess call to one budget."""

    worker: BackendWorker
    budget: ExecutionBudget

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float,
        max_stdout_bytes: int = 1_000_000,
        max_stderr_bytes: int = 1_000_000,
    ) -> WorkerResult:
        run_with_budget = getattr(self.worker, "run_with_budget", None)
        if callable(run_with_budget):
            return run_with_budget(
                command,
                budget=self.budget,
                cwd=cwd,
                env=env,
                timeout_seconds=min(timeout_seconds, self.budget.per_backend_wall_time_seconds),
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=max_stderr_bytes,
            )
        # Custom/test workers remain usable; they are not claimed as the
        # production LocalSubprocessWorker isolation profile.
        return self.worker.run(
            command,
            cwd=cwd,
            env=env,
            timeout_seconds=min(timeout_seconds, self.budget.per_backend_wall_time_seconds),
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )


def _truncate(raw: bytes | str, limit: int) -> tuple[str, bool]:
    data = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    if len(data) <= limit:
        return data.decode("utf-8", errors="replace"), False
    return data[:limit].decode("utf-8", errors="replace"), True


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
