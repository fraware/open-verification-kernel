"""Execution budget helpers and bounded backend workers.

``ExecutionBudget`` is defined in ``ovk.core.execution_models``. This module
re-exports it, provides policy conversion helpers, and defines the worker
protocol that enforces subprocess environment bounds. Adapters describe
computation; workers enforce timeout, cwd, env allowlist, and output caps.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from ovk.core.execution_models import ExecutionBudget

__all__ = [
    "BackendWorker",
    "ExecutionBudget",
    "LocalSubprocessWorker",
    "WorkerResult",
    "execution_budget_from_policy",
]


def execution_budget_from_policy(policy: dict[str, Any] | None) -> ExecutionBudget:
    """Build an ``ExecutionBudget`` from repository policy configuration."""
    policy = policy or {}
    budget_section = policy.get("budget", {})
    if not isinstance(budget_section, dict):
        budget_section = {}
    routing = policy.get("routing", {})
    if not isinstance(routing, dict):
        routing = {}

    allowed = budget_section.get("allowed_backends")
    if allowed is None:
        allowed = policy.get("allowed_backends")
    denied_raw = budget_section.get("denied_backends")
    if denied_raw is None:
        denied_raw = policy.get("denied_backends", [])
    denied = [str(item) for item in denied_raw] if isinstance(denied_raw, (list, tuple)) else []

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
        allowed_backends=[str(item) for item in allowed] if isinstance(allowed, (list, tuple)) else None,
        denied_backends=denied,
    )


@dataclass(frozen=True)
class WorkerResult:
    """Bounded subprocess execution result."""

    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    cwd: str | None = None
    command: tuple[str, ...] = ()


class BackendWorker(Protocol):
    """Protocol for workers that enforce execution environment bounds."""

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


# Environment variable names that must never be inherited into backend workers.
_SECRET_ENV_DENYLIST = (
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "OPENAI_API_KEY",
    "OVK_SIGNING_KEY",
    "PRIVATE_KEY",
    "SSH_AUTH_SOCK",
)


@dataclass
class LocalSubprocessWorker:
    """Local subprocess worker with timeout, cwd bound, and env allowlist.

    Secret-bearing environment variables are never inherited. Only an explicit
    allowlist (plus a minimal safe baseline) is passed to the child process.
    """

    allowed_env_keys: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "PATH",
                "PATHEXT",
                "SYSTEMROOT",
                "TEMP",
                "TMP",
                "TMPDIR",
                "HOME",
                "USERPROFILE",
                "LANG",
                "LC_ALL",
                "PYTHONPATH",
                "VIRTUAL_ENV",
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
        cwd_resolved = cwd.resolve()
        if self.bound_roots:
            if not any(_is_relative_to(cwd_resolved, root.resolve()) for root in self.bound_roots):
                return WorkerResult(
                    exit_code=None,
                    timed_out=False,
                    stdout="",
                    stderr=f"cwd {cwd_resolved} is outside bound roots",
                    cwd=str(cwd_resolved),
                    command=tuple(command),
                )

        child_env = self._build_env(env)
        try:
            completed = subprocess.run(
                list(command),
                cwd=str(cwd_resolved),
                env=child_env,
                capture_output=True,
                timeout=timeout_seconds if timeout_seconds > 0 else None,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout, stdout_truncated = _truncate(exc.stdout or b"", max_stdout_bytes)
            stderr, stderr_truncated = _truncate(exc.stderr or b"", max_stderr_bytes)
            return WorkerResult(
                exit_code=None,
                timed_out=True,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                cwd=str(cwd_resolved),
                command=tuple(command),
            )

        stdout, stdout_truncated = _truncate(completed.stdout or b"", max_stdout_bytes)
        stderr, stderr_truncated = _truncate(completed.stderr or b"", max_stderr_bytes)
        return WorkerResult(
            exit_code=int(completed.returncode),
            timed_out=False,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            cwd=str(cwd_resolved),
            command=tuple(command),
        )

    def _build_env(self, extra: Mapping[str, str] | None) -> dict[str, str]:
        baseline = {
            key: value
            for key, value in os.environ.items()
            if key in self.allowed_env_keys and key.upper() not in _SECRET_ENV_DENYLIST
        }
        if extra:
            for key, value in extra.items():
                upper = key.upper()
                if upper in _SECRET_ENV_DENYLIST:
                    continue
                if key in self.allowed_env_keys or key.startswith("OVK_WORKER_"):
                    baseline[key] = value
        # Explicitly drop denylisted keys even if allowlisted by mistake.
        for denied in _SECRET_ENV_DENYLIST:
            baseline.pop(denied, None)
        return baseline


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
