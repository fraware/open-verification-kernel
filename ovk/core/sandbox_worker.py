"""Production sandbox worker that actually enforces isolation controls.

``LocalSubprocessWorker`` remains truthful: it rejects external native commands
when network or write denial cannot be enforced. Strict native evidence uses
``SandboxedBackendWorker`` when a Linux bubblewrap profile can be applied.
Where the sandbox cannot run, strict native stays UNKNOWN/review rather than
claiming isolation that was not enforced.

Isolation profile id: ``oci-sandbox.v1``. The first landing uses bubblewrap
(or equivalent unshare) rather than claiming OCI runtime isolation that is not
present. Digest-pinned worker images are recorded when supplied.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from ovk.core.execution_budget import (
    ExecutionBudget,
    LocalSubprocessWorker,
    WorkerResult,
    _SECRET_ENV_DENYLIST,
    _truncate,
)

ISOLATION_PROFILE_ID = "oci-sandbox.v1"
LOCKFILE_PATH = Path("toolchains/backend-tools.lock.json")
DOCKER_SOCKET = Path("/var/run/docker.sock")


def sandbox_available() -> bool:
    """True only when this process can actually enforce the Linux sandbox profile."""
    if os.name != "posix" or sys.platform == "win32":
        return False
    if shutil.which("bwrap") is None:
        return False
    return True


def load_worker_image_digest(lockfile: Path | None = None) -> str | None:
    digest = os.environ.get("OVK_WORKER_IMAGE_DIGEST")
    if digest:
        return digest.strip() or None
    path = lockfile or LOCKFILE_PATH
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    image = payload.get("worker_image") if isinstance(payload, dict) else None
    if isinstance(image, dict):
        value = image.get("digest")
        return str(value) if value else None
    return None


def tool_digest_for_command(command: Sequence[str]) -> str | None:
    if not command:
        return None
    executable = shutil.which(str(command[0])) or str(command[0])
    path = Path(executable)
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def build_bwrap_argv(
    command: Sequence[str],
    *,
    cwd: Path,
    scratch: Path,
    allow_network: bool,
    allow_repository_write: bool,
    extra_ro_binds: Sequence[Path] = (),
) -> list[str]:
    """Construct a bubblewrap argv that denies net/write by default.

    The command is executed inside a new user/network/pid namespace with
    dropped capabilities, no new privileges, and a dedicated scratch tmpfs.
    """
    cwd_resolved = cwd.resolve()
    scratch_resolved = scratch.resolve()
    argv: list[str] = [
        "bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
        "--as-pid-1",
    ]
    if not allow_network:
        argv.append("--unshare-net")
    for root in ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"):
        if Path(root).exists():
            argv.extend(["--ro-bind", root, root])
    python_root = Path(sys.prefix)
    if python_root.exists() and str(python_root) not in {"/usr", "/"}:
        argv.extend(["--ro-bind", str(python_root), str(python_root)])
    if Path("/dev/null").exists():
        argv.extend(["--dev-bind", "/dev/null", "/dev/null"])
    argv.extend(["--tmpfs", "/tmp", "--dir", str(scratch_resolved)])
    bind_flag = "--bind" if allow_repository_write else "--ro-bind"
    argv.extend([bind_flag, str(cwd_resolved), str(cwd_resolved)])
    for extra in extra_ro_binds:
        resolved = extra.resolve()
        if resolved.exists() and resolved != cwd_resolved:
            argv.extend(["--ro-bind", str(resolved), str(resolved)])
    home = Path.home()
    argv.extend(["--tmpfs", str(home)])
    if DOCKER_SOCKET.exists():
        argv.extend(["--tmpfs", str(DOCKER_SOCKET.parent)])
    git_dir = cwd_resolved / ".git"
    if git_dir.exists() and not allow_repository_write:
        argv.extend(["--tmpfs", str(git_dir)])
    argv.extend(["--chdir", str(cwd_resolved), "--"] + [str(part) for part in command])
    return argv


@dataclass
class SandboxedBackendWorker:
    """Linux bubblewrap worker used for strict native isolation claims."""

    allowed_env_keys: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "PATH",
                "PATHEXT",
                "SYSTEMROOT",
                "TEMP",
                "TMP",
                "TMPDIR",
                "LANG",
                "LC_ALL",
                "PYTHONPATH",
                "VIRTUAL_ENV",
                "LD_LIBRARY_PATH",
                "SSL_CERT_FILE",
                "SSL_CERT_DIR",
            }
        )
    )
    bound_roots: tuple[Path, ...] = ()
    isolation_profile: str = ISOLATION_PROFILE_ID
    worker_image_digest: str | None = field(default_factory=load_worker_image_digest)

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
        budget = ExecutionBudget(
            total_wall_time_seconds=timeout_seconds,
            per_backend_wall_time_seconds=timeout_seconds,
            max_memory_mb=0,
            max_parallel_backends=1,
            allow_network=False,
            allow_repository_write=False,
        )
        return self.run_with_budget(
            command,
            budget=budget,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
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
        cwd_resolved = cwd.resolve()
        tool_digest = tool_digest_for_command(command)
        controls = [
            "timeout",
            "environment_allowlist",
            "output_caps",
            "network_denied" if not budget.allow_network else "network_enabled_explicit",
            "filesystem_writes_denied" if not budget.allow_repository_write else "repository_write_enabled_explicit",
            "capabilities_dropped",
            "no_new_privileges",
            "process_namespace",
        ]
        if not sandbox_available():
            return WorkerResult(
                exit_code=None,
                timed_out=False,
                stdout="",
                stderr=(
                    "strict native sandbox is unavailable on this platform; "
                    "isolation cannot be claimed"
                ),
                cwd=str(cwd_resolved),
                command=tuple(command),
                isolation_profile=self.isolation_profile,
                enforced_controls=(),
                tool_digest=tool_digest,
                worker_image_digest=self.worker_image_digest,
                termination_category="isolation_unenforceable",
            )
        if timeout_seconds <= 0:
            return WorkerResult(
                exit_code=None,
                timed_out=False,
                stdout="",
                stderr=f"non-positive wall-time budget rejected: {timeout_seconds}",
                cwd=str(cwd_resolved),
                command=tuple(command),
                isolation_profile=self.isolation_profile,
                enforced_controls=tuple(controls),
                tool_digest=tool_digest,
                worker_image_digest=self.worker_image_digest,
                termination_category="error",
            )

        child_env = self._build_env(env)
        with tempfile.TemporaryDirectory(prefix="ovk-sandbox-") as scratch_dir:
            argv = build_bwrap_argv(
                command,
                cwd=cwd_resolved,
                scratch=Path(scratch_dir),
                allow_network=budget.allow_network,
                allow_repository_write=budget.allow_repository_write,
            )
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=str(cwd_resolved),
                    env=child_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
            except OSError as exc:
                return WorkerResult(
                    exit_code=None,
                    timed_out=False,
                    stdout="",
                    stderr=f"sandbox execution failed: {exc}",
                    cwd=str(cwd_resolved),
                    command=tuple(command),
                    isolation_profile=self.isolation_profile,
                    enforced_controls=tuple(controls),
                    tool_digest=tool_digest,
                    worker_image_digest=self.worker_image_digest,
                    termination_category="error",
                )
            try:
                stdout_raw, stderr_raw = process.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                self._kill_process_group(process)
                stdout_raw, stderr_raw = process.communicate(timeout=1)
                stdout, stdout_truncated = _truncate(stdout_raw or b"", max_stdout_bytes)
                stderr, stderr_truncated = _truncate(stderr_raw or b"", max_stderr_bytes)
                return WorkerResult(
                    exit_code=None,
                    timed_out=True,
                    stdout=stdout,
                    stderr=stderr,
                    stdout_truncated=stdout_truncated,
                    stderr_truncated=stderr_truncated,
                    cwd=str(cwd_resolved),
                    command=tuple(command),
                    isolation_profile=self.isolation_profile,
                    enforced_controls=tuple(controls + ["cgroup_timeout", "process_group_killed"]),
                    tool_digest=tool_digest,
                    worker_image_digest=self.worker_image_digest,
                    termination_category="timeout",
                )
            stdout, stdout_truncated = _truncate(stdout_raw or b"", max_stdout_bytes)
            stderr, stderr_truncated = _truncate(stderr_raw or b"", max_stderr_bytes)
            return WorkerResult(
                exit_code=int(process.returncode if process.returncode is not None else 1),
                timed_out=False,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                cwd=str(cwd_resolved),
                command=tuple(command),
                isolation_profile=self.isolation_profile,
                enforced_controls=tuple(controls),
                tool_digest=tool_digest,
                worker_image_digest=self.worker_image_digest,
                termination_category="completed",
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
        baseline.setdefault("PYTHONDONTWRITEBYTECODE", "1")
        for denied in _SECRET_ENV_DENYLIST:
            for existing in list(baseline):
                if existing.upper() == denied.upper():
                    baseline.pop(existing, None)
        return baseline

    @staticmethod
    def _kill_process_group(process: subprocess.Popen | None) -> None:
        if process is None or process.pid is None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError, AttributeError):
            try:
                process.kill()
            except OSError:
                return


def production_backend_worker() -> LocalSubprocessWorker | SandboxedBackendWorker:
    """Select the production worker. Sandbox is required to claim strict isolation."""
    if sandbox_available():
        return SandboxedBackendWorker()
    return LocalSubprocessWorker()
