"""Optional Cedar CLI runner for native contract probing."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from ovk.core.execution_budget import BackendWorker, LocalSubprocessWorker


def probe_cedar_binary(
    *,
    timeout_seconds: int = 10,
    worker: BackendWorker | None = None,
) -> dict[str, Any]:
    """Probe the Cedar CLI when available; never fabricate pass/fail from absence."""
    cedar_path = shutil.which("cedar")
    if cedar_path is None:
        return {
            "status": "unknown",
            "reason": "cedar binary not found",
            "used_native_binary": False,
        }

    active_worker = worker or LocalSubprocessWorker()
    with tempfile.TemporaryDirectory() as tmp:
        result = active_worker.run(
            [cedar_path, "--version"],
            cwd=Path(tmp),
            timeout_seconds=float(timeout_seconds),
            max_stdout_bytes=64_000,
            max_stderr_bytes=64_000,
        )

    if result.timed_out:
        return {
            "status": "unknown",
            "reason": "cedar execution timed out",
            "used_native_binary": False,
        }

    if result.exit_code is None:
        return {
            "status": "error",
            "reason": result.stderr.strip() or "cedar worker rejected execution",
            "used_native_binary": False,
        }

    if result.exit_code != 0:
        return {
            "status": "error",
            "reason": result.stderr.strip() or "cedar --version failed",
            "used_native_binary": False,
        }

    return {
        "status": "pass",
        "reason": result.stdout.strip() or "cedar binary responsive",
        "used_native_binary": True,
        "version": result.stdout.strip(),
    }
