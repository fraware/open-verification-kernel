"""Optional Cedar CLI runner for native contract probing."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any


def probe_cedar_binary(*, timeout_seconds: int = 10) -> dict[str, Any]:
    """Probe the Cedar CLI when available; never fabricate pass/fail from absence."""
    cedar_path = shutil.which("cedar")
    if cedar_path is None:
        return {
            "status": "unknown",
            "reason": "cedar binary not found",
            "used_native_binary": False,
        }

    try:
        completed = subprocess.run(
            [cedar_path, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "unknown",
            "reason": "cedar execution timed out",
            "used_native_binary": False,
        }

    if completed.returncode != 0:
        return {
            "status": "error",
            "reason": completed.stderr.strip() or "cedar --version failed",
            "used_native_binary": False,
        }

    return {
        "status": "pass",
        "reason": completed.stdout.strip() or "cedar binary responsive",
        "used_native_binary": True,
        "version": completed.stdout.strip(),
    }
