"""Optional Cedar CLI probe for toolchain availability."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any


def probe_cedar_binary(*, timeout_seconds: int = 10) -> dict[str, Any]:
    """Probe Cedar CLI availability without claiming policy evaluation."""
    cedar_path = shutil.which("cedar")
    if cedar_path is None:
        return {
            "status": "unknown",
            "reason": "cedar binary not found",
            "binary_present": False,
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
            "reason": "cedar version probe timed out",
            "binary_present": True,
            "used_native_binary": False,
        }
    except OSError as error:
        return {
            "status": "error",
            "reason": f"cedar version probe failed: {error}",
            "binary_present": True,
            "used_native_binary": False,
        }

    if completed.returncode != 0:
        return {
            "status": "error",
            "reason": completed.stderr.strip() or "cedar --version failed",
            "binary_present": True,
            "used_native_binary": False,
        }

    version = completed.stdout.strip() or completed.stderr.strip()
    return {
        "status": "pass",
        "reason": version or "cedar binary responsive",
        "binary_present": True,
        "used_native_binary": False,
        "version": version,
        "probe_type": "version_only",
    }
