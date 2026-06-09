"""Optional OPA CLI runner.

The runner is deliberately optional. If the OPA binary is unavailable, the result
is `unknown`, never `pass`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def run_opa_policy(
    *,
    policy_path: Path,
    input_path: Path,
    query: str = "data.ovk.self_protection.violation",
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Run OPA when available and return a normalized raw result."""
    opa_path = shutil.which("opa")
    if opa_path is None:
        return {"status": "unknown", "reason": "opa binary not found", "violations": []}

    command = [
        opa_path,
        "eval",
        "--format",
        "json",
        "--data",
        str(policy_path),
        "--input",
        str(input_path),
        query,
    ]

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"status": "unknown", "reason": "opa execution timed out", "violations": []}

    if completed.returncode != 0:
        return {
            "status": "error",
            "reason": completed.stderr.strip() or "opa execution failed",
            "violations": [],
        }

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"status": "error", "reason": "opa returned invalid JSON", "violations": []}

    values: list[Any] = []
    for item in payload.get("result", []):
        for expression in item.get("expressions", []):
            values.append(expression.get("value"))

    violations: list[Any] = []
    for value in values:
        if isinstance(value, list):
            violations.extend(value)
        elif value:
            violations.append(value)

    return {
        "status": "fail" if violations else "pass",
        "reason": "violations returned" if violations else "no violations returned",
        "violations": violations,
        "raw": payload,
    }
