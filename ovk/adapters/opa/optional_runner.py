"""Optional OPA CLI runner.

The runner is deliberately optional. If the OPA binary is unavailable, the result
is `unknown`, never `pass`. Subprocess execution goes through
``LocalSubprocessWorker`` so env allowlisting, timeouts, and output bounds are
enforced outside the adapter.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from ovk.core.execution_budget import BackendWorker, LocalSubprocessWorker


def run_opa_policy(
    *,
    policy_path: Path,
    input_path: Path,
    query: str = "data.ovk.self_protection.violation",
    timeout_seconds: int = 10,
    worker: BackendWorker | None = None,
    cwd: Path | None = None,
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

    active_worker = worker or LocalSubprocessWorker()
    work_cwd = cwd or input_path.parent
    result = active_worker.run(
        command,
        cwd=work_cwd,
        timeout_seconds=float(timeout_seconds),
        max_stdout_bytes=2_000_000,
        max_stderr_bytes=500_000,
    )

    if result.timed_out:
        return {"status": "unknown", "reason": "opa execution timed out", "violations": []}

    if result.exit_code is None:
        return {
            "status": "error",
            "reason": result.stderr.strip() or "opa worker rejected execution",
            "violations": [],
        }

    if result.exit_code != 0:
        return {
            "status": "error",
            "reason": result.stderr.strip() or "opa execution failed",
            "violations": [],
        }

    try:
        payload = json.loads(result.stdout)
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
