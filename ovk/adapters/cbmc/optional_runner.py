"""Optional CBMC CLI runner for native harness execution."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from ovk.core.execution_budget import BackendWorker, LocalSubprocessWorker


def _parse_cbmc_counterexamples(output: str, *, failure_mode: str) -> list[dict[str, Any]]:
    """Extract OVK counterexamples from CBMC stdout/stderr."""
    counterexamples: list[dict[str, Any]] = []
    combined = output
    violation_blocks = re.findall(
        r"Violated property:\s*\n(?:\s+.+\n)+",
        combined,
    )
    assertion_lines = re.findall(
        r"^\s*(?:file )?(.+\.(?:c|h|cpp):\d+ .+)$",
        combined,
        flags=re.MULTILINE,
    )
    trace_snippets = re.findall(
        r"^\[.+\].+$",
        combined,
        flags=re.MULTILINE,
    )

    if violation_blocks:
        summary = violation_blocks[0].strip().splitlines()[-1].strip()
        counterexamples.append(
            {
                "summary": summary or "CBMC reported a property violation.",
                "failure_mode": failure_mode,
                "trace_snippet": "\n".join(trace_snippets[:12]),
            }
        )
    elif assertion_lines:
        counterexamples.append(
            {
                "summary": assertion_lines[0].strip(),
                "failure_mode": failure_mode,
                "trace_snippet": "\n".join(trace_snippets[:12]),
            }
        )
    elif "VERIFICATION FAILED" in combined:
        counterexamples.append(
            {
                "summary": "CBMC verification failed within stated bounds.",
                "failure_mode": failure_mode,
                "trace_snippet": "\n".join(trace_snippets[:12]),
            }
        )
    return counterexamples


def run_cbmc_harness(
    *,
    harness_path: Path,
    entry_function: str = "harness",
    unwind: int | None = None,
    timeout_seconds: int = 60,
    failure_mode: str = "cbmc_assertion_failed",
    worker: BackendWorker | None = None,
) -> dict[str, Any]:
    """Run CBMC on a harness file when the binary is available."""
    cbmc_path = shutil.which("cbmc")
    if cbmc_path is None:
        return {
            "status": "unknown",
            "reason": "cbmc binary not found",
            "used_native_binary": False,
            "counterexamples": [],
        }

    if not harness_path.is_file():
        return {
            "status": "error",
            "reason": f"harness file not found: {harness_path}",
            "used_native_binary": False,
            "counterexamples": [],
        }

    command = [
        cbmc_path,
        str(harness_path),
        "--function",
        entry_function,
        "--trace",
        "--bounds-check",
        "--pointer-check",
    ]
    if unwind is not None:
        command.extend(["--unwind", str(unwind)])

    active_worker = worker or LocalSubprocessWorker()
    result = active_worker.run(
        command,
        cwd=harness_path.parent,
        timeout_seconds=float(timeout_seconds),
        max_stdout_bytes=2_000_000,
        max_stderr_bytes=500_000,
    )

    if result.timed_out:
        return {
            "status": "unknown",
            "reason": "cbmc execution timed out",
            "native_attempted": True,
            "used_native_binary": True,
            "counterexamples": [],
        }

    if result.exit_code is None:
        return {
            "status": "error",
            "reason": result.stderr.strip() or "cbmc worker rejected execution",
            "used_native_binary": False,
            "counterexamples": [],
        }

    combined = f"{result.stdout}\n{result.stderr}"
    version_match = re.search(r"CBMC version ([^\s]+)", combined)
    tool_version = version_match.group(1) if version_match else None

    if result.exit_code != 0 and "VERIFICATION FAILED" not in combined:
        return {
            "status": "error",
            "reason": result.stderr.strip() or "cbmc execution failed",
            "used_native_binary": True,
            "tool_version": tool_version,
            "counterexamples": [],
            "raw_output": combined[-4000:],
        }

    if "VERIFICATION SUCCESSFUL" in combined:
        return {
            "status": "pass",
            "reason": "CBMC verification successful within bounds.",
            "used_native_binary": True,
            "tool_version": tool_version,
            "counterexamples": [],
            "raw_output": combined[-4000:],
        }

    if "VERIFICATION FAILED" in combined:
        return {
            "status": "fail",
            "reason": "CBMC reported a reachable violation.",
            "used_native_binary": True,
            "tool_version": tool_version,
            "counterexamples": _parse_cbmc_counterexamples(combined, failure_mode=failure_mode),
            "raw_output": combined[-4000:],
        }

    return {
        "status": "unknown",
        "reason": "cbmc output did not report verification status",
        "used_native_binary": True,
        "tool_version": tool_version,
        "counterexamples": [],
        "raw_output": combined[-4000:],
    }
