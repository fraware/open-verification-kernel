#!/usr/bin/env python
"""Run OVK local release preflight checks."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.release_preflight_report import build_release_preflight_report


ROOT = Path(__file__).resolve().parents[1]


def _run_benchmark() -> list[str]:
    result = subprocess.run(
        [sys.executable, str(ROOT / "benchmarks/formal_pr_bench/score_all_lanes.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        output = result.stdout.strip() or result.stderr.strip()
        return [f"benchmark preflight failed: {output}"]
    return []


def main() -> int:
    failures = _run_benchmark()
    report = build_release_preflight_report()
    failures.extend(report.failures)

    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("OVK release preflight checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
