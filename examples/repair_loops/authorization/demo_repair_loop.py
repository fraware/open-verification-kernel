#!/usr/bin/env python
"""Demonstrate agent repair loop for authorization lane."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
FAILING = ROOT / "examples/repair_loops/authorization/failing.diff"
PASSING = ROOT / "examples/repair_loops/authorization/passing.diff"


def _run_check(diff_path: Path, head_sha: str) -> dict:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ovk.cli",
            "check",
            "--changed-files",
            str(diff_path),
            "--repo",
            "example/repair-loop",
            "--head-sha",
            head_sha,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError(result.stdout + result.stderr)
    return json.loads((ROOT / "ovk-evidence.json").read_text(encoding="utf-8"))


def main() -> int:
    first = _run_check(FAILING, "agent-pr-1")
    if first["decision"]["merge_recommendation"] != "block":
        print("expected initial block", file=sys.stderr)
        return 1

    suggest = subprocess.run(
        [sys.executable, "-m", "ovk.cli", "repair-suggest", "--evidence", str(ROOT / "ovk-evidence.json")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    hints = json.loads(suggest.stdout)
    if not any(item.get("fix_class") == "add_route_guard" for item in hints.get("repair_hints", [])):
        print("expected add_route_guard hint", file=sys.stderr)
        return 1

    second = _run_check(PASSING, "agent-pr-2")
    if second["decision"]["merge_recommendation"] != "allow":
        print("expected repaired allow", file=sys.stderr)
        return 1

    print("authorization repair loop: block -> add_route_guard -> allow")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
