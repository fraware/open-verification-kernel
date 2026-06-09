#!/usr/bin/env python
"""Smoke test the validated authorization command path."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_case(fixture: str, expected_recommendation: str) -> bool:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        evidence = tmp / "evidence.json"
        markdown = tmp / "comment.md"
        attestation = tmp / "attestation.json"
        command = [
            sys.executable,
            "-m",
            "ovk.cli",
            "auth-obligation",
            fixture,
            "--repo",
            "smoke/repo",
            "--head-sha",
            "smoke-head",
            "--evidence-output",
            str(evidence),
            "--markdown-output",
            str(markdown),
            "--attestation-output",
            str(attestation),
            "--advisory",
        ]
        completed = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
        if completed.returncode != 0:
            print(completed.stdout)
            print(completed.stderr)
            return False
        if not evidence.exists() or not markdown.exists() or not attestation.exists():
            return False
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        return payload["decision"]["merge_recommendation"] == expected_recommendation


def main() -> int:
    cases = [
        ("examples/auth_regression/input_malformed_missing_routes.json", "require_human_review"),
    ]
    failures = []
    for fixture, expected in cases:
        ok = run_case(fixture, expected)
        print(f"{fixture}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            failures.append(fixture)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
