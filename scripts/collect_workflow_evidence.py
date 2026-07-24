"""Collect GitHub Actions workflow run IDs and digests for attributable publication.

Requires network + ``gh`` auth. Does not push or mutate remotes.
When Actions are unavailable, exits non-zero with an explicit blocker message.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_WORKFLOW_NAMES = (
    "CI",
    "Native Tier 1",
    "Release",
    "Bench",
)


def _run_gh(args: list[str]) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            ["gh", *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)
    return completed.returncode, completed.stdout, completed.stderr


def collect_for_sha(*, repo: str, sha: str, limit: int = 30) -> dict[str, Any]:
    code, stdout, stderr = _run_gh(
        [
            "run",
            "list",
            "--repo",
            repo,
            "--commit",
            sha,
            "--limit",
            str(limit),
            "--json",
            "databaseId,displayTitle,workflowName,status,conclusion,url,headSha,createdAt",
        ]
    )
    if code != 0:
        return {
            "ok": False,
            "blocker": "gh_run_list_failed",
            "detail": stderr.strip() or stdout.strip() or "gh run list failed",
            "benchmark_source_sha": sha,
            "verified_source_sha": None,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "runs": [],
        }
    runs = json.loads(stdout or "[]")
    by_workflow: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        name = str(run.get("workflowName") or "unknown")
        by_workflow.setdefault(name, []).append(run)
    observed = sorted(by_workflow)
    # verified_source_sha is only set when callers confirm the full required set.
    return {
        "ok": True,
        "blocker": None,
        "benchmark_source_sha": sha,
        "verified_source_sha": None,
        "required_workflow_names": list(REQUIRED_WORKFLOW_NAMES),
        "observed_workflow_names": observed,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "runs": runs,
        "note": (
            "Cite benchmark_source_sha for measurement identity. "
            "Set verified_source_sha only after maintainers confirm the complete "
            "required-workflow set on this commit."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect workflow evidence for a source SHA")
    parser.add_argument("--repo", default="fraware/open-verification-kernel")
    parser.add_argument("--sha", required=True, help="Source commit SHA")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    payload = collect_for_sha(repo=args.repo, sha=args.sha)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if not payload.get("ok"):
        print(f"blocked: {payload.get('blocker')}: {payload.get('detail')}", file=sys.stderr)
        return 2
    print(
        f"collected {len(payload.get('runs') or [])} runs for "
        f"benchmark_source_sha={args.sha}; verified_source_sha left unset"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
