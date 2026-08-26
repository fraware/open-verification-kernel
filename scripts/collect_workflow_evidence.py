"""Collect candidate-bound GitHub Actions observations for release authorization.

This script records live GitHub workflow metadata but does not authorize a
release and never sets ``verified_source_sha``. Authorization is a separate
network-backed verification step in ``verify_release_ledger_github.py``.

For final publication, callers pass ``--required-event workflow_dispatch`` so
PR-merge checks cannot be reused as tag-bound release evidence merely because
their GitHub run metadata references the same candidate head SHA.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.release_ledger import REQUIRED_WORKFLOWS  # noqa: E402

REQUIRED_WORKFLOW_NAMES = REQUIRED_WORKFLOWS


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


def collect_for_sha(
    *,
    repo: str,
    sha: str,
    limit: int = 50,
    required_event: str | None = None,
) -> dict[str, Any]:
    fields = (
        "databaseId,displayTitle,workflowName,status,conclusion,url,"
        "headSha,createdAt,event"
    )
    command = [
        "run",
        "list",
        "--repo",
        repo,
        "--commit",
        sha,
        "--limit",
        str(limit),
        "--json",
        fields,
    ]
    if required_event:
        command.extend(["--event", required_event])
    code, stdout, stderr = _run_gh(command)
    collected_at = datetime.now(timezone.utc).isoformat()
    common = {
        "benchmark_source_sha": sha,
        "verified_source_sha": None,
        "required_workflow_names": list(REQUIRED_WORKFLOWS),
        "required_event": required_event,
        "collected_at": collected_at,
    }
    if code != 0:
        return {
            "ok": False,
            "collection_ok": False,
            "complete_required_set": False,
            "blocker": "gh_run_list_failed",
            "detail": stderr.strip() or stdout.strip() or "gh run list failed",
            **common,
            "observed_workflow_names": [],
            "missing_workflow_names": list(REQUIRED_WORKFLOWS),
            "runs": [],
        }

    try:
        runs = json.loads(stdout or "[]")
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "collection_ok": False,
            "complete_required_set": False,
            "blocker": "gh_run_list_invalid_json",
            "detail": str(exc),
            **common,
            "observed_workflow_names": [],
            "missing_workflow_names": list(REQUIRED_WORKFLOWS),
            "runs": [],
        }

    if not isinstance(runs, list):
        runs = []
    normalized_runs = [run for run in runs if isinstance(run, dict)]
    if required_event:
        normalized_runs = [
            run for run in normalized_runs if str(run.get("event") or "") == required_event
        ]

    by_workflow: dict[str, list[dict[str, Any]]] = {}
    for run in normalized_runs:
        name = str(run.get("workflowName") or "unknown")
        by_workflow.setdefault(name, []).append(run)
    observed = sorted(by_workflow)
    missing = [name for name in REQUIRED_WORKFLOWS if name not in by_workflow]
    complete = not missing

    return {
        "ok": complete,
        "collection_ok": True,
        "complete_required_set": complete,
        "blocker": None if complete else "required_workflows_missing",
        "detail": None if complete else "missing: " + ", ".join(missing),
        **common,
        "observed_workflow_names": observed,
        "missing_workflow_names": missing,
        "runs": normalized_runs,
        "note": (
            "These are untrusted observations used to draft a release ledger. "
            "Only independent live run-ID resolution may mint verified_source_sha."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect candidate-bound GitHub workflow observations"
    )
    parser.add_argument("--repo", default="fraware/open-verification-kernel")
    parser.add_argument("--sha", required=True, help="Source commit SHA")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--ledger-output",
        type=Path,
        default=None,
        help="Optional path to write an unauthorized release-ledger draft",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum GitHub workflow records to inspect",
    )
    parser.add_argument(
        "--required-event",
        default=None,
        help="Optional exact GitHub Actions event, e.g. workflow_dispatch for release evidence.",
    )
    args = parser.parse_args(argv)

    payload = collect_for_sha(
        repo=args.repo,
        sha=args.sha,
        limit=args.limit,
        required_event=args.required_event,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if args.ledger_output is not None:
        from ovk.core.release_ledger import ledger_from_collect_workflow_evidence

        sha = args.sha.lower()
        ledger = ledger_from_collect_workflow_evidence(
            args.repo_root.resolve(),
            evidence=payload,
            candidate_sha=sha,
        )
        args.ledger_output.parent.mkdir(parents=True, exist_ok=True)
        args.ledger_output.write_text(
            json.dumps(ledger, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            f"draft release ledger -> {args.ledger_output} "
            "(authorized=false; provenance unverified)"
        )

    if not payload.get("ok"):
        print(
            f"blocked: {payload.get('blocker')}: {payload.get('detail')}",
            file=sys.stderr,
        )
        return 2

    event_note = f", event={args.required_event}" if args.required_event else ""
    print(
        f"collected complete required workflow set for "
        f"benchmark_source_sha={args.sha}{event_note}; verified_source_sha remains unset"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
