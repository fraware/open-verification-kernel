#!/usr/bin/env python
"""Authorize an OVK release ledger against live GitHub Actions provenance.

Unlike the offline structural checker, this command resolves every ledger run
ID through GitHub's API and only then permits ``verified_source_sha`` to be set.
It never tags, creates a GitHub Release, signs artifacts, or publishes to PyPI.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.release_ledger import verify_release_ledger  # noqa: E402


def _run_gh_api(repo: str, run_id: int) -> Mapping[str, Any]:
    try:
        completed = subprocess.run(
            ["gh", "api", f"repos/{repo}/actions/runs/{run_id}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"gh api execution failed: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "gh api failed"
        raise RuntimeError(detail)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("gh api returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("gh api returned a non-object workflow run")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Authorize an OVK release ledger using live GitHub Actions provenance"
    )
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--require-artifacts", action="store_true")
    parser.add_argument("--require-consumers", action="store_true")
    parser.add_argument("--require-holdout", action="store_true")
    parser.add_argument(
        "--write",
        type=Path,
        required=True,
        help="Output path for the provenance-authorized ledger",
    )
    args = parser.parse_args(argv)

    payload = json.loads(args.ledger.read_text(encoding="utf-8"))
    ok, failures, authorized = verify_release_ledger(
        payload,
        repo_root=args.repo_root.resolve(),
        workflow_run_resolver=_run_gh_api,
        require_artifacts=args.require_artifacts,
        require_consumers=args.require_consumers,
        require_holdout=args.require_holdout,
    )
    for failure in failures:
        print(failure, file=sys.stderr)
    if not ok:
        return 1

    args.write.parent.mkdir(parents=True, exist_ok=True)
    args.write.write_text(
        json.dumps(authorized, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "authorized verified_source_sha="
        f"{authorized['release_state']['verified_source_sha']} "
        "via live GitHub workflow provenance; published=false tag=null"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
