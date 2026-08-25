#!/usr/bin/env python
"""Build a draft release ledger from local evidence only (WP-17).

Never invents green required-run IDs. Offline verify fail-closes when
required_runs / consumers / holdout / artifacts are incomplete.
Does not tag or publish.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.release_ledger import (  # noqa: E402
    build_release_ledger,
    verify_release_ledger,
    write_release_ledger,
)


def _git_sha(repo_root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    sha = completed.stdout.strip().lower()
    if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
        return sha
    return None


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Draft local release ledger (no publish)")
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--candidate-sha", default=None)
    parser.add_argument(
        "--workflow-evidence",
        type=Path,
        default=None,
        help="Optional JSON from scripts/collect_workflow_evidence.py",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Default: .verification/release-ledger.json",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Also require artifacts/consumers/holdout digests (still fail-closed without them)",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    candidate = (args.candidate_sha or _git_sha(repo_root) or "").lower()
    if len(candidate) != 40:
        print("fail-closed: candidate_sha unavailable; pass --candidate-sha", file=sys.stderr)
        return 1

    workflow_evidence = {"ok": True, "runs": [], "blocker": None}
    if args.workflow_evidence is not None:
        if not args.workflow_evidence.is_file():
            print(f"fail-closed: workflow evidence missing: {args.workflow_evidence}", file=sys.stderr)
            return 1
        workflow_evidence = json.loads(args.workflow_evidence.read_text(encoding="utf-8"))

    # Local open P0 list from project-status when present; never invent green runs.
    status_path = repo_root / ".verification" / "project-status.json"
    p0_notes: list[str] = []
    if status_path.is_file():
        status = json.loads(status_path.read_text(encoding="utf-8"))
        for item in status.get("open_p0") or status.get("p0_blockers") or []:
            p0_notes.append(str(item))

    holdout = {
        "candidate_source_sha": candidate,
        "predictions_sha256": _sha256_file(repo_root / ".verification" / "holdout-predictions.json"),
        "aggregate_sha256": _sha256_file(repo_root / ".verification" / "holdout-aggregate.json"),
        "holdout_tag": None,
    }
    artifacts = {
        "wheel_sha256": _sha256_file(repo_root / "dist" / ".wheel-sha256"),
        "sdist_sha256": _sha256_file(repo_root / "dist" / ".sdist-sha256"),
        "sbom_sha256": _sha256_file(repo_root / "dist" / "sbom.cdx.json")
        or _sha256_file(repo_root / ".verification" / "sbom.cdx.json"),
        "sigstore_summary_sha256": None,
    }

    ledger = build_release_ledger(
        repo_root,
        candidate_sha=candidate,
        workflow_evidence=workflow_evidence,
        holdout=holdout,
        artifacts=artifacts,
    )
    # Surface local incomplete status as evidence notes (not forged success).
    evidence = dict(ledger.get("evidence") or {})
    blockers = list(evidence.get("p0_blockers") or [])
    if not (workflow_evidence.get("runs") or []):
        blockers.append("required_runs_absent_local_draft")
    blockers.extend(f"status:{note}" for note in p0_notes)
    evidence["p0_blockers"] = sorted(set(blockers))
    evidence["claim_registry_sha256"] = _sha256_file(repo_root / ".verification" / "claim-registry.json")
    evidence["project_status_sha256"] = _sha256_file(status_path)
    ledger["evidence"] = evidence

    out = (args.output or (repo_root / ".verification" / "release-ledger.json")).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    ok, failures, authorized = verify_release_ledger(
        ledger,
        repo_root=repo_root,
        require_artifacts=args.require_complete,
        require_consumers=args.require_complete,
        require_holdout=args.require_complete,
    )
    print(f"draft ledger -> {out}")
    print(f"offline_verify ok={ok} authorized={authorized['release_state']['authorized']}")
    for failure in failures:
        print(f"  fail-closed: {failure}", file=sys.stderr)
    # Local draft is expected to fail closed without live GHA run IDs.
    if ok:
        write_release_ledger(repo_root, authorized)
        print("unexpected: local draft authorized without complete evidence", file=sys.stderr)
        return 2
    print(
        "expected fail-closed: fill required run IDs via "
        "scripts/collect_workflow_evidence.py --ledger-output ..."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
