#!/usr/bin/env python
"""Run the Sprint 1 v0 self-protection path."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.core.sprint1_runner import (
    build_metadata_from_inputs,
    run_sprint1_self_protection,
    write_sprint1_outputs,
)


EXIT_CODES = {
    "allow": 0,
    "allow_with_warning": 0,
    "block": 1,
    "require_human_review": 2,
    "require_stronger_check": 2,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run OVK v0 self-protection path")
    parser.add_argument("metadata", type=Path, nargs="?", help="JSON metadata input")
    parser.add_argument("--changed-files", type=Path, default=None)
    parser.add_argument("--check-metadata", type=Path, default=None)
    parser.add_argument("--github-event", type=Path, default=None)
    parser.add_argument("--backend-strategy", default="deterministic", choices=["deterministic", "opa", "both"])
    parser.add_argument("--repo", default="unknown/repo")
    parser.add_argument("--head-sha", default="unknown")
    parser.add_argument("--base-sha", default=None)
    parser.add_argument("--evidence-output", type=Path, default=Path("ovk-evidence.json"))
    parser.add_argument("--markdown-output", type=Path, default=Path("ovk-pr-comment.md"))
    parser.add_argument("--attestation-output", type=Path, default=Path("ovk-attestation.json"))
    parser.add_argument("--advisory", action="store_true", help="Always exit 0 after writing outputs")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metadata = build_metadata_from_inputs(
        metadata_path=args.metadata,
        changed_files_path=args.changed_files,
        check_metadata_path=args.check_metadata,
        github_event_path=args.github_event,
    )
    result = run_sprint1_self_protection(
        metadata=metadata,
        repo=args.repo,
        head_sha=args.head_sha,
        base_sha=args.base_sha,
        backend_strategy=args.backend_strategy,
    )
    write_sprint1_outputs(
        result,
        evidence_output=args.evidence_output,
        markdown_output=args.markdown_output,
        attestation_output=args.attestation_output,
    )

    print(f"OVK recommendation: {result.recommendation}")
    if args.advisory:
        return 0
    return EXIT_CODES.get(result.recommendation, 2)


if __name__ == "__main__":
    raise SystemExit(main())
