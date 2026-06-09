#!/usr/bin/env python
"""Run the validated obligation-backed authorization path."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
from ovk.core.bundle import make_bundle
from ovk.core.exit_codes import exit_code_for_recommendation
from ovk.core.json_io import read_json_file
from ovk.core.run_outputs import StandardOutputPaths, write_standard_run_outputs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run OVK authorization obligation path")
    parser.add_argument("input", type=Path, help="Authorization fixture JSON")
    parser.add_argument("--repo", default="unknown/repo")
    parser.add_argument("--head-sha", default="unknown")
    parser.add_argument("--base-sha", default=None)
    parser.add_argument("--evidence-output", type=Path, default=Path("ovk-auth-evidence.json"))
    parser.add_argument("--markdown-output", type=Path, default=Path("ovk-auth-comment.md"))
    parser.add_argument("--attestation-output", type=Path, default=Path("ovk-auth-attestation.json"))
    parser.add_argument("--advisory", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data = read_json_file(args.input)
    evidence = evaluate_validated_authorization_path(
        data,
        repo=args.repo,
        head_sha=args.head_sha,
        base_sha=args.base_sha,
    )
    bundle = make_bundle([evidence])
    write_standard_run_outputs(
        bundle,
        StandardOutputPaths(
            evidence=args.evidence_output,
            markdown=args.markdown_output,
            attestation=args.attestation_output,
        ),
    )

    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    print(f"OVK authorization recommendation: {recommendation}")
    if args.advisory:
        return 0
    return exit_code_for_recommendation(recommendation)


if __name__ == "__main__":
    raise SystemExit(main())
