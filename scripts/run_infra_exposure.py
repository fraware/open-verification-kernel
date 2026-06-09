#!/usr/bin/env python
"""Run the infrastructure exposure path."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.infra.normalize import normalize_infra_input
from ovk.adapters.infra.policy_config import load_policy
from ovk.core.bundle import make_bundle
from ovk.core.exit_codes import exit_code_for_recommendation
from ovk.core.json_io import read_json_file
from ovk.core.run_outputs import StandardOutputPaths, write_standard_run_outputs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run OVK infrastructure exposure path")
    parser.add_argument("input", type=Path, help="Infrastructure input JSON")
    parser.add_argument("--input-format", default="infra", choices=["infra", "terraform", "kubernetes"])
    parser.add_argument("--policy", type=Path, default=None, help="Optional infrastructure exposure policy JSON")
    parser.add_argument("--repo", default="unknown/repo")
    parser.add_argument("--head-sha", default="unknown")
    parser.add_argument("--base-sha", default=None)
    parser.add_argument("--evidence-output", type=Path, default=Path("ovk-infra-evidence.json"))
    parser.add_argument("--markdown-output", type=Path, default=Path("ovk-infra-comment.md"))
    parser.add_argument("--attestation-output", type=Path, default=Path("ovk-infra-attestation.json"))
    parser.add_argument("--manifest-output", type=Path, default=Path("ovk-infra-artifact-manifest.json"))
    parser.add_argument("--quality-output", type=Path, default=Path("ovk-infra-evidence-quality.json"))
    parser.add_argument("--advisory", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_data = read_json_file(args.input)
    data = normalize_infra_input(raw_data, args.input_format)
    policy = load_policy(args.policy)
    evidence = evaluate_infra_exposure(
        data,
        repo=args.repo,
        head_sha=args.head_sha,
        base_sha=args.base_sha,
        policy=policy,
    )
    bundle = make_bundle([evidence])
    write_standard_run_outputs(
        bundle,
        StandardOutputPaths(
            evidence=args.evidence_output,
            markdown=args.markdown_output,
            attestation=args.attestation_output,
            manifest=args.manifest_output,
            quality_report=args.quality_output,
        ),
    )

    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    print(f"OVK infrastructure recommendation: {recommendation}")
    if args.advisory:
        return 0
    return exit_code_for_recommendation(recommendation)


if __name__ == "__main__":
    raise SystemExit(main())
