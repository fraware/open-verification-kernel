#!/usr/bin/env python
"""Run the infrastructure exposure path."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.adapters.infra.normalize import normalize_infra_input
from ovk.adapters.infra.policy_config import load_policy
from ovk.core.artifact_manifest import artifact_entry, build_artifact_manifest
from ovk.core.attestation import bundle_to_statement
from ovk.core.bundle import make_bundle
from ovk.core.render import render_bundle_markdown


EXIT_CODES = {
    "allow": 0,
    "allow_with_warning": 0,
    "block": 1,
    "require_human_review": 2,
    "require_stronger_check": 2,
}


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
    parser.add_argument("--advisory", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_data = json.loads(args.input.read_text(encoding="utf-8"))
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
    markdown = render_bundle_markdown(bundle)
    attestation = bundle_to_statement(bundle)

    args.evidence_output.write_text(
        json.dumps(bundle.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    args.markdown_output.write_text(markdown, encoding="utf-8")
    args.attestation_output.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")

    manifest = build_artifact_manifest(
        [
            artifact_entry(args.evidence_output, kind="evidence"),
            artifact_entry(args.markdown_output, kind="markdown"),
            artifact_entry(args.attestation_output, kind="attestation"),
        ]
    )
    args.manifest_output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    print(f"OVK infrastructure recommendation: {recommendation}")
    if args.advisory:
        return 0
    return EXIT_CODES.get(recommendation, 2)


if __name__ == "__main__":
    raise SystemExit(main())
