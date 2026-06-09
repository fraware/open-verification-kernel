#!/usr/bin/env python
"""Run the obligation-backed authorization path."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.adapters.z3.evidence import authorization_result_to_evidence
from ovk.adapters.z3.executor import run_authorization_obligation_with_z3
from ovk.adapters.z3.obligation import build_authorization_obligation
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
    data = json.loads(args.input.read_text(encoding="utf-8"))
    obligation = build_authorization_obligation(data)
    raw = run_authorization_obligation_with_z3(obligation)
    evidence = authorization_result_to_evidence(
        raw,
        obligation,
        repo=args.repo,
        head_sha=args.head_sha,
        base_sha=args.base_sha,
        author_type=str(data.get("author_type", "unknown")),
        agent=str(data.get("agent", "unknown")),
        task=str(data.get("task", "unknown")),
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

    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    print(f"OVK authorization recommendation: {recommendation}")
    if args.advisory:
        return 0
    return EXIT_CODES.get(recommendation, 2)


if __name__ == "__main__":
    raise SystemExit(main())
