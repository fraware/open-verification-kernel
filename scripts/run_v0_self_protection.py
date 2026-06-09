#!/usr/bin/env python
"""Run the Sprint 1 v0 self-protection path.

This runner accepts a JSON metadata object, normalizes it into the canonical
self-protection adapter input, evaluates the check, and emits evidence, Markdown,
and an unsigned attestation statement.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ovk.adapters.opa import evaluate_self_protection
from ovk.core.attestation import bundle_to_statement
from ovk.core.bundle import make_bundle
from ovk.core.render import render_bundle_markdown
from ovk.core.self_protection_input import build_from_json_like


EXIT_CODES = {
    "allow": 0,
    "allow_with_warning": 0,
    "block": 1,
    "require_human_review": 2,
    "require_stronger_check": 2,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run OVK v0 self-protection path")
    parser.add_argument("metadata", type=Path, help="JSON metadata input")
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
    raw = json.loads(args.metadata.read_text(encoding="utf-8"))
    adapter_input = build_from_json_like(raw)
    evidence = evaluate_self_protection(
        adapter_input,
        repo=args.repo,
        head_sha=args.head_sha,
        base_sha=args.base_sha,
    )
    bundle = make_bundle([evidence])
    statement = bundle_to_statement(bundle)

    args.evidence_output.write_text(
        json.dumps(bundle.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    args.markdown_output.write_text(render_bundle_markdown(bundle), encoding="utf-8")
    args.attestation_output.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")

    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    print(f"OVK recommendation: {recommendation}")
    if args.advisory:
        return 0
    return EXIT_CODES.get(recommendation, 2)


if __name__ == "__main__":
    raise SystemExit(main())
