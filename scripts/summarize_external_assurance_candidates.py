#!/usr/bin/env python
"""Summarize the external assurance candidate coverage denominator."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.core.external_candidate_registry import (
    load_external_candidate_registry,
    summarize_external_candidate_coverage,
)
from ovk.paths import ensure_repo_on_path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = (
    ROOT
    / "benchmarks"
    / "assurance_qualification"
    / "external_candidates.v1.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize representational coverage over external security "
            "candidates reviewed before model-specific selection"
        )
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=DEFAULT_REGISTRY,
    )
    return parser.parse_args()


def main() -> int:
    ensure_repo_on_path()
    args = parse_args()
    registry = load_external_candidate_registry(args.registry)
    summary = summarize_external_candidate_coverage(registry)
    print(json.dumps(summary.model_dump(mode="json"), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
