#!/usr/bin/env python
"""Run the durable-assurance product qualification suite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.core.assurance_qualification import (
    load_assurance_qualification_suite,
    run_assurance_qualification_suite,
    validate_assurance_qualification_report,
)
from ovk.core.json_io import write_json_file
from ovk.paths import ensure_repo_on_path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUITE = (
    ROOT / "benchmarks" / "assurance_qualification" / "suite.v1.json"
)
DEFAULT_OUTPUT = (
    ROOT / ".verification" / "assurance-qualification-report.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run production-shaped durable-assurance qualification cases "
            "through the ordinary ovk check path"
        )
    )
    parser.add_argument(
        "--suite",
        type=Path,
        default=DEFAULT_SUITE,
        help="Qualification suite JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output report JSON",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the report without writing it",
    )
    return parser.parse_args()


def main() -> int:
    ensure_repo_on_path()
    args = parse_args()
    suite = load_assurance_qualification_suite(args.suite)
    report = run_assurance_qualification_suite(suite)
    validate_assurance_qualification_report(report)
    payload = report.model_dump(mode="json")

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json_file(args.output, payload)

    summary = {
        "suite_id": report.suite_id,
        "cases_total": report.cases_total,
        "metrics": report.metrics.model_dump(mode="json"),
        "evidence_classes": report.evidence_classes.model_dump(mode="json"),
        "qualification": report.qualification.model_dump(mode="json"),
    }
    print(json.dumps(summary, indent=2))
    print(f"wrote assurance qualification report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
