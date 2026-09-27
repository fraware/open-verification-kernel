#!/usr/bin/env python
"""Run pinned external-repository assurance replay cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.core.external_assurance_replay import (
    load_external_assurance_replay_suite,
    run_external_assurance_replay_suite,
    validate_external_assurance_replay_report,
)
from ovk.core.json_io import write_json_file
from ovk.paths import ensure_repo_on_path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / ".verification" / "external-assurance-replay-report.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Replay pinned external GitHub revisions through OVK's durable "
            "assurance qualification path"
        )
    )
    parser.add_argument("suite", type=Path, help="External replay suite JSON")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Machine-readable external replay report",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print report without writing it",
    )
    return parser.parse_args()


def main() -> int:
    ensure_repo_on_path()
    args = parse_args()
    suite = load_external_assurance_replay_suite(args.suite)
    report = run_external_assurance_replay_suite(suite)
    validate_external_assurance_replay_report(report)
    payload = report.model_dump(mode="json")

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json_file(args.output, payload)
    print(
        json.dumps(
            {
                "suite_id": report.suite_id,
                "cases_total": report.cases_total,
                "results": [
                    {
                        "case_id": item.case_id,
                        "repository": item.repository,
                        "expectation_met": (
                            item.qualification_result.expectation_met
                        ),
                        "unsafe_false_assurance": (
                            item.qualification_result.unsafe_false_assurance
                        ),
                        "semantic_coverage_complete": (
                            item.qualification_result.semantic_coverage_complete
                        ),
                    }
                    for item in report.results
                ],
            },
            indent=2,
        )
    )
    print(f"wrote external assurance replay report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
