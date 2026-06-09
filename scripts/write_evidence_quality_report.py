#!/usr/bin/env python
"""Write an OVK evidence quality report."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.json_io import read_json_file, write_json_file
from ovk.core.models import EvidenceBundle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write an OVK evidence quality report")
    parser.add_argument("bundle", type=Path, help="Evidence bundle JSON")
    parser.add_argument("--output", type=Path, default=Path("ovk-evidence-quality.json"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    bundle = EvidenceBundle.model_validate(read_json_file(args.bundle))
    report = build_evidence_quality_report(bundle)
    write_json_file(args.output, report.to_dict())
    for issue in report.issues:
        print(f"{issue.severity}: {issue.path}: {issue.message}")
    if not report.passed:
        return 1
    print(f"OVK evidence quality report passed: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
