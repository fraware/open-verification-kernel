#!/usr/bin/env python
"""Check OVK evidence bundle invariants."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.core.evidence_invariants import check_evidence_bundle_invariants
from ovk.core.json_io import read_json_file
from ovk.core.models import EvidenceBundle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check OVK evidence bundle invariants")
    parser.add_argument("bundle", type=Path, help="Evidence bundle JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    bundle = EvidenceBundle.model_validate(read_json_file(args.bundle))
    issues = check_evidence_bundle_invariants(bundle)
    for issue in issues:
        print(f"{issue.severity}: {issue.path}: {issue.message}")
    if any(issue.severity == "error" for issue in issues):
        return 1
    print("OVK evidence bundle invariants passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
