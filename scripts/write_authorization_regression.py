#!/usr/bin/env python
"""Write authorization regression tests from an OVK evidence bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.adapters.z3.regression import render_authorization_regression_suite


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write authorization regression tests")
    parser.add_argument("evidence_bundle", type=Path)
    parser.add_argument("--output", type=Path, default=Path("test_no_admin_route_bypass.py"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    bundle = json.loads(args.evidence_bundle.read_text(encoding="utf-8"))
    counterexamples = []
    for evidence in bundle.get("evidence", []):
        if isinstance(evidence, dict):
            counterexamples.extend(evidence.get("counterexamples", []))
    rendered = render_authorization_regression_suite(counterexamples)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"Wrote authorization regression test to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
