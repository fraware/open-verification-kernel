#!/usr/bin/env python
"""Build the normative Template Conformance v3 machine artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.template_conformance_v3 import (  # noqa: E402
    domain_counts_markdown,
    validate_matrix,
    write_conformance_matrix,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build OVK Template Conformance v3 matrix")
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path (default: docs/benchmarks/template-conformance.json)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero when the matrix fails gate validation or committed bytes are stale",
    )
    parser.add_argument(
        "--print-domain-counts",
        action="store_true",
        help="Print README-style domain counts derived from the matrix",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    output = (args.output or (repo_root / "docs" / "benchmarks" / "template-conformance.json")).resolve()

    # Freshness: rebuild into memory first, then compare or write.
    from ovk.core.template_conformance_v3 import build_conformance_matrix

    matrix = build_conformance_matrix(repo_root)
    failures = validate_matrix(matrix)
    if args.print_domain_counts:
        sys.stdout.write(domain_counts_markdown(matrix))
    print(
        f"template conformance v3: {matrix['template_count']} templates -> {output}"
        f" (candidate={matrix.get('counts_by_status_v3', {}).get('source_profile_candidate', 0)},"
        f" strict={matrix.get('counts_by_status_v3', {}).get('source_profile_strict_eligible', 0)},"
        f" catalog_only={matrix.get('counts_by_status_v3', {}).get('catalog_only', 0)})"
    )
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    if args.check:
        if not output.is_file():
            print(f"committed conformance artifact missing: {output}", file=sys.stderr)
            return 1
        on_disk = json.loads(output.read_text(encoding="utf-8"))
        disk_failures = validate_matrix(on_disk)
        if disk_failures:
            for failure in disk_failures:
                print(failure, file=sys.stderr)
            return 1
        expected_text = json.dumps(matrix, indent=2, sort_keys=True) + "\n"
        actual_text = output.read_text(encoding="utf-8")
        if actual_text != expected_text:
            print(
                "template-conformance.json is stale vs exact-head generation; "
                "run: python scripts/build_template_conformance.py",
                file=sys.stderr,
            )
            return 1
        if on_disk.get("maturity_contract", {}).get("normative_status_field") != "conformance_status_v3":
            print("maturity_contract must declare conformance_status_v3 as normative", file=sys.stderr)
            return 1
        print("template conformance v3 freshness gate passed")
        return 0

    write_conformance_matrix(repo_root, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
