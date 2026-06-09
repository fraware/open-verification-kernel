#!/usr/bin/env python
"""Write infrastructure regression artifacts from an OVK evidence bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_OUTPUT = Path(".verification/generated_tests/test_no_public_sensitive_resource.py")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write infrastructure regression artifacts")
    parser.add_argument("evidence_bundle", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def _artifact_contents(bundle: dict[str, Any]) -> str:
    for evidence in bundle.get("evidence", []):
        if not isinstance(evidence, dict):
            continue
        for artifact in evidence.get("generated_artifacts", []):
            if not isinstance(artifact, dict):
                continue
            if artifact.get("kind") == "regression_unit_test" and artifact.get("content"):
                return str(artifact["content"])
    return "# No infrastructure regression artifact was available.\n"


def main() -> int:
    args = parse_args()
    bundle = json.loads(args.evidence_bundle.read_text(encoding="utf-8"))
    rendered = _artifact_contents(bundle)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"Wrote infrastructure regression artifact to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
