#!/usr/bin/env python
"""Write a manifest for standard OVK runner outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.core.standard_artifacts import standard_run_manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write a manifest for standard OVK outputs")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("ovk-artifact-manifest.json"))
    parser.add_argument("--root", type=Path, default=None, help="Optional root used for relative artifact paths")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = standard_run_manifest(
        evidence_path=args.evidence,
        markdown_path=args.markdown,
        attestation_path=args.attestation,
        root=args.root,
    )
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote OVK standard run manifest to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
