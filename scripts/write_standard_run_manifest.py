#!/usr/bin/env python
"""Write a manifest for standard OVK runner outputs."""

from __future__ import annotations

import argparse
from pathlib import Path

from ovk.core.json_io import write_json_file
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
    write_json_file(args.output, manifest)
    print(f"Wrote OVK standard run manifest to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
