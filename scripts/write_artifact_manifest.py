#!/usr/bin/env python
"""Write a deterministic OVK artifact manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.core.artifact_manifest import artifact_entry, build_artifact_manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write an OVK artifact manifest")
    parser.add_argument("--artifact", action="append", default=[], help="Artifact path to include")
    parser.add_argument(
        "--kind", action="append", default=[], help="Optional artifact kind, aligned with --artifact order"
    )
    parser.add_argument("--root", type=Path, default=Path("."), help="Root used for relative paths")
    parser.add_argument("--output", type=Path, default=Path("ovk-artifact-manifest.json"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.kind and len(args.kind) != len(args.artifact):
        raise SystemExit("--kind must be supplied once per --artifact when used")
    kinds = args.kind or ["artifact"] * len(args.artifact)
    entries = [
        artifact_entry(Path(path), kind=kind, root=args.root) for path, kind in zip(args.artifact, kinds, strict=True)
    ]
    manifest = build_artifact_manifest(entries)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote OVK artifact manifest to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
