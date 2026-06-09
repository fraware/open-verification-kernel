#!/usr/bin/env python
"""Write an OVK attestation envelope."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ovk.core.attestation_envelope import build_attestation_envelope


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write an OVK attestation envelope")
    parser.add_argument("--statement", type=Path, required=True, help="Unsigned attestation statement JSON")
    parser.add_argument("--manifest", type=Path, required=True, help="Artifact manifest JSON")
    parser.add_argument("--output", type=Path, default=Path("ovk-attestation-envelope.json"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    statement = json.loads(args.statement.read_text(encoding="utf-8"))
    envelope = build_attestation_envelope(statement=statement, manifest_path=args.manifest)
    args.output.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote OVK attestation envelope to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
