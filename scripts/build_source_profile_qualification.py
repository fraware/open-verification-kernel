#!/usr/bin/env python
"""Build machine-derived .verification/source-profile-qualification.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.source_profile_qualification import (  # noqa: E402
    build_source_profile_qualification,
    qualification_output_path,
    write_source_profile_qualification,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build source-profile qualification artifact")
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Rebuild and require on-disk artifact to match (when present) plus schema validity",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    output = (args.output or qualification_output_path(repo_root)).resolve()

    payload = write_source_profile_qualification(repo_root, output)
    print(
        f"source-profile qualification: {len(payload.get('profiles') or {})} profiles -> {output}"
    )
    for profile_id, row in sorted((payload.get("profiles") or {}).items()):
        maturity = row.get("maturity")
        unmet = (row.get("qualification") or {}).get("unmet_strict_obligations") or []
        print(f"  {profile_id}: {maturity} unmet={len(unmet)}")

    if args.check:
        expected = build_source_profile_qualification(repo_root)
        on_disk = json.loads(output.read_text(encoding="utf-8"))
        if on_disk != expected:
            print("source-profile-qualification.json is stale; regenerate", file=sys.stderr)
            return 1
        if on_disk.get("maturity_contract", {}).get("externally_calibrated_strict_locally_derivable"):
            print("externally_calibrated_strict must remain non-local", file=sys.stderr)
            return 1
        print("source-profile qualification gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
