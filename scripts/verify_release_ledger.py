#!/usr/bin/env python
"""Offline release-ledger verifier (WP-17). Never tags or publishes."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.release_ledger import verify_release_ledger, write_release_ledger  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify OVK release ledger offline")
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--require-artifacts", action="store_true")
    parser.add_argument("--require-consumers", action="store_true")
    parser.add_argument("--require-holdout", action="store_true")
    parser.add_argument("--write", type=Path, default=None)
    args = parser.parse_args()
    payload = json.loads(args.ledger.read_text(encoding="utf-8"))
    ok, failures, authorized = verify_release_ledger(
        payload,
        repo_root=args.repo_root.resolve(),
        require_artifacts=args.require_artifacts,
        require_consumers=args.require_consumers,
        require_holdout=args.require_holdout,
    )
    for failure in failures:
        print(failure, file=sys.stderr)
    if args.write is not None:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(json.dumps(authorized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    elif ok:
        write_release_ledger(args.repo_root.resolve(), authorized)
    if not ok:
        return 1
    print(
        "authorized verified_source_sha="
        f"{authorized['release_state']['verified_source_sha']} published=false tag=null"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
