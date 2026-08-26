#!/usr/bin/env python
"""Offline release-ledger structural checker (WP-17).

This command deliberately cannot authorize a release or mint
``verified_source_sha`` because workflow provenance is not independently
available offline. Use ``verify_release_ledger_github.py`` for authorization.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.release_ledger import validate_release_ledger_structure  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate OVK release-ledger structure offline (never authorizes)"
    )
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--require-artifacts", action="store_true")
    parser.add_argument("--require-consumers", action="store_true")
    parser.add_argument("--require-holdout", action="store_true")
    parser.add_argument(
        "--write",
        type=Path,
        default=None,
        help="Optional path for a normalized unauthorized ledger copy",
    )
    args = parser.parse_args(argv)

    payload = json.loads(args.ledger.read_text(encoding="utf-8"))
    failures = validate_release_ledger_structure(
        payload,
        repo_root=args.repo_root.resolve(),
        require_artifacts=args.require_artifacts,
        require_consumers=args.require_consumers,
        require_holdout=args.require_holdout,
    )
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1

    output = json.loads(json.dumps(payload))
    output["release_state"] = {
        "authorized": False,
        "verified_source_sha": None,
        "tag": None,
        "published": False,
        "authorization_reason": "offline_structural_validation_only",
    }
    output["evidence"] = dict(output.get("evidence") or {})
    output["evidence"]["workflow_provenance"] = None
    if args.write is not None:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(
            json.dumps(output, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(
        "release ledger structurally valid; NOT authorized "
        "(live GitHub workflow provenance required)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
