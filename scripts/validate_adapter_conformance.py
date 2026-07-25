#!/usr/bin/env python
"""Validate the seven-item adapter conformance matrix (OVK-PR4 / OVK-05)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.adapter_conformance import (  # noqa: E402
    ADVERTISED_ADAPTER_IDS,
    is_fully_conformant,
    validate_all_adapter_conformance,
)
from ovk.core.capabilities import CapabilityRegistry  # noqa: E402
from ovk.core.adapter_conformance import stable_requires_conformance_failures  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate OVK adapter conformance fixtures (pass/fail/malformed/timeout/unavailable + docs)"
    )
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument(
        "--adapter",
        action="append",
        dest="adapters",
        help="Validate one advertised adapter id (repeatable). Defaults to all advertised adapters.",
    )
    parser.add_argument(
        "--structural-only",
        action="store_true",
        help="Only check that the seven artifacts exist (skip evaluation/seal).",
    )
    parser.add_argument(
        "--no-seal",
        action="store_true",
        help="Evaluate fixtures but skip evidence integrity sealing.",
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    adapters = tuple(args.adapters) if args.adapters else ADVERTISED_ADAPTER_IDS

    if args.structural_only:
        from ovk.core.adapter_conformance import structural_conformance_failures

        failures: list[str] = []
        for adapter_id in adapters:
            failures.extend(structural_conformance_failures(adapter_id, root=root))
    else:
        failures = validate_all_adapter_conformance(
            root=root,
            seal=not args.no_seal,
            adapters=adapters,
        )

    # Also enforce: no capability.json may claim stable without conformance.
    registry = CapabilityRegistry.from_directory(root / "adapters", validate=False)
    failures.extend(stable_requires_conformance_failures(registry.all(), root=root))

    for failure in failures:
        print(failure)
    if failures:
        return 1

    conformant = sum(1 for adapter_id in adapters if is_fully_conformant(adapter_id, root=root, seal=False))
    print(
        f"OVK adapter conformance passed "
        f"({len(adapters)} adapters checked, {conformant} structurally complete)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
