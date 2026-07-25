#!/usr/bin/env python
"""Verify in-repo OVK-PR9 / program Definition-of-Done items.

Live attributable publication gates (non-[skip ci] workflow IDs, Sigstore,
consumer remote pins) are listed as remaining maintainer actions and do not
fail this script.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.adapter_conformance import (  # noqa: E402
    ADVERTISED_ADAPTER_IDS,
    apply_release_status_honesty,
    is_fully_conformant,
)
from ovk.core.capabilities import CapabilityRegistry  # noqa: E402
from ovk.core.release_metadata import OVK_RELEASE_CANDIDATE  # noqa: E402

PILOT_ROOT = ROOT / "docs" / "pilots"
BENCH_MANIFEST = ROOT / "benchmarks" / "formal_pr_bench" / "manifest.v1.json"
TCB_DOC = ROOT / "docs" / "TRUSTED_COMPUTING_BASE.md"
DECISION_TRUTH = ROOT / "tests" / "test_decision_lattice_truth_table.py"
EVIDENCE_SUITE = ROOT / "tests" / "test_evidence_integrity_suite.py"


def _check_registry_coverage(repo_root: Path) -> list[str]:
    failures: list[str] = []
    registry = CapabilityRegistry.from_directory(repo_root / "adapters", validate=True)
    by_id = {
        str(m.get("checker_id") or m.get("tool", {}).get("name")): apply_release_status_honesty(
            dict(m), root=repo_root
        )
        for m in registry.all()
    }
    missing = [cid for cid in ADVERTISED_ADAPTER_IDS if cid not in by_id]
    if missing:
        failures.append("registry missing public checkers: " + ", ".join(missing))

    for checker_id, manifest in by_id.items():
        if checker_id not in ADVERTISED_ADAPTER_IDS:
            continue
        if manifest.get("release_status") != "stable":
            continue
        if not is_fully_conformant(checker_id, root=repo_root):
            failures.append(f"stable checker not fully conformant: {checker_id}")
    return failures


def _check_strict_fail_closed_tests() -> list[str]:
    failures: list[str] = []
    if not DECISION_TRUTH.exists():
        failures.append(f"missing decision lattice truth-table tests: {DECISION_TRUTH}")
    if not EVIDENCE_SUITE.exists():
        failures.append(f"missing evidence integrity suite: {EVIDENCE_SUITE}")
    return failures


def _check_evidence_controlling_decision() -> list[str]:
    """Ensure evidence integrity APIs that reconstruct controlling decisions exist."""
    failures: list[str] = []
    try:
        from ovk.core import evidence_integrity
        from ovk.core import decision as decision_mod
    except ImportError as exc:  # pragma: no cover
        return [f"evidence/decision import failed: {exc}"]
    required = (
        "seal_evidence",
        "verify_evidence_digest",
        "compute_evidence_digest",
        "reconstruct_controlling_decision",
    )
    for name in required:
        if not hasattr(evidence_integrity, name):
            failures.append(f"evidence integrity missing {name}")
    if not hasattr(decision_mod, "aggregate_decision"):
        failures.append("decision module missing aggregate_decision")
    return failures


def _check_bench_manifest() -> list[str]:
    failures: list[str] = []
    if not BENCH_MANIFEST.exists():
        return [f"missing FormalPR-Bench version manifest: {BENCH_MANIFEST}"]
    payload: dict[str, Any] = json.loads(BENCH_MANIFEST.read_text(encoding="utf-8"))
    if not payload.get("benchmark_version"):
        failures.append("bench manifest missing benchmark_version")
    digests = payload.get("partition_digests")
    if not isinstance(digests, dict) or not digests:
        failures.append("bench manifest missing partition_digests")
    partitions = payload.get("partitions")
    if not isinstance(partitions, list) or not partitions:
        failures.append("bench manifest missing partitions list")
    elif isinstance(digests, dict):
        for name in partitions:
            if name not in digests:
                failures.append(f"bench manifest missing digest for partition {name!r}")
    return failures


def _check_pilot_reports() -> list[str]:
    failures: list[str] = []
    if not PILOT_ROOT.exists():
        return ["missing docs/pilots/ directory"]
    reports = sorted(PILOT_ROOT.glob("*/REPORT.md"))
    if len(reports) < 2:
        failures.append(f"need >=2 pilot REPORT.md files; found {len(reports)}")
    json_reports = sorted(PILOT_ROOT.glob("*/pilot-report.json"))
    if len(json_reports) < 2:
        failures.append(f"need >=2 pilot-report.json files; found {len(json_reports)}")
    return failures


def _check_tcb_doc() -> list[str]:
    failures: list[str] = []
    if not TCB_DOC.exists():
        return ["missing docs/TRUSTED_COMPUTING_BASE.md"]
    text = TCB_DOC.read_text(encoding="utf-8")
    for needle in (
        "Trusted Computing Base",
        "trusted_components",
        "Composite Action",
        OVK_RELEASE_CANDIDATE,
    ):
        if needle not in text:
            failures.append(f"TCB doc missing expected content: {needle!r}")
    return failures


def _check_version_alignment(repo_root: Path) -> list[str]:
    failures: list[str] = []
    pyproject = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    if f'version = "{OVK_RELEASE_CANDIDATE}"' not in pyproject:
        failures.append("pyproject.toml version does not match OVK_RELEASE_CANDIDATE")
    import ovk

    if ovk.__version__ != OVK_RELEASE_CANDIDATE:
        failures.append("ovk.__version__ does not match OVK_RELEASE_CANDIDATE")
    return failures


REMAINING_MAINTAINER_GATES: tuple[str, ...] = (
    "Live non-[skip ci] CI / native Tier 1 / Action dogfood workflow IDs on verified_source_sha",
    "Signed immutable tag v1.3.0-rc.1 + Publish/Sigstore identity-bound evidence",
    "Consumer remotes bumped to immutable rc.1 pin with downloaded validation artifacts",
    "Label-separated holdout aggregates with HOLDOUT_* secrets (if promoting beyond RC)",
)


def verify_rc_dod(*, repo_root: Path | None = None) -> list[str]:
    """Return failure messages for in-repo RC DoD checks."""
    root = repo_root or ROOT
    failures: list[str] = []
    failures.extend(_check_version_alignment(root))
    failures.extend(_check_registry_coverage(root))
    failures.extend(_check_strict_fail_closed_tests())
    failures.extend(_check_evidence_controlling_decision())
    failures.extend(_check_bench_manifest())
    failures.extend(_check_pilot_reports())
    failures.extend(_check_tcb_doc())
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Optional JSON report output path",
    )
    args = parser.parse_args()
    failures = verify_rc_dod(repo_root=args.repo_root.resolve())
    payload = {
        "schema_version": "ovk.rc_dod.v1",
        "package_version": OVK_RELEASE_CANDIDATE,
        "passed": not failures,
        "failures": failures,
        "remaining_maintainer_gates": list(REMAINING_MAINTAINER_GATES),
    }
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    for failure in failures:
        print(failure)
    if failures:
        print(
            f"OVK RC DoD failed ({len(failures)} in-repo item(s)); "
            "live publication gates remain maintainer actions",
            file=sys.stderr,
        )
        return 1
    print(f"OVK RC DoD in-repo checks passed ({OVK_RELEASE_CANDIDATE})")
    print("Remaining maintainer publication gates:")
    for gate in REMAINING_MAINTAINER_GATES:
        print(f"  - {gate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
