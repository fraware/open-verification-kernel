#!/usr/bin/env python
"""Collect pilot program metrics and emit a schema-valid JSON report."""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ovk.core.json_io import read_json_file, write_json_file
from ovk.core.pilot import run_pilot_manifest, run_pilot_program
from ovk.core.release_metadata import OVK_VERSION
from ovk.core.schema_validation import require_schema_valid
from ovk.paths import ensure_repo_on_path, resource_path, schema_path

ROOT = Path(__file__).resolve().parents[1]
REAL_DIFF_MANIFEST = ROOT / "benchmarks" / "real_diffs" / "manifest.json"
METRICS_SCHEMA = schema_path("pilot.metrics.schema.json")
DEFAULT_OUTPUT = ROOT / ".verification" / "pilot-dogfood-report.json"
EXTERNAL_MANIFEST = resource_path("examples", "pilot_repos", "external_oss_ci_secrets.json")


def _iso_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _real_diff_recall() -> float | None:
    """Compute intent recall across the real_diff corpus manifest."""
    if not REAL_DIFF_MANIFEST.is_file():
        return None
    from ovk.core.check import run_check

    cases = json.loads(REAL_DIFF_MANIFEST.read_text(encoding="utf-8")).get("cases", [])
    if not cases:
        return None
    recalled = 0
    diff_root = REAL_DIFF_MANIFEST.parent
    for case in cases:
        diff_text = (diff_root / case["diff"]).read_text(encoding="utf-8")
        plan = run_check(diff_text=diff_text, use_cache=False, repo="metrics/repo", head_sha="metrics").plan
        expected = set(case.get("expected_intents", []))
        actual = set(plan.get("candidate_intents", []))
        if expected.issubset(actual):
            recalled += 1
    return recalled / len(cases)


def _bundle_artifacts(bundle_dir: Path | None) -> list[str]:
    if bundle_dir is None or not bundle_dir.is_dir():
        return []
    return sorted(path.name for path in bundle_dir.rglob("*") if path.is_file())


def _false_positive_rate(results: list[dict[str, Any]]) -> float | None:
    evaluated = [item for item in results if "passed" in item]
    if not evaluated:
        return None
    false_positives = sum(
        1 for item in evaluated if not item.get("passed") and item.get("merge_recommendation") == "block"
    )
    return false_positives / len(evaluated)


def _median_elapsed_ms(results: list[dict[str, Any]]) -> float | None:
    timings = [float(item["elapsed_ms"]) for item in results if "elapsed_ms" in item]
    if not timings:
        return None
    return float(statistics.median(timings))


def _load_pilot_report(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    return read_json_file(path)


def _evidence_recommendation(evidence_path: Path | None) -> str | None:
    if evidence_path is None or not evidence_path.exists():
        return None
    evidence = read_json_file(evidence_path)
    decision = evidence.get("decision", {})
    recommendation = decision.get("merge_recommendation")
    return str(recommendation) if recommendation is not None else None


def _discover_bundle_dir(artifacts_dir: Path, *names: str) -> Path | None:
    for name in names:
        bundle_dir = artifacts_dir / name
        if bundle_dir.is_dir():
            return bundle_dir
        matches = [path for path in artifacts_dir.rglob(name) if path.is_dir()]
        if matches:
            return matches[0]
    return None


def discover_artifacts_dir(artifacts_dir: Path) -> tuple[Path | None, Path | None, Path | None]:
    """Locate pilot report, evidence, and bundle paths inside workflow artifacts."""
    pilot_report = artifacts_dir / "pilot-report.json"
    if not pilot_report.exists():
        matches = sorted(artifacts_dir.rglob("pilot-report.json"))
        pilot_report = matches[0] if matches else None

    evidence = artifacts_dir / "ovk-evidence.json"
    if not evidence.exists():
        matches = sorted(artifacts_dir.rglob("ovk-evidence.json"))
        evidence = matches[0] if matches else None

    bundle_dir = _discover_bundle_dir(
        artifacts_dir,
        "pilot-dogfood-bundle",
        "ovk-pilot-bundle",
        "ovk-pilot-artifacts",
    )
    if bundle_dir is None:
        alt = artifacts_dir / ".verification" / "pilot-dogfood-bundle"
        bundle_dir = alt if alt.is_dir() else None

    return pilot_report, evidence, bundle_dir


def collect_from_artifacts_dir(
    artifacts_dir: Path,
    *,
    source: str,
    ovk_version: str | None = None,
) -> dict[str, Any]:
    """Parse a downloaded workflow artifact directory into pilot metrics."""
    pilot_report_path, evidence_path, bundle_dir = discover_artifacts_dir(artifacts_dir)
    return collect_pilot_metrics(
        source=source,
        bundle_dir=bundle_dir,
        pilot_report_path=pilot_report_path,
        evidence_path=evidence_path,
        ovk_version=ovk_version,
    )


def _repo_relative(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def collect_pilot_metrics(
    *,
    source: str,
    external_manifest: Path | None = None,
    bundle_dir: Path | None = None,
    pilot_report_path: Path | None = None,
    evidence_path: Path | None = None,
    ovk_version: str | None = None,
) -> dict[str, Any]:
    """Build a pilot metrics report from manifests, pilot reports, and optional artifacts."""
    ensure_repo_on_path()
    manifest_path = external_manifest or EXTERNAL_MANIFEST
    external_result = run_pilot_manifest(manifest_path, repo="pilot-dogfood/repo", head_sha="dogfood-head")

    pilot_report = _load_pilot_report(pilot_report_path)
    if pilot_report is None:
        pilot_report = run_pilot_program()
    results = list(pilot_report.get("results", [external_result]))
    manifests_total = int(pilot_report.get("manifests_total", len(results)))
    manifests_passed = int(pilot_report.get("manifests_passed", sum(1 for item in results if item.get("passed"))))

    recommendation = _evidence_recommendation(evidence_path)
    block_rate = None
    if recommendation is not None:
        block_rate = 1.0 if recommendation == "block" else 0.0

    median_elapsed = _median_elapsed_ms(results) or external_result.get("elapsed_ms")

    return {
        "schema_version": "ovk.pilot_metrics.v1",
        "collected_at": _iso_timestamp(),
        "source": source,
        "ovk_version": ovk_version or OVK_VERSION,
        "pilot_report": {
            "manifests_total": manifests_total,
            "manifests_passed": manifests_passed,
            "results": results,
        },
        "adoption": {
            "real_diff_recall": _real_diff_recall(),
            "pilot_dogfood": {
                "manifests_passed": manifests_passed,
                "manifests_total": manifests_total,
                "median_elapsed_ms": median_elapsed,
                "false_positive_rate": _false_positive_rate(results),
                "block_rate_on_unsafe_fixture": block_rate,
                "external_manifest": _repo_relative(manifest_path),
            },
        },
        "bundle_artifacts": _bundle_artifacts(bundle_dir),
    }


def validate_metrics(metrics: dict[str, Any]) -> None:
    if not METRICS_SCHEMA.exists():
        raise FileNotFoundError(f"missing schema: {METRICS_SCHEMA}")
    require_schema_valid(metrics, read_json_file(METRICS_SCHEMA), context="pilot metrics")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect OVK pilot metrics into a JSON report")
    parser.add_argument(
        "--pilot-report",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Pilot report JSON from ovk pilot or metrics output path",
    )
    parser.add_argument("--input-pilot-report", type=Path, help="Existing ovk pilot --output JSON to parse")
    parser.add_argument("--evidence", type=Path, help="Optional ovk-evidence.json from advisory check")
    parser.add_argument("--artifacts-dir", type=Path, help="Downloaded workflow artifact directory")
    parser.add_argument("--bundle-dir", type=Path, default=None, help="Optional release bundle directory")
    parser.add_argument("--external-manifest", type=Path, default=None, help="External OSS pilot manifest path")
    parser.add_argument("--source", default="pilot-dogfood", help="Metrics source label")
    parser.add_argument("--ovk-version", default=None, help="Pinned OVK package version")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print without writing")
    return parser.parse_args()


def main() -> int:
    ensure_repo_on_path()
    args = parse_args()
    pilot_report_path = args.input_pilot_report
    evidence_path = args.evidence
    bundle_dir = args.bundle_dir

    if args.artifacts_dir is not None:
        discovered_report, discovered_evidence, discovered_bundle = discover_artifacts_dir(args.artifacts_dir)
        pilot_report_path = pilot_report_path or discovered_report
        evidence_path = evidence_path or discovered_evidence
        bundle_dir = bundle_dir or discovered_bundle

    report = collect_pilot_metrics(
        source=args.source,
        external_manifest=args.external_manifest,
        bundle_dir=bundle_dir,
        pilot_report_path=pilot_report_path,
        evidence_path=evidence_path,
        ovk_version=args.ovk_version,
    )
    validate_metrics(report)

    if args.dry_run:
        print(json.dumps(report, indent=2))
        return 0

    args.pilot_report.parent.mkdir(parents=True, exist_ok=True)
    write_json_file(args.pilot_report, report)
    print(f"wrote pilot metrics report to {args.pilot_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
