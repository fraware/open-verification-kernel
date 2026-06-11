#!/usr/bin/env python
"""Ingest external pilot metrics from workflow artifacts into the registry."""

from __future__ import annotations

import argparse
import statistics
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ovk.core.json_io import read_json_file, write_json_file
from ovk.core.release_metadata import OVK_VERSION
from ovk.core.schema_validation import require_schema_valid
from ovk.paths import ensure_repo_on_path, schema_path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "docs" / "benchmarks" / "external-pilots-registry.json"
REGISTRY_SCHEMA = schema_path("external.pilots.registry.schema.json")
EXTERNAL_PILOT_SCHEMA = schema_path("external.pilot.schema.json")

REPORT_FIELD_MAP = {
    "check_types": "check_types",
    "advisory_start": "advisory_start",
    "advisory_end": "advisory_end",
    "prs_evaluated": "prs_evaluated",
    "prs_blocked": "prs_blocked",
    "false_positives": "false_positives",
    "false_positive_rate": "false_positive_rate",
    "median_check_latency_ms": "median_check_latency_ms",
    "strict_enabled": "strict_enabled",
    "ovk_version_pin": "ovk_version_pin",
    "workflow_path": "workflow_path",
    "evidence_url": "evidence_url",
    "notes": "notes",
}


def _iso_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _find_file(artifacts_dir: Path, name: str) -> Path | None:
    direct = artifacts_dir / name
    if direct.is_file():
        return direct
    matches = sorted(artifacts_dir.rglob(name))
    return matches[0] if matches else None


def _median_elapsed_ms(results: list[dict[str, Any]]) -> float | None:
    timings = [float(item["elapsed_ms"]) for item in results if "elapsed_ms" in item]
    if not timings:
        return None
    return float(statistics.median(timings))


def _false_positive_rate(results: list[dict[str, Any]]) -> float | None:
    evaluated = [item for item in results if "passed" in item]
    if not evaluated:
        return None
    false_positives = sum(
        1 for item in evaluated if not item.get("passed") and item.get("merge_recommendation") == "block"
    )
    return false_positives / len(evaluated)


def _blocked_count(results: list[dict[str, Any]]) -> int | None:
    evaluated = [item for item in results if "merge_recommendation" in item]
    if not evaluated:
        return None
    return sum(1 for item in evaluated if item.get("merge_recommendation") == "block")


def _infer_status(row: dict[str, Any]) -> str:
    if row.get("status") == "completed":
        return "completed"
    if row.get("strict_enabled"):
        return "strict"
    if row.get("advisory_start"):
        return "advisory"
    if row.get("status") in {"recruiting", "advisory", "strict", "completed"}:
        return str(row["status"])
    return "advisory"


def _metrics_from_artifacts(artifacts_dir: Path) -> dict[str, Any]:
    from scripts.collect_pilot_metrics import discover_artifacts_dir

    pilot_report_path, evidence_path, _bundle_dir = discover_artifacts_dir(artifacts_dir)
    metrics: dict[str, Any] = {}

    pilot_report = read_json_file(pilot_report_path) if pilot_report_path and pilot_report_path.exists() else None
    if pilot_report is not None:
        results = list(pilot_report.get("results", []))
        metrics["prs_evaluated"] = len(results) or None
        metrics["prs_blocked"] = _blocked_count(results)
        metrics["false_positive_rate"] = _false_positive_rate(results)
        if metrics["false_positive_rate"] is not None and metrics["prs_evaluated"]:
            metrics["false_positives"] = round(metrics["false_positive_rate"] * metrics["prs_evaluated"])
        metrics["median_check_latency_ms"] = _median_elapsed_ms(results)

    if evidence_path and evidence_path.exists():
        evidence = read_json_file(evidence_path)
        decision = evidence.get("decision", {})
        if decision.get("merge_recommendation") == "block" and metrics.get("prs_blocked") is None:
            metrics["prs_blocked"] = 1
        timing = evidence.get("timing_ms") or evidence.get("timing")
        if isinstance(timing, dict):
            metrics["median_check_latency_ms"] = timing.get("p50") or timing.get("median")
        elif isinstance(timing, (int, float)):
            metrics["median_check_latency_ms"] = float(timing)

    external_report = _find_file(artifacts_dir, "external_pilot_report.json")
    if external_report is not None:
        report = read_json_file(external_report)
        for report_key, row_key in REPORT_FIELD_MAP.items():
            if report_key in report and report[report_key] is not None:
                metrics[row_key] = report[report_key]

    return metrics


def _apply_report(row: dict[str, Any], report_path: Path) -> dict[str, Any]:
    report = read_json_file(report_path)
    updated = dict(row)
    for report_key, row_key in REPORT_FIELD_MAP.items():
        if report_key in report and report[report_key] is not None:
            updated[row_key] = report[report_key]
    if "repository" in report and report["repository"]:
        updated["repository"] = report["repository"]
    return updated


def build_pilot_row(
    repo: str,
    *,
    artifacts_dir: Path | None = None,
    report_path: Path | None = None,
    ovk_version: str | None = None,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one external pilot registry row from artifacts and optional self-report."""
    row: dict[str, Any] = {
        "repository": repo,
        "status": "advisory",
        "check_types": ["ci_secrets"],
        "advisory_start": None,
        "advisory_end": None,
        "prs_evaluated": None,
        "prs_blocked": None,
        "false_positives": None,
        "false_positive_rate": None,
        "median_check_latency_ms": None,
        "strict_enabled": False,
        "ovk_version_pin": ovk_version or OVK_VERSION,
        "workflow_path": ".github/workflows/ovk-pilot.yml",
    }
    if existing is not None:
        row.update({key: value for key, value in existing.items() if value is not None or key in row})
        row["repository"] = repo
    if report_path is not None and report_path.exists():
        row = _apply_report(row, report_path)
    if artifacts_dir is not None and artifacts_dir.is_dir():
        row.update({key: value for key, value in _metrics_from_artifacts(artifacts_dir).items() if value is not None})
    row["status"] = _infer_status(row)
    return row


def validate_registry(registry: dict[str, Any]) -> None:
    require_schema_valid(registry, read_json_file(REGISTRY_SCHEMA), context="external pilots registry")
    pilot_schema = read_json_file(EXTERNAL_PILOT_SCHEMA)
    for index, pilot in enumerate(registry.get("external_pilots", [])):
        require_schema_valid(pilot, pilot_schema, context=f"external pilot[{index}]")


def load_registry(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {
            "schema_version": "ovk.external_pilots_registry.v1",
            "updated_at": _iso_timestamp(),
            "external_pilots": [],
        }
    return read_json_file(path)


def upsert_pilot_row(registry: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    pilots = list(registry.get("external_pilots", []))
    repo = str(row["repository"])
    replaced = False
    for index, item in enumerate(pilots):
        if str(item.get("repository")) == repo:
            pilots[index] = row
            replaced = True
            break
    if not replaced:
        pilots.append(row)
    updated = dict(registry)
    updated["external_pilots"] = pilots
    updated["updated_at"] = _iso_timestamp()
    validate_registry(updated)
    return updated


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest external pilot metrics into the registry")
    parser.add_argument("--repo", required=True, help="External repository slug (org/name)")
    parser.add_argument("--artifacts-dir", type=Path, help="Downloaded workflow artifact directory")
    parser.add_argument("--report", type=Path, help="Self-reported external_pilot_report.json")
    parser.add_argument(
        "--registry",
        type=Path,
        default=DEFAULT_REGISTRY,
        help="Registry path (default: docs/benchmarks/external-pilots-registry.json)",
    )
    parser.add_argument("--ovk-version", default=None, help="Pinned OVK package version")
    parser.add_argument("--dry-run", action="store_true", help="Print updated registry without writing")
    return parser.parse_args()


def main() -> int:
    ensure_repo_on_path()
    args = parse_args()
    registry = load_registry(args.registry)
    existing = next(
        (item for item in registry.get("external_pilots", []) if str(item.get("repository")) == args.repo),
        None,
    )
    row = build_pilot_row(
        args.repo,
        artifacts_dir=args.artifacts_dir,
        report_path=args.report,
        ovk_version=args.ovk_version,
        existing=existing,
    )
    require_schema_valid(row, read_json_file(EXTERNAL_PILOT_SCHEMA), context="external pilot row")
    updated = upsert_pilot_row(registry, row)
    if args.dry_run:
        import json

        print(json.dumps(updated, indent=2))
        return 0
    args.registry.parent.mkdir(parents=True, exist_ok=True)
    write_json_file(args.registry, updated)
    print(f"upserted {args.repo} in {args.registry}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
