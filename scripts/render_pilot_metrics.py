#!/usr/bin/env python
"""Render adoption-summary.json from pilot metrics and FormalPR-Bench snapshots."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ovk.core.json_io import read_json_file, write_json_file
from ovk.core.release_metadata import OVK_VERSION
from ovk.core.schema_validation import require_schema_valid
from ovk.core.verified_source import resolve_verified_source_sha
from ovk.paths import schema_path

ROOT = Path(__file__).resolve().parents[1]
ADOPTION_SUMMARY_PATH = ROOT / "docs" / "benchmarks" / "adoption-summary.json"
EXTERNAL_PILOTS_REGISTRY_PATH = ROOT / "docs" / "benchmarks" / "external-pilots-registry.json"
LEADERBOARD_SUMMARY_PATH = ROOT / "docs" / "benchmarks" / "latest-leaderboard-summary.json"
LEADERBOARD_PATH = ROOT / ".verification" / "formal-pr-bench-leaderboard.json"
ADOPTION_SCHEMA = schema_path("adoption.summary.schema.json")
EXTERNAL_PILOTS_REGISTRY_SCHEMA = schema_path("external.pilots.registry.schema.json")
PILOT_DOGFOOD_WORKFLOW = ".github/workflows/pilot-dogfood.yml"


def _leaderboard_snapshot() -> dict[str, Any]:
    if LEADERBOARD_SUMMARY_PATH.is_file():
        payload = read_json_file(LEADERBOARD_SUMMARY_PATH)
        return {
            "cases_total": payload.get("cases_total"),
            "cases_passed": payload.get("cases_passed"),
            "pass_rate": payload.get("pass_rate"),
            "intent_recall": payload.get("intent_recall"),
            "by_category": payload.get("by_category", {}),
            "timing_ms": payload.get("timing_ms", {}),
        }
    if LEADERBOARD_PATH.is_file():
        payload = read_json_file(LEADERBOARD_PATH)
        summary = payload.get("summary", {})
        cases_total = summary.get("cases_total", 0)
        cases_passed = summary.get("cases_passed", 0)
        return {
            "cases_total": cases_total,
            "cases_passed": cases_passed,
            "pass_rate": (cases_passed / cases_total) if cases_total else None,
            "intent_recall": summary.get("intent_recall"),
            "by_category": summary.get("by_category", {}),
            "timing_ms": payload.get("timing_ms", {}),
        }
    return {"cases_total": None, "cases_passed": None, "pass_rate": None, "by_category": {}}


def _real_diff_recall(metrics: dict[str, Any]) -> float | None:
    adoption = metrics.get("adoption", {})
    if adoption.get("real_diff_recall") is not None:
        return adoption.get("real_diff_recall")
    bench = _leaderboard_snapshot()
    if LEADERBOARD_SUMMARY_PATH.is_file():
        return read_json_file(LEADERBOARD_SUMMARY_PATH).get("real_diff_recall")
    if LEADERBOARD_PATH.is_file():
        return read_json_file(LEADERBOARD_PATH).get("summary", {}).get("real_diff_recall")
    return bench.get("real_diff_recall")


def load_external_pilots_registry(registry_path: Path) -> list[dict[str, Any]]:
    """Load and validate external pilot rows from the registry file."""
    if not registry_path.is_file():
        return []
    payload = read_json_file(registry_path)
    if EXTERNAL_PILOTS_REGISTRY_SCHEMA.is_file():
        require_schema_valid(
            payload,
            read_json_file(EXTERNAL_PILOTS_REGISTRY_SCHEMA),
            context="external pilots registry",
        )
    pilots = payload.get("external_pilots", [])
    return [dict(item) for item in pilots]


def merge_external_pilots(
    registry_pilots: list[dict[str, Any]],
    existing_pilots: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Merge registry rows with any existing adoption-summary rows by repository key."""
    merged: dict[str, dict[str, Any]] = {}
    for item in existing_pilots or []:
        key = str(item.get("repository", ""))
        if key:
            merged[key] = dict(item)
    for item in registry_pilots:
        key = str(item.get("repository", ""))
        if key:
            merged[key] = dict(item)
    return list(merged.values())


def render_adoption_summary(
    metrics: dict[str, Any],
    *,
    registry_path: Path | None = None,
    existing_summary: dict[str, Any] | None = None,
    verified_source_sha: str | None = None,
) -> dict[str, Any]:
    """Build the public adoption summary document from pilot metrics."""
    adoption = metrics.get("adoption", {})
    pilot_dogfood = adoption.get("pilot_dogfood", {})
    registry = load_external_pilots_registry(registry_path or EXTERNAL_PILOTS_REGISTRY_PATH)
    existing_pilots = None
    if existing_summary is not None:
        existing_pilots = existing_summary.get("external_pilots")
    sha = verified_source_sha or resolve_verified_source_sha()
    summary: dict[str, Any] = {
        "schema_version": "ovk.adoption_summary.v1",
        "ovk_version": metrics.get("ovk_version", OVK_VERSION),
        "updated_at": metrics.get("collected_at"),
        "formal_pr_bench": _leaderboard_snapshot(),
        "real_diff_recall": _real_diff_recall(metrics),
        "pilot_dogfood": {
            "source": metrics.get("source"),
            "last_run": metrics.get("collected_at"),
            "manifests_passed": pilot_dogfood.get("manifests_passed"),
            "manifests_total": pilot_dogfood.get("manifests_total"),
            "median_elapsed_ms": pilot_dogfood.get("median_elapsed_ms"),
            "false_positive_rate": pilot_dogfood.get("false_positive_rate"),
            "external_manifest": pilot_dogfood.get(
                "external_manifest", "examples/pilot_repos/external_oss_ci_secrets.json"
            ),
            "weekly_schedule": "0 7 * * 1",
            "workflow": PILOT_DOGFOOD_WORKFLOW,
            "ovk_version_pin": metrics.get("ovk_version", OVK_VERSION),
        },
        "external_pilots": merge_external_pilots(registry, existing_pilots),
    }
    if sha:
        summary["verified_source_sha"] = sha
    return summary


def validate_summary(summary: dict[str, Any]) -> None:
    if not ADOPTION_SCHEMA.exists():
        raise FileNotFoundError(f"missing schema: {ADOPTION_SCHEMA}")
    require_schema_valid(summary, read_json_file(ADOPTION_SCHEMA), context="adoption summary")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render adoption-summary.json from pilot metrics")
    parser.add_argument("--metrics", type=Path, help="Pilot metrics JSON report from collect_pilot_metrics.py")
    parser.add_argument(
        "--registry",
        type=Path,
        default=EXTERNAL_PILOTS_REGISTRY_PATH,
        help="External pilots registry JSON (default: docs/benchmarks/external-pilots-registry.json)",
    )
    parser.add_argument("--output", type=Path, default=ADOPTION_SUMMARY_PATH, help="Output path for adoption-summary.json")
    parser.add_argument(
        "--verified-source-sha",
        default=None,
        help="Commit that produced the metrics (defaults to GITHUB_SHA / git HEAD)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print summary without writing files")
    return parser.parse_args()


def main() -> int:
    from ovk.paths import ensure_repo_on_path

    ensure_repo_on_path()
    args = parse_args()
    if args.metrics is not None and args.metrics.exists():
        metrics = read_json_file(args.metrics)
    else:
        from scripts.collect_pilot_metrics import collect_pilot_metrics

        metrics = collect_pilot_metrics(source="local")
    existing_summary = read_json_file(args.output) if args.output.is_file() else None
    summary = render_adoption_summary(
        metrics,
        registry_path=args.registry,
        existing_summary=existing_summary,
        verified_source_sha=args.verified_source_sha,
    )
    validate_summary(summary)
    if args.dry_run:
        print(json.dumps(summary, indent=2))
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json_file(args.output, summary)
    print(f"wrote adoption summary to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
