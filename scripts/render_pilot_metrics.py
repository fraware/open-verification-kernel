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
from ovk.paths import schema_path

ROOT = Path(__file__).resolve().parents[1]
ADOPTION_SUMMARY_PATH = ROOT / "docs" / "benchmarks" / "adoption-summary.json"
LEADERBOARD_SUMMARY_PATH = ROOT / "docs" / "benchmarks" / "latest-leaderboard-summary.json"
LEADERBOARD_PATH = ROOT / ".verification" / "formal-pr-bench-leaderboard.json"
ADOPTION_SCHEMA = schema_path("adoption.summary.schema.json")
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


def render_adoption_summary(metrics: dict[str, Any]) -> dict[str, Any]:
    """Build the public adoption summary document from pilot metrics."""
    adoption = metrics.get("adoption", {})
    pilot_dogfood = adoption.get("pilot_dogfood", {})
    return {
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
            "external_manifest": pilot_dogfood.get("external_manifest", "examples/pilot_repos/external_oss_ci_secrets.json"),
            "weekly_schedule": "0 7 * * 1",
            "workflow": PILOT_DOGFOOD_WORKFLOW,
            "ovk_version_pin": metrics.get("ovk_version", OVK_VERSION),
        },
        "external_pilots": [],
    }


def validate_summary(summary: dict[str, Any]) -> None:
    if not ADOPTION_SCHEMA.exists():
        raise FileNotFoundError(f"missing schema: {ADOPTION_SCHEMA}")
    require_schema_valid(summary, read_json_file(ADOPTION_SCHEMA), context="adoption summary")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render adoption-summary.json from pilot metrics")
    parser.add_argument("--metrics", type=Path, help="Pilot metrics JSON report from collect_pilot_metrics.py")
    parser.add_argument("--output", type=Path, default=ADOPTION_SUMMARY_PATH, help="Output path for adoption-summary.json")
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
    summary = render_adoption_summary(metrics)
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
