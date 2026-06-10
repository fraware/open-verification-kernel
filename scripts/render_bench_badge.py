#!/usr/bin/env python
"""Render shields.io badge JSON and public leaderboard summary from FormalPR-Bench output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEADERBOARD = ROOT / ".verification" / "formal-pr-bench-leaderboard.json"
BADGE_PATH = ROOT / "docs" / "benchmarks" / "leaderboard-badge.json"
SUMMARY_PATH = ROOT / "docs" / "benchmarks" / "latest-leaderboard-summary.json"


def badge_color(cases_passed: int, cases_total: int) -> str:
    """Map pass rate to shields.io color."""
    if cases_total <= 0:
        return "lightgrey"
    if cases_passed == cases_total:
        return "brightgreen"
    rate = cases_passed / cases_total
    if rate >= 0.95:
        return "yellow"
    return "red"


def render_badge(leaderboard: dict[str, Any]) -> dict[str, Any]:
    """Build shields.io endpoint badge payload."""
    summary = leaderboard.get("summary", {})
    cases_total = int(summary.get("cases_total", 0))
    cases_passed = int(summary.get("cases_passed", 0))
    rate = (cases_passed / cases_total * 100.0) if cases_total else 0.0
    return {
        "schemaVersion": 1,
        "label": "FormalPR-Bench",
        "message": f"{cases_passed}/{cases_total} ({rate:.0f}%)",
        "color": badge_color(cases_passed, cases_total),
    }


def render_summary(leaderboard: dict[str, Any]) -> dict[str, Any]:
    """Build trimmed public summary for docs and README links."""
    summary = leaderboard.get("summary", {})
    timing = leaderboard.get("timing_ms", {})
    return {
        "schema_version": "formal_pr_bench.summary.v1",
        "generated_from": leaderboard.get("schema_version", "formal_pr_bench.leaderboard.v1"),
        "cases_total": summary.get("cases_total", 0),
        "cases_passed": summary.get("cases_passed", 0),
        "pass_rate": (
            summary.get("cases_passed", 0) / summary.get("cases_total", 1)
            if summary.get("cases_total")
            else 0.0
        ),
        "merge_decision_accuracy": summary.get("merge_decision_accuracy"),
        "status_accuracy": summary.get("status_accuracy"),
        "counterexample_usefulness": summary.get("counterexample_usefulness"),
        "backend_selection_accuracy": summary.get("backend_selection_accuracy"),
        "evidence_honesty": summary.get("evidence_honesty"),
        "intent_recall": summary.get("intent_recall"),
        "real_diff_recall": summary.get("real_diff_recall"),
        "by_category": summary.get("by_category", {}),
        "timing_ms": {
            "p50": timing.get("p50"),
            "p95": timing.get("p95"),
            "max": timing.get("max"),
        },
    }


def write_outputs(leaderboard_path: Path, *, dry_run: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read leaderboard and write badge + summary files."""
    leaderboard = json.loads(leaderboard_path.read_text(encoding="utf-8"))
    badge = render_badge(leaderboard)
    summary = render_summary(leaderboard)
    if not dry_run:
        BADGE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BADGE_PATH.write_text(json.dumps(badge, indent=2) + "\n", encoding="utf-8")
        SUMMARY_PATH.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return badge, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Render FormalPR-Bench shields.io badge JSON")
    parser.add_argument(
        "--leaderboard",
        type=Path,
        default=DEFAULT_LEADERBOARD,
        help="Path to formal-pr-bench-leaderboard.json",
    )
    parser.add_argument("--dry-run", action="store_true", help="Compute outputs without writing files")
    args = parser.parse_args()
    if not args.leaderboard.exists():
        print(f"leaderboard not found: {args.leaderboard}")
        return 1
    badge, summary = write_outputs(args.leaderboard, dry_run=args.dry_run)
    if args.dry_run:
        print(json.dumps({"badge": badge, "summary": summary}, indent=2))
    else:
        print(f"wrote {BADGE_PATH.relative_to(ROOT)} and {SUMMARY_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
