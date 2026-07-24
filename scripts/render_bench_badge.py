"""Render shields.io badge JSON and public leaderboard summary from FormalPR-Bench output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ovk.core.verified_source import resolve_benchmark_source_sha, resolve_verified_source_sha

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


def render_badge(
    leaderboard: dict[str, Any],
    *,
    benchmark_source_sha: str | None = None,
    verified_source_sha: str | None = None,
) -> dict[str, Any]:
    """Build shields.io endpoint badge payload.

    ``benchmark_source_sha`` is the commit measured by FormalPR-Bench.
    ``verified_source_sha`` is set only when a complete required-workflow set was
    observed for that source; badge-only commits must not be labeled verified.
    """
    summary = leaderboard.get("summary", {})
    cases_total = int(summary.get("cases_total", 0))
    cases_passed = int(summary.get("cases_passed", 0))
    rate = (cases_passed / cases_total * 100.0) if cases_total else 0.0
    bench_sha = benchmark_source_sha or resolve_benchmark_source_sha()
    verified_sha = verified_source_sha or resolve_verified_source_sha()
    payload: dict[str, Any] = {
        "schemaVersion": 1,
        "label": "FormalPR-Bench",
        "message": f"{cases_passed}/{cases_total} ({rate:.0f}%)",
        "color": badge_color(cases_passed, cases_total),
    }
    if bench_sha:
        payload["benchmark_source_sha"] = bench_sha
    if verified_sha:
        payload["verified_source_sha"] = verified_sha
    return payload


def render_summary(
    leaderboard: dict[str, Any],
    *,
    benchmark_source_sha: str | None = None,
    verified_source_sha: str | None = None,
) -> dict[str, Any]:
    """Build trimmed public summary for docs and README links."""
    summary = leaderboard.get("summary", {})
    timing = leaderboard.get("timing_ms", {})
    bench_sha = benchmark_source_sha or resolve_benchmark_source_sha()
    verified_sha = verified_source_sha or resolve_verified_source_sha()
    payload: dict[str, Any] = {
        "schema_version": "formal_pr_bench.summary.v1",
        "generated_from": leaderboard.get("schema_version", "formal_pr_bench.leaderboard.v1"),
        "cases_total": summary.get("cases_total", 0),
        "cases_passed": summary.get("cases_passed", 0),
        "pass_rate": (
            summary.get("cases_passed", 0) / summary.get("cases_total", 1) if summary.get("cases_total") else 0.0
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
    if bench_sha:
        payload["benchmark_source_sha"] = bench_sha
    if verified_sha:
        payload["verified_source_sha"] = verified_sha
    payload["provenance_note"] = (
        "Cite benchmark_source_sha for FormalPR-Bench measurement identity. "
        "Cite verified_source_sha only when a complete required-workflow set was "
        "observed for that commit; do not treat a later [skip ci] badge commit as verified."
    )
    return payload


def write_outputs(
    leaderboard_path: Path,
    *,
    dry_run: bool = False,
    benchmark_source_sha: str | None = None,
    verified_source_sha: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read leaderboard and write badge + summary files."""
    leaderboard = json.loads(leaderboard_path.read_text(encoding="utf-8"))
    bench_sha = benchmark_source_sha or resolve_benchmark_source_sha()
    verified_sha = verified_source_sha or resolve_verified_source_sha()
    badge = render_badge(
        leaderboard,
        benchmark_source_sha=bench_sha,
        verified_source_sha=verified_sha,
    )
    summary = render_summary(
        leaderboard,
        benchmark_source_sha=bench_sha,
        verified_source_sha=verified_sha,
    )
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
    parser.add_argument(
        "--benchmark-source-sha",
        default=None,
        help="Commit measured by FormalPR-Bench (defaults to GITHUB_SHA / git HEAD)",
    )
    parser.add_argument(
        "--verified-source-sha",
        default=None,
        help="Commit with a complete observed required-workflow set (optional)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Compute outputs without writing files")
    args = parser.parse_args()
    if not args.leaderboard.exists():
        print(f"leaderboard not found: {args.leaderboard}")
        return 1
    badge, summary = write_outputs(
        args.leaderboard,
        dry_run=args.dry_run,
        benchmark_source_sha=args.benchmark_source_sha,
        verified_source_sha=args.verified_source_sha,
    )
    if args.dry_run:
        print(json.dumps({"badge": badge, "summary": summary}, indent=2))
    else:
        print(f"wrote {BADGE_PATH.relative_to(ROOT)} and {SUMMARY_PATH.relative_to(ROOT)}")
        if summary.get("benchmark_source_sha"):
            print(f"benchmark_source_sha={summary['benchmark_source_sha']}")
        if summary.get("verified_source_sha"):
            print(f"verified_source_sha={summary['verified_source_sha']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
