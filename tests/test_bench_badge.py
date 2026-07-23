"""Tests for FormalPR-Bench shields.io badge rendering."""

from __future__ import annotations

from scripts.render_bench_badge import badge_color, render_badge, render_summary


def test_badge_color_rules() -> None:
    assert badge_color(100, 100) == "brightgreen"
    assert badge_color(96, 100) == "yellow"
    assert badge_color(90, 100) == "red"
    assert badge_color(0, 0) == "lightgrey"


def test_render_badge_shape() -> None:
    leaderboard = {
        "schema_version": "formal_pr_bench.leaderboard.v1",
        "summary": {"cases_total": 100, "cases_passed": 100},
        "timing_ms": {"p50": 1.0, "p95": 2.0, "max": 3.0},
    }
    badge = render_badge(leaderboard, verified_source_sha="abc1234deadbeef")
    assert badge["schemaVersion"] == 1
    assert badge["label"] == "FormalPR-Bench"
    assert "100/100" in badge["message"]
    assert badge["color"] == "brightgreen"
    assert badge["verified_source_sha"] == "abc1234deadbeef"


def test_render_summary_includes_dimensions() -> None:
    leaderboard = {
        "schema_version": "formal_pr_bench.leaderboard.v1",
        "summary": {
            "cases_total": 10,
            "cases_passed": 9,
            "merge_decision_accuracy": 0.9,
            "by_category": {"lane": {"cases_total": 10, "cases_passed": 9, "pass_rate": 0.9}},
        },
        "timing_ms": {"p50": 1.0, "p95": 2.0, "max": 3.0},
    }
    summary = render_summary(leaderboard, verified_source_sha="sha-source")
    assert summary["schema_version"] == "formal_pr_bench.summary.v1"
    assert summary["cases_passed"] == 9
    assert summary["timing_ms"]["p95"] == 2.0
    assert "lane" in summary["by_category"]
    assert summary["verified_source_sha"] == "sha-source"
    assert "skip ci" in summary["provenance_note"]


def test_render_summary_includes_real_diff_recall() -> None:
    leaderboard = {
        "schema_version": "formal_pr_bench.leaderboard.v1",
        "summary": {"cases_total": 10, "cases_passed": 9, "real_diff_recall": 0.95},
        "timing_ms": {"p50": 1.0, "p95": 2.0, "max": 3.0},
    }
    summary = render_summary(leaderboard, verified_source_sha="x" * 40)
    assert summary["real_diff_recall"] == 0.95
