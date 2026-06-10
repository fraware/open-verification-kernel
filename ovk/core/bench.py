"""FormalPR-Bench runner entry point for the OVK CLI."""

from __future__ import annotations

from typing import Any

from ovk.paths import ensure_repo_on_path


def run_formal_pr_bench(
    *,
    expanded: bool = False,
    include_extended: bool = True,
) -> tuple[list[Any], dict[str, Any]]:
    """Run FormalPR-Bench and return per-case scores plus the leaderboard payload."""
    ensure_repo_on_path()
    from benchmarks.formal_pr_bench.score_all_lanes import run_benchmark

    return run_benchmark(expanded=expanded, include_extended=include_extended)
