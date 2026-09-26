from __future__ import annotations

import json
from pathlib import Path

from benchmarks.formal_pr_bench.incremental_semantic_summary_v1.run_scaling_benchmark import (
    run_scaling_benchmark,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/incremental_semantic_summary_v1/"
    "scaling_workloads.json"
)


def test_semantic_summary_work_scales_with_changed_file_surface() -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    report = run_scaling_benchmark()

    assert report["claim_scope"] == (
        "deterministic per-file semantic-summary work regression; "
        "wall-clock fields are observational only"
    )
    expected = {
        int(item["source_files"]): item
        for item in config["expected"]
    }

    assert [
        int(item["source_files"])
        for item in report["results"]
    ] == config["sizes"]

    for item in report["results"]:
        size = int(item["source_files"])
        target = expected[size]

        assert item["cold_fresh_parses"] == size
        assert item["cold_fresh_contract_summaries"] == size
        assert item["cold_fresh_route_summaries"] == size

        assert item["warm_fresh_parses"] == target["warm_fresh_parses"]
        assert (
            item["warm_fresh_contract_summaries"]
            == target["warm_fresh_contract_summaries"]
        )
        assert (
            item["warm_fresh_route_summaries"]
            == target["warm_fresh_route_summaries"]
        )
        assert (
            item["warm_reused_contract_summaries"]
            == target["warm_reused_contract_summaries"]
        )
        assert (
            item["warm_reused_route_summaries"]
            == target["warm_reused_route_summaries"]
        )
        assert item["warm_reused_parses"] == size - 1

        assert item["coverage_status"] == "partial"
        assert item["detected_changed_contract_semantics"] == 1

        for field in (
            "cold_parse_ms",
            "cold_contract_summary_ms",
            "cold_route_summary_ms",
            "warm_parse_ms",
            "warm_contract_summary_ms",
            "warm_route_summary_ms",
            "compile_from_warm_summaries_ms",
        ):
            assert item[field] >= 0


def test_largest_semantic_workload_refreshes_one_of_256_file_summaries() -> None:
    largest = run_scaling_benchmark()["results"][-1]

    assert largest["source_files"] == 256
    assert largest["warm_fresh_parses"] == 1
    assert largest["warm_fresh_contract_summaries"] == 1
    assert largest["warm_fresh_route_summaries"] == 1
    assert largest["warm_reused_contract_summaries"] == 255
    assert largest["warm_reused_route_summaries"] == 255
    assert largest["detected_changed_contract_semantics"] == 1
