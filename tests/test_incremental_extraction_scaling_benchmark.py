from __future__ import annotations

import json
from pathlib import Path

from benchmarks.formal_pr_bench.incremental_extraction_v1.run_scaling_benchmark import (
    run_scaling_benchmark,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/incremental_extraction_v1/"
    "scaling_workloads.json"
)


def test_incremental_ast_parse_work_scales_with_changed_file_surface() -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    report = run_scaling_benchmark()

    assert report["claim_scope"] == (
        "deterministic parse-work regression; wall-clock fields are observational only"
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

        assert item["base_fresh_parses"] == target["base_fresh_parses"]
        assert item["cold_head_fresh_parses"] == target["cold_head_fresh_parses"]
        assert item["warm_head_fresh_parses"] == target["warm_head_fresh_parses"]
        assert item["warm_head_reused"] == target["warm_head_reused"]

        assert item["warm_head_fresh_parses"] == 1
        assert (
            item["warm_head_fresh_parses"] + item["warm_head_reused"]
            == size
        )
        assert item["head_source_files_supplied_to_semantic_compile"] == size

        # Timing fields are observations only. Assert shape, not speed ratios.
        assert item["base_index_ms"] >= 0
        assert item["cold_head_index_ms"] >= 0
        assert item["warm_head_index_ms"] >= 0
        assert item["compile_from_warm_index_ms"] >= 0


def test_largest_workload_reuses_255_of_256_parsed_files() -> None:
    report = run_scaling_benchmark()
    largest = report["results"][-1]

    assert largest["source_files"] == 256
    assert largest["cold_head_fresh_parses"] == 256
    assert largest["warm_head_fresh_parses"] == 1
    assert largest["warm_head_reused"] == 255
    assert largest["head_source_files_supplied_to_semantic_compile"] == 256
