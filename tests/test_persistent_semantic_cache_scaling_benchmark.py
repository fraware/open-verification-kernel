from __future__ import annotations

import json
from pathlib import Path

from benchmarks.formal_pr_bench.persistent_semantic_cache_v1.run_scaling_benchmark import (
    run_scaling_benchmark,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/persistent_semantic_cache_v1/"
    "scaling_workloads.json"
)


def test_persistent_semantic_cache_scales_across_fresh_workers() -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    report = run_scaling_benchmark()
    expected = {
        int(item["source_files"]): item
        for item in config["expected"]
    }

    assert report["claim_scope"] == (
        "deterministic fresh-worker parse/summary work regression; "
        "wall-clock fields are observational only"
    )

    for item in report["results"]:
        size = int(item["source_files"])
        target = expected[size]

        assert item["seed_parses"] == size
        assert item["seed_writes"] == size

        assert item["unchanged_hits"] == target["unchanged_hits"]
        assert item["unchanged_misses"] == 0
        assert item["unchanged_parses"] == target["unchanged_parses"]
        assert item["unchanged_fresh_contract_summaries"] == 0
        assert item["unchanged_fresh_route_summaries"] == 0

        assert item["changed_hits"] == target["changed_hits"]
        assert item["changed_misses"] == 1
        assert item["changed_parses"] == target["changed_parses"]
        assert item["changed_fresh_contract_summaries"] == 1
        assert item["changed_fresh_route_summaries"] == 1
        assert item["changed_coverage_status"] == "partial"

        for field in (
            "seed_load_ms",
            "unchanged_load_ms",
            "unchanged_compile_ms",
            "changed_load_ms",
            "changed_compile_ms",
        ):
            assert item[field] >= 0


def test_256_file_fresh_worker_uses_zero_parses_when_unchanged() -> None:
    largest = run_scaling_benchmark()["results"][-1]

    assert largest["source_files"] == 256
    assert largest["unchanged_hits"] == 256
    assert largest["unchanged_parses"] == 0
    assert largest["changed_hits"] == 255
    assert largest["changed_parses"] == 1
