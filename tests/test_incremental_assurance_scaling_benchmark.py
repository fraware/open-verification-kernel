from __future__ import annotations

import json
from pathlib import Path

from benchmarks.formal_pr_bench.incremental_assurance_v1.run_scaling_benchmark import (
    run_scaling_benchmark,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/incremental_assurance_v1/scaling_workloads.json"
)


def test_incremental_assurance_work_count_scales_with_changed_surface() -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    report = run_scaling_benchmark()

    assert report["claim_scope"] == (
        "work-count regression only; no wall-clock performance claim"
    )

    expected = {
        int(item["protected_effects"]): item
        for item in config["expected"]
    }
    results = report["results"]
    assert [int(item["protected_effects"]) for item in results] == config["sizes"]

    previous_avoided_fraction = -1.0
    for item in results:
        size = int(item["protected_effects"])
        target = expected[size]

        assert item["initial_seed_checks"] == size
        assert item["cold_fresh_checks"] == target["cold_fresh_checks"]
        assert item["warm_fresh_checks"] == target["warm_fresh_checks"]
        assert item["warm_reused_checks"] == target["warm_reused_checks"]
        assert item["avoided_checks"] == size - 1
        assert item["avoided_fraction"] == target["avoided_fraction"]

        assert item["warm_fresh_checks"] == 1
        assert item["warm_fresh_checks"] + item["warm_reused_checks"] == size
        assert item["avoided_fraction"] >= previous_avoided_fraction
        previous_avoided_fraction = float(item["avoided_fraction"])


def test_largest_development_workload_avoids_over_98_percent_of_repeat_checks() -> None:
    report = run_scaling_benchmark()
    largest = report["results"][-1]

    assert largest["protected_effects"] == 64
    assert largest["cold_fresh_checks"] == 64
    assert largest["warm_fresh_checks"] == 1
    assert largest["warm_reused_checks"] == 63
    assert largest["avoided_fraction"] == 0.984375
