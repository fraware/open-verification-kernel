from __future__ import annotations

import json
from pathlib import Path

from benchmarks.formal_pr_bench.incremental_contract_composition_v1.run_scaling_benchmark import (
    run_scaling_benchmark,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/incremental_contract_composition_v1/"
    "scaling_workloads.json"
)


def test_contract_composition_work_scales_with_dependency_closure() -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    report = run_scaling_benchmark()

    assert report["claim_scope"] == (
        "deterministic contract-composition work regression; "
        "wall-clock fields are observational only"
    )

    width_expected = config["expected_width"]
    for item in report["width_results"]:
        width = int(item["width"])
        expected = width_expected[str(width)]
        assert item["head_fresh_parses"] == 1
        assert item["changed_seeds"] == 1
        assert item["recomposed_contracts"] == expected["recomposed"]
        assert item["invalidated_names"] == expected["invalidated"]
        assert (
            item["reused_composed_contracts"]
            == expected["reused_composed"]
        )
        assert item["full_recompose_fallback"] is False
        assert item["full_equivalent"] is True
        assert item["incremental_compose_ms"] >= 0
        assert item["full_compose_ms"] >= 0

    depth_expected = config["expected_depth"]
    for item in report["depth_results"]:
        depth = int(item["depth"])
        expected = depth_expected[str(depth)]
        assert item["head_fresh_parses"] == 1
        assert item["changed_seeds"] == 1
        assert item["recomposed_contracts"] == expected["recomposed"]
        assert item["invalidated_names"] == expected["invalidated"]
        assert (
            item["reused_composed_contracts"]
            == expected["reused_composed"]
        )
        assert item["full_recompose_fallback"] is False
        assert item["full_equivalent"] is True
        assert item["incremental_compose_ms"] >= 0
        assert item["full_compose_ms"] >= 0


def test_unrelated_width_256_still_recomposes_two_contracts() -> None:
    report = run_scaling_benchmark()
    largest = report["width_results"][-1]

    assert largest["width"] == 256
    assert largest["recomposed_contracts"] == 2
    assert largest["invalidated_names"] == 3
    assert largest["reused_composed_contracts"] == 255


def test_depth_16_recomposes_only_sixteen_wrapper_contracts() -> None:
    report = run_scaling_benchmark()
    deepest = report["depth_results"][-1]

    assert deepest["depth"] == 16
    assert deepest["unrelated_chains"] == 32
    assert deepest["recomposed_contracts"] == 16
    assert deepest["invalidated_names"] == 17
    assert deepest["reused_composed_contracts"] == 32
