from __future__ import annotations

import json
from pathlib import Path

from benchmarks.formal_pr_bench.persistent_fastapi_incremental_v1.run_scaling_benchmark import (
    run_scaling_benchmark,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/persistent_fastapi_incremental_v1/"
    "scaling_workloads.json"
)


def test_fresh_worker_semantic_work_is_repository_width_invariant() -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    report = run_scaling_benchmark()

    assert report["claim_scope"] == (
        "deterministic fresh-worker semantic work regression; "
        "wall-clock fields are observational only"
    )

    expected = config["expected"]
    assert [
        int(item["source_files"])
        for item in report["results"]
    ] == config["sizes"]

    for item in report["results"]:
        size = int(item["source_files"])
        target = expected[str(size)]

        unchanged = item["unchanged"]
        assert unchanged["previous_state_loaded"] is True
        assert unchanged["fresh_parses"] == target["unchanged"]["fresh_parses"]
        assert unchanged["summary_hits"] == size
        assert unchanged["summary_misses"] == 0
        assert unchanged["recomposed_contracts"] == target["unchanged"]["recomposed"]
        assert unchanged["rebound_fragments"] == target["unchanged"]["rebound"]
        assert unchanged["reused_fragments"] == size

        unrelated = item["unrelated_change"]
        assert unrelated["previous_state_loaded"] is True
        assert (
            unrelated["fresh_parses"]
            == target["unrelated_change"]["fresh_parses"]
        )
        assert unrelated["summary_hits"] == size - 1
        assert unrelated["summary_misses"] == 1
        assert (
            unrelated["recomposed_contracts"]
            == target["unrelated_change"]["recomposed"]
        )
        assert (
            unrelated["rebound_fragments"]
            == target["unrelated_change"]["rebound"]
        )
        assert unrelated["reused_fragments"] == size - 1

        contract = item["contract_change"]
        assert contract["previous_state_loaded"] is True
        assert (
            contract["fresh_parses"]
            == target["contract_change"]["fresh_parses"]
        )
        assert contract["summary_hits"] == size - 1
        assert contract["summary_misses"] == 1
        assert (
            contract["recomposed_contracts"]
            == target["contract_change"]["recomposed"]
        )
        assert (
            contract["invalidated_contract_names"]
            == target["contract_change"]["invalidated"]
        )
        assert (
            contract["rebound_fragments"]
            == target["contract_change"]["rebound"]
        )
        assert contract["reused_fragments"] == size - 2

        for phase in ("base", "unchanged", "unrelated_change", "contract_change"):
            assert item[phase]["compile_ms"] >= 0
            assert item[phase]["state_written"] is True


def test_256_file_fresh_worker_unchanged_head_does_zero_semantic_recompute() -> None:
    largest = run_scaling_benchmark()["results"][-1]

    assert largest["source_files"] == 256
    unchanged = largest["unchanged"]
    assert unchanged["fresh_parses"] == 0
    assert unchanged["recomposed_contracts"] == 0
    assert unchanged["rebound_fragments"] == 0
    assert unchanged["summary_hits"] == 256
    assert unchanged["reused_fragments"] == 256


def test_256_file_contract_edit_is_one_parse_plus_three_name_closure() -> None:
    largest = run_scaling_benchmark()["results"][-1]

    contract = largest["contract_change"]
    assert contract["fresh_parses"] == 1
    assert contract["recomposed_contracts"] == 2
    assert contract["invalidated_contract_names"] == 3
    assert contract["rebound_fragments"] == 2
    assert contract["summary_hits"] == 255
    assert contract["reused_fragments"] == 254
