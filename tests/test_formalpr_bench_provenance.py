"""FormalPR-Bench provenance, partitions, and contamination guards (OVK-PR5)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from benchmarks.formal_pr_bench.provenance_kit import (
    BENCHMARK_VERSION,
    BENCH_DIR,
    HELD_OUT_DIR,
    MANIFEST_PATH,
    PARTITIONS,
    PARTITIONS_PATH,
    PROVENANCE_DIR,
    RATIONALES_DIR,
    TEMPLATE_DEV_PATH,
    ProvenanceError,
    assert_no_template_dev_contamination,
    filter_cases_for_partition,
    load_all_cases,
    load_manifest,
    load_partitions,
    load_template_dev_cases,
    partition_membership,
    require_published_score_identity,
    verify_manifest_digests,
)
from benchmarks.formal_pr_bench.scoring import DimensionScore, build_leaderboard
from ovk.core.json_io import read_json_file
from ovk.core.schema_validation import require_schema_valid


ROOT = Path(__file__).resolve().parents[1]


def test_partition_digests_match_version_manifest() -> None:
    verify_manifest_digests()
    manifest = load_manifest()
    partitions = load_partitions()
    assert manifest["benchmark_version"] == BENCHMARK_VERSION
    assert partitions["benchmark_version"] == BENCHMARK_VERSION
    assert manifest["case_count"] == len(load_all_cases())
    assert set(manifest["partition_digests"]) == set(PARTITIONS)


def test_manifest_schema_valid() -> None:
    payload = read_json_file(MANIFEST_PATH)
    schema = read_json_file(ROOT / "schemas" / "formal_pr_bench.manifest.schema.json")
    require_schema_valid(payload, schema, context="formal_pr_bench manifest")


def test_template_dev_and_held_out_are_disjoint() -> None:
    assert_no_template_dev_contamination()
    template_dev = load_template_dev_cases()
    held_out = set(load_partitions()["partitions"]["held_out"])
    assert template_dev.isdisjoint(held_out)
    assert held_out
    for case_id in held_out:
        assert (HELD_OUT_DIR / f"{case_id}.json").is_file()
        assert (PROVENANCE_DIR / f"{case_id}.json").is_file()
        assert (RATIONALES_DIR / f"{case_id}.md").is_file()


def test_every_case_has_provenance_rationale_and_license() -> None:
    cases = load_all_cases()
    licenses = json.loads((BENCH_DIR / "licenses.json").read_text(encoding="utf-8"))
    membership = partition_membership()
    assert set(membership) == set(cases)
    for case_id in cases:
        assert (PROVENANCE_DIR / f"{case_id}.json").is_file()
        assert (RATIONALES_DIR / f"{case_id}.md").is_file()
        assert case_id in licenses["cases"]
        assert licenses["cases"][case_id]["license"] == "Apache-2.0"


def test_real_diff_corpus_synced_to_eighteen() -> None:
    real_diff = json.loads((BENCH_DIR / "real_diff_cases.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / "benchmarks" / "real_diffs" / "manifest.json").read_text(encoding="utf-8"))
    assert len(real_diff["cases"]) == 18
    assert len(manifest["cases"]) == 18
    assert {case["case_id"] for case in real_diff["cases"]} == {
        case["case_id"] for case in manifest["cases"]
    }
    assert load_manifest()["real_diff_case_count"] == 18


def test_mutations_and_adversarial_present() -> None:
    mutations = list((BENCH_DIR / "mutations").glob("*.json"))
    adversarial = list((BENCH_DIR / "adversarial").glob("*"))
    assert len(mutations) >= 3
    assert any(path.suffix == ".diff" for path in adversarial)
    assert (BENCH_DIR / "duplication_report.json").is_file()


def test_published_leaderboard_requires_version_and_partition() -> None:
    scores = [
        DimensionScore(
            case_id="example",
            category="lane",
            passed=True,
            merge_decision_correct=True,
            status_correct=True,
            counterexample_useful=None,
            backend_selection_correct=None,
            evidence_honest=True,
            elapsed_ms=1.0,
            details={},
        )
    ]
    leaderboard = build_leaderboard(
        scores,
        benchmark_name="FormalPR-Bench",
        case_set="unit",
        partition="test",
        benchmark_version=BENCHMARK_VERSION,
    )
    require_published_score_identity(leaderboard)
    assert leaderboard["benchmark_version"] == BENCHMARK_VERSION
    assert leaderboard["partition"] == "test"

    broken = dict(leaderboard)
    broken.pop("partition")
    with pytest.raises(ProvenanceError, match="partition"):
        require_published_score_identity(broken)


def test_held_out_scoring_rejects_template_dev_contamination() -> None:
    template_dev = sorted(load_template_dev_cases())
    assert template_dev
    with pytest.raises(ProvenanceError, match="template-dev contamination"):
        assert_no_template_dev_contamination(
            scored_case_ids=[template_dev[0]],
            partition="held_out",
        )


def test_partition_filter_for_held_out_excludes_template_dev() -> None:
    cases = list(load_all_cases().values())
    held = filter_cases_for_partition(cases, partition="held_out")
    held_ids = {str(case["case_id"]) for case in held}
    assert held_ids == set(load_partitions()["partitions"]["held_out"])
    assert held_ids.isdisjoint(load_template_dev_cases())


def test_tampered_held_out_membership_fails_contamination_guard() -> None:
    partitions = copy.deepcopy(load_partitions())
    seed_case = sorted(load_template_dev_cases())[0]
    partitions["partitions"]["held_out"] = list(partitions["partitions"]["held_out"]) + [seed_case]
    with pytest.raises(ProvenanceError, match="template-dev contamination"):
        assert_no_template_dev_contamination(partitions=partitions)


def test_tampered_partition_digest_fails_manifest_check() -> None:
    partitions = copy.deepcopy(load_partitions())
    partitions["partitions"]["test"] = list(partitions["partitions"]["test"])[:-1]
    with pytest.raises(ProvenanceError, match="partition digest mismatch"):
        verify_manifest_digests(partitions=partitions)


def test_template_dev_registry_matches_seed_cases() -> None:
    seed = json.loads((BENCH_DIR / "seed_cases.json").read_text(encoding="utf-8"))
    template_dev = load_template_dev_cases()
    assert template_dev == {str(case["case_id"]) for case in seed["cases"]}
    assert TEMPLATE_DEV_PATH.is_file()
    assert PARTITIONS_PATH.is_file()
