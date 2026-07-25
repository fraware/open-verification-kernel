"""FormalPR-Bench provenance, partitions, and contamination guards (OVK-06)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

BENCH_DIR = Path(__file__).resolve().parent
ROOT = BENCH_DIR.parents[1]

BENCHMARK_VERSION = "v1"
MANIFEST_NAME = f"manifest.{BENCHMARK_VERSION}.json"
PARTITIONS = ("train", "development", "test", "held_out")
TEMPLATE_DEV_PATH = BENCH_DIR / "template_dev_cases.json"
PARTITIONS_PATH = BENCH_DIR / "partitions.json"
LICENSES_PATH = BENCH_DIR / "licenses.json"
DUPLICATION_REPORT_PATH = BENCH_DIR / "duplication_report.json"
MANIFEST_PATH = BENCH_DIR / MANIFEST_NAME
PROVENANCE_DIR = BENCH_DIR / "provenance"
RATIONALES_DIR = BENCH_DIR / "rationales"
HELD_OUT_DIR = BENCH_DIR / "held_out"
MUTATIONS_DIR = BENCH_DIR / "mutations"
ADVERSARIAL_DIR = BENCH_DIR / "adversarial"

CASE_SOURCES = (
    BENCH_DIR / "seed_cases_expanded.json",
    BENCH_DIR / "extended_cases.json",
    BENCH_DIR / "real_diff_cases.json",
)


class ProvenanceError(ValueError):
    """Raised when FormalPR-Bench provenance or partition rules are violated."""


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(payload: Any) -> str:
    """Return a hex SHA-256 digest over canonical JSON."""
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def partition_digest(case_ids: Iterable[str]) -> str:
    """Digest a partition membership list (order-independent)."""
    return sha256_hex({"case_ids": sorted(str(case_id) for case_id in case_ids)})


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_all_cases() -> dict[str, dict[str, Any]]:
    """Load the canonical FormalPR-Bench corpus keyed by case_id."""
    cases: dict[str, dict[str, Any]] = {}
    for path in CASE_SOURCES:
        if not path.is_file():
            continue
        payload = load_json(path)
        for case in payload.get("cases", []):
            case_id = str(case["case_id"])
            if case_id in cases:
                raise ProvenanceError(f"duplicate case_id across corpora: {case_id}")
            cases[case_id] = dict(case)
            cases[case_id]["_source_file"] = str(path.relative_to(ROOT)).replace("\\", "/")
    return cases


def load_partitions() -> dict[str, Any]:
    if not PARTITIONS_PATH.is_file():
        raise ProvenanceError(f"missing partitions file: {PARTITIONS_PATH}")
    return load_json(PARTITIONS_PATH)


def load_template_dev_cases() -> set[str]:
    if not TEMPLATE_DEV_PATH.is_file():
        raise ProvenanceError(f"missing template-dev registry: {TEMPLATE_DEV_PATH}")
    payload = load_json(TEMPLATE_DEV_PATH)
    return {str(case_id) for case_id in payload.get("case_ids", [])}


def load_manifest() -> dict[str, Any]:
    if not MANIFEST_PATH.is_file():
        raise ProvenanceError(f"missing version manifest: {MANIFEST_PATH}")
    return load_json(MANIFEST_PATH)


def partition_membership(partitions: dict[str, Any] | None = None) -> dict[str, str]:
    """Return case_id -> partition name; raises on overlap or unknown partition keys."""
    payload = partitions or load_partitions()
    membership: dict[str, str] = {}
    for name in PARTITIONS:
        for case_id in payload.get("partitions", {}).get(name, []):
            case_id = str(case_id)
            if case_id in membership:
                raise ProvenanceError(
                    f"case {case_id} appears in both {membership[case_id]} and {name}"
                )
            membership[case_id] = name
    return membership


def assert_no_template_dev_contamination(
    *,
    scored_case_ids: Iterable[str] | None = None,
    partition: str | None = None,
    template_dev: set[str] | None = None,
    partitions: dict[str, Any] | None = None,
) -> None:
    """Fail closed when template-dev cases are counted as held-out evaluation.

    Rules:
    * The held_out partition must be disjoint from template_dev_cases.
    * Scoring with ``partition='held_out'`` must not include any template-dev case.
    """
    template = template_dev if template_dev is not None else load_template_dev_cases()
    payload = partitions or load_partitions()
    held_out = {str(case_id) for case_id in payload.get("partitions", {}).get("held_out", [])}
    overlap = sorted(held_out & template)
    if overlap:
        raise ProvenanceError(
            "template-dev contamination: held_out cases used during template development: "
            + ", ".join(overlap)
        )
    if partition == "held_out" and scored_case_ids is not None:
        scored = {str(case_id) for case_id in scored_case_ids}
        scored_overlap = sorted(scored & template)
        if scored_overlap:
            raise ProvenanceError(
                "template-dev contamination: cannot score template-dev cases as held_out: "
                + ", ".join(scored_overlap)
            )


def compute_partition_digests(partitions: dict[str, Any] | None = None) -> dict[str, str]:
    payload = partitions or load_partitions()
    return {
        name: partition_digest(payload.get("partitions", {}).get(name, []))
        for name in PARTITIONS
    }


def verify_manifest_digests(
    *,
    partitions: dict[str, Any] | None = None,
    manifest: dict[str, Any] | None = None,
) -> None:
    """Assert committed partition digests match the version manifest."""
    payload = partitions or load_partitions()
    man = manifest or load_manifest()
    expected = man.get("partition_digests", {})
    actual = compute_partition_digests(payload)
    mismatches: list[str] = []
    for name in PARTITIONS:
        if expected.get(name) != actual[name]:
            mismatches.append(f"{name}: expected {expected.get(name)} got {actual[name]}")
    if mismatches:
        raise ProvenanceError("partition digest mismatch vs version manifest: " + "; ".join(mismatches))
    if man.get("benchmark_version") != payload.get("benchmark_version"):
        raise ProvenanceError(
            f"benchmark_version mismatch: manifest={man.get('benchmark_version')} "
            f"partitions={payload.get('benchmark_version')}"
        )
    corpus_digest = sha256_hex({"partition_digests": actual, "benchmark_version": man.get("benchmark_version")})
    if man.get("corpus_digest") != corpus_digest:
        raise ProvenanceError(
            f"corpus_digest mismatch: expected {man.get('corpus_digest')} got {corpus_digest}"
        )


def filter_cases_for_partition(
    cases: list[dict[str, Any]],
    *,
    partition: str,
    partitions: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Filter cases to a named partition and enforce contamination guards."""
    if partition not in PARTITIONS:
        raise ProvenanceError(f"unknown partition: {partition}")
    membership = partition_membership(partitions)
    selected = [case for case in cases if membership.get(str(case["case_id"])) == partition]
    assert_no_template_dev_contamination(
        scored_case_ids=[str(case["case_id"]) for case in selected],
        partition=partition,
        partitions=partitions,
    )
    return selected


def require_published_score_identity(leaderboard: dict[str, Any]) -> None:
    """Published FormalPR-Bench scores must cite benchmark_version and partition."""
    if not leaderboard.get("benchmark_version"):
        raise ProvenanceError("published scores must cite benchmark_version")
    if not leaderboard.get("partition"):
        raise ProvenanceError("published scores must cite partition")


def build_version_manifest(
    *,
    partitions: dict[str, Any],
    case_count: int,
    licenses_digest: str,
    duplication_digest: str,
) -> dict[str, Any]:
    digests = compute_partition_digests(partitions)
    benchmark_version = str(partitions.get("benchmark_version", BENCHMARK_VERSION))
    return {
        "schema_version": "formal_pr_bench.manifest.v1",
        "benchmark_version": benchmark_version,
        "case_count": case_count,
        "partitions": list(PARTITIONS),
        "partition_digests": digests,
        "corpus_digest": sha256_hex({"partition_digests": digests, "benchmark_version": benchmark_version}),
        "licenses_digest": licenses_digest,
        "duplication_report_digest": duplication_digest,
        "artifact_layout": {
            "provenance": "provenance/<case_id>.json",
            "licenses": "licenses.json",
            "partitions": "partitions.json",
            "duplication_report": "duplication_report.json",
            "mutations": "mutations/",
            "held_out": "held_out/",
            "adversarial": "adversarial/",
            "rationales": "rationales/<case_id>.md",
            "template_dev_cases": "template_dev_cases.json",
        },
    }
