#!/usr/bin/env python3
"""Reproduce the post-audit structural-circularity finding for pilot N=10."""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
SEALED = ROOT / "experiments" / "rtk" / "sealed" / "pilot_n10"


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main() -> int:
    cdis = read_jsonl(SEALED / "CanonicalDecisionInput.tier_a.jsonl")
    oracle_records = read_jsonl(SEALED / "ORACLE.jsonl")
    predictions = read_jsonl(SEALED / "RTK_PREDICTIONS.jsonl")

    oracle = {item["case_id"]: item for item in oracle_records}
    predicted = {item["decision_input_id"]: item for item in predictions}

    findings = {
        "case_count": len(cdis),
        "complete_evidence_snapshots": 0,
        "evidence_artifact_paths_equal_context_footprint_elements": 0,
        "footprint_fully_covered_by_artifact_paths": 0,
        "oracle_and_predictor_reduced_to_same_path_intersection_predicate": 0,
        "oracle_prediction_agreement": 0,
        "exceptions": [],
    }

    for cdi in cdis:
        case_id = cdi["decision_input_id"]
        evidence = cdi["evidence_snapshot"]
        artifact_paths = {str(item["path"]) for item in evidence["artifact_refs"]}
        footprint_paths = {str(item) for item in cdi["context_footprint"]["elements"]}
        changed_paths = {str(item) for item in cdi["transition"]["changed_paths"]}

        if evidence["completeness"] == "COMPLETE":
            findings["complete_evidence_snapshots"] += 1

        sets_equal = artifact_paths == footprint_paths
        if sets_equal:
            findings["evidence_artifact_paths_equal_context_footprint_elements"] += 1

        covered = footprint_paths <= artifact_paths
        if covered:
            findings["footprint_fully_covered_by_artifact_paths"] += 1

        expected_oracle = (
            "VALID"
            if not (artifact_paths & changed_paths)
            else "REVALIDATION_REQUIRED"
        )
        expected_predictor = (
            "VALID"
            if not (footprint_paths & changed_paths)
            else "REVALIDATION_REQUIRED"
        )

        actual_oracle = oracle[case_id]["verdict"]
        actual_predictor = predicted[case_id]["verdict"]

        mechanically_implied = (
            sets_equal
            and actual_oracle == expected_oracle
            and actual_predictor == expected_predictor
        )
        if mechanically_implied:
            findings[
                "oracle_and_predictor_reduced_to_same_path_intersection_predicate"
            ] += 1

        if actual_oracle == actual_predictor:
            findings["oracle_prediction_agreement"] += 1

        if not (
            evidence["completeness"] == "COMPLETE"
            and sets_equal
            and covered
            and mechanically_implied
            and actual_oracle == actual_predictor
        ):
            findings["exceptions"].append(case_id)

    n = findings["case_count"]
    required = (
        n == 16
        and findings["complete_evidence_snapshots"] == n
        and findings[
            "evidence_artifact_paths_equal_context_footprint_elements"
        ] == n
        and findings["footprint_fully_covered_by_artifact_paths"] == n
        and findings[
            "oracle_and_predictor_reduced_to_same_path_intersection_predicate"
        ] == n
        and findings["oracle_prediction_agreement"] == n
        and not findings["exceptions"]
    )

    output = {
        "schema_version": "rtk.methodological_audit_reproducer.v0",
        "status": "CONFIRMED" if required else "NOT_CONFIRMED",
        **findings,
        "interpretation": (
            "The 16/16 score is structural-consistency evidence because the "
            "oracle and predictor use extensionally identical path-intersection "
            "statistics on every sealed case."
            if required
            else "The committed methodological-audit conclusion no longer follows "
            "from the checked repository bytes."
        ),
    }
    print(json.dumps(output, sort_keys=True, indent=2))
    return 0 if required else 1


if __name__ == "__main__":
    sys.exit(main())
