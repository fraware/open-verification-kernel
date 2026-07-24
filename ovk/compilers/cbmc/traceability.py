"""Harness/obligation traceability helpers for CBMC."""

from __future__ import annotations

from ovk.compilers.cbmc.project import CbmcHarness, CbmcProject


REQUIRED_TRACEABILITY_FIELDS = (
    "harness_id",
    "entry_function",
    "traces_to_obligation_id",
    "traces_to_intent_id",
    "traces_to_source_functions",
    "includes_project_code",
)


def traceability_record(harness: CbmcHarness) -> dict[str, object]:
    return {
        "harness_id": harness.harness_id,
        "entry_function": harness.entry_function,
        "traces_to_obligation_id": harness.traces_to_obligation_id,
        "traces_to_intent_id": harness.traces_to_intent_id,
        "traces_to_source_functions": list(harness.traces_to_source_functions),
        "includes_project_code": harness.includes_project_code,
        "bound": harness.bound,
        "source_path": harness.source_path,
    }


def validate_project_traceability(project: CbmcProject) -> list[str]:
    failures: list[str] = []
    for harness in project.harnesses:
        record = traceability_record(harness)
        for field in REQUIRED_TRACEABILITY_FIELDS:
            if record.get(field) in (None, [], ""):
                failures.append(f"{harness.harness_id}: missing {field}")
        if project.guarantee_type == "bounded_project_model_check" and not harness.includes_project_code:
            failures.append(f"{harness.harness_id}: bounded_project_model_check requires includes_project_code")
    return failures
