"""Template Conformance v3 maturity projection.

The legacy conformance builder remains the source of catalog metadata and
executable-link evidence. This module is the normative maturity layer. Local
source-profile demonstrations may establish candidate evidence, but they do not
satisfy the corpus, error-path, installed-package, Action, or external evidence
obligations required for strict maturity.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ovk.core import template_conformance as legacy
from ovk.core.source_profile_maturity import (
    SourceProfileMaturity,
    SourceProfileQualification,
    classify_source_profile_maturity,
    qualification_from_dict,
    qualification_from_local_profile_evidence,
)

REQUIRED_ROW_FIELDS = legacy.REQUIRED_ROW_FIELDS
REQUIRED_EXECUTABLE_LINKS = legacy.REQUIRED_EXECUTABLE_LINKS
PRODUCTION_STATUSES = tuple(legacy.STATUS_RANK)
CONFORMANCE_STATUSES_V3: tuple[SourceProfileMaturity, ...] = (
    "deprecated",
    "catalog_only",
    "executable_advisory",
    "source_profile_candidate",
    "source_profile_strict_eligible",
    "externally_calibrated_strict",
)
CONFORMANCE_STATUSES_V2 = (
    "deprecated",
    "catalog_only",
    "executable_advisory",
    "source_profile_strict_eligible",
    "externally_calibrated_strict",
)

_V2_COMPATIBILITY = {
    "deprecated": "deprecated",
    "catalog_only": "catalog_only",
    "executable_advisory": "executable_advisory",
    # v2 had no candidate state. Down-projecting a candidate to advisory is the
    # only conservative compatibility representation.
    "source_profile_candidate": "executable_advisory",
    "source_profile_strict_eligible": "source_profile_strict_eligible",
    "externally_calibrated_strict": "externally_calibrated_strict",
}

# Re-export legacy catalog helpers for callers that need raw template
# classification. Maturity consumers should use build_conformance_matrix below.
classify_template = legacy.classify_template
domain_counts_markdown = legacy.domain_counts_markdown


def _executable(row: dict[str, Any]) -> bool:
    if row.get("production_status") in {"deprecated", "catalog_only"}:
        return False
    links = row.get("executable_links")
    if not isinstance(links, dict):
        return False
    return bool(links.get("neutral_compiler") and links.get("backend_registry"))


def _sanitize_local_evidence(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    sanitized = dict(payload)
    legacy_predicate = bool(sanitized.pop("strict_eligible", False))
    sanitized["candidate_evidence_complete"] = legacy_predicate
    sanitized["evidence_scope"] = "local_profile_regression"
    sanitized["maturity_effect"] = "candidate_only"
    return sanitized


def _qualification_for_row(row: dict[str, Any]) -> SourceProfileQualification | None:
    profile_id = row.get("source_profile_id")
    evidence = row.get("source_profile_evidence")
    if not profile_id or not isinstance(evidence, dict):
        return None
    links = row.get("executable_links") if isinstance(row.get("executable_links"), dict) else {}
    return qualification_from_local_profile_evidence(
        profile_id=str(profile_id),
        materials_trusted=bool(evidence.get("materials_trusted")),
        coverage_complete=bool(evidence.get("coverage_complete")),
        enforcement_test_present=bool(evidence.get("enforcement_test_present")),
        executable_path_complete=not bool(row.get("missing_executable_links")),
        compiler_binding_present=bool(links.get("neutral_compiler")),
    )


def _qualification_payload(qualification: SourceProfileQualification) -> dict[str, Any]:
    payload = asdict(qualification)
    payload["candidate_ready"] = qualification.candidate_ready()
    payload["strict_ready"] = qualification.strict_ready()
    payload["unmet_strict_obligations"] = list(qualification.unmet_strict_obligations())
    return payload


def _project_row(row: dict[str, Any]) -> dict[str, Any]:
    projected = json.loads(json.dumps(row))
    sanitized = _sanitize_local_evidence(projected.get("source_profile_evidence"))
    if sanitized is None:
        projected.pop("source_profile_evidence", None)
    else:
        projected["source_profile_evidence"] = sanitized

    notes = projected.get("notes")
    if isinstance(notes, list):
        projected["notes"] = [
            "source_profile_evidence:candidate_complete"
            if str(note) == "source_profile_evidence:strict_ok"
            else note
            for note in notes
        ]

    qualification = _qualification_for_row(row)
    status = classify_source_profile_maturity(
        qualification,
        executable=_executable(row),
        deprecated=row.get("production_status") == "deprecated",
        # External calibration is deliberately not inferred from template
        # metadata or local generation.
        external_calibration=None,
    )
    projected["conformance_status_v3"] = status
    projected["conformance_status_v2"] = _V2_COMPATIBILITY[status]
    if qualification is not None:
        projected["source_profile_qualification"] = _qualification_payload(qualification)
        projected.setdefault("notes", []).append("v3_maturity:" + status)
    return projected


def build_conformance_matrix(repo_root: Path, templates_dir: Path | None = None) -> dict[str, Any]:
    """Build the normative v3 matrix from legacy catalog/link evidence."""
    raw = legacy.build_conformance_matrix(repo_root, templates_dir=templates_dir)
    rows = [_project_row(row) for row in raw.get("templates") or [] if isinstance(row, dict)]

    top_evidence: dict[str, Any] = {}
    for intent_id, payload in sorted((raw.get("source_profile_evidence") or {}).items()):
        sanitized = _sanitize_local_evidence(payload if isinstance(payload, dict) else None)
        if sanitized is not None:
            top_evidence[str(intent_id)] = sanitized

    counts_v3 = Counter(str(row["conformance_status_v3"]) for row in rows)
    counts_v2 = Counter(str(row["conformance_status_v2"]) for row in rows)
    payload = dict(raw)
    payload.update(
        {
            "schema_version": "ovk.template_conformance.v3",
            "conformance_statuses_v3": list(CONFORMANCE_STATUSES_V3),
            "counts_by_status_v3": dict(sorted(counts_v3.items())),
            "conformance_statuses_v2": list(CONFORMANCE_STATUSES_V2),
            "counts_by_status_v2": dict(sorted(counts_v2.items())),
            "source_profile_evidence": top_evidence,
            "maturity_contract": {
                "normative_status_field": "conformance_status_v3",
                "local_profile_evidence_maximum": "source_profile_candidate",
                "strict_requires_complete_machine_qualification": True,
                "external_calibration_inferred_from_template_metadata": False,
            },
            "templates": rows,
        }
    )
    return payload


def _qualification_from_row(row: dict[str, Any]) -> SourceProfileQualification | None:
    payload = row.get("source_profile_qualification")
    if not isinstance(payload, dict):
        return None
    return qualification_from_dict(payload)


def validate_matrix(matrix: dict[str, Any]) -> list[str]:
    """Validate v3 maturity without trusting self-declared status fields."""
    failures: list[str] = []
    if matrix.get("schema_version") != "ovk.template_conformance.v3":
        failures.append("schema_version must be ovk.template_conformance.v3")

    contract = matrix.get("maturity_contract")
    if not isinstance(contract, dict) or contract.get("normative_status_field") != "conformance_status_v3":
        failures.append("maturity_contract must declare conformance_status_v3 as normative")

    templates = matrix.get("templates")
    if not isinstance(templates, list) or not templates:
        failures.append("templates must be a non-empty list")
        return failures

    allowed_v3 = set(CONFORMANCE_STATUSES_V3)
    allowed_v2 = set(CONFORMANCE_STATUSES_V2)
    observed_v3: Counter[str] = Counter()
    observed_v2: Counter[str] = Counter()

    for index, row in enumerate(templates):
        if not isinstance(row, dict):
            failures.append(f"templates[{index}] must be an object")
            continue
        for field in REQUIRED_ROW_FIELDS:
            if field not in row:
                failures.append(f"templates[{index}] missing required field {field}")

        production_status = row.get("production_status")
        if production_status not in PRODUCTION_STATUSES:
            failures.append(f"templates[{index}] invalid production_status {production_status!r}")

        status_v3 = row.get("conformance_status_v3")
        if status_v3 not in allowed_v3:
            failures.append(f"templates[{index}] invalid conformance_status_v3 {status_v3!r}")
            continue
        observed_v3[str(status_v3)] += 1

        status_v2 = row.get("conformance_status_v2")
        if status_v2 not in allowed_v2:
            failures.append(f"templates[{index}] invalid conformance_status_v2 {status_v2!r}")
        else:
            observed_v2[str(status_v2)] += 1
        if status_v2 != _V2_COMPATIBILITY[str(status_v3)]:
            failures.append(
                f"{row.get('intent_id')}: v2 compatibility status must conservatively project v3 maturity"
            )

        qualification = _qualification_from_row(row)
        if status_v3 == "source_profile_candidate":
            if qualification is None or not qualification.candidate_ready() or qualification.strict_ready():
                failures.append(
                    f"{row.get('intent_id')}: source_profile_candidate requires candidate-ready, non-strict qualification"
                )
        if status_v3 in {"source_profile_strict_eligible", "externally_calibrated_strict"}:
            if qualification is None or not qualification.strict_ready():
                failures.append(
                    f"{row.get('intent_id')}: {status_v3} requires complete machine strict qualification"
                )
        if status_v3 == "externally_calibrated_strict":
            failures.append(
                f"{row.get('intent_id')}: external calibration requires a separately verified artifact and is not locally derivable"
            )

        local_evidence = row.get("source_profile_evidence")
        if isinstance(local_evidence, dict) and "strict_eligible" in local_evidence:
            failures.append(
                f"{row.get('intent_id')}: local source-profile evidence must not expose a strict_eligible maturity assertion"
            )

        missing = row.get("missing_executable_links") or []
        if production_status == "strict_eligible" and missing:
            failures.append(f"{row.get('intent_id')}: legacy strict_eligible requires empty missing_executable_links")

    stated_v3 = Counter({str(k): int(v) for k, v in (matrix.get("counts_by_status_v3") or {}).items()})
    stated_v2 = Counter({str(k): int(v) for k, v in (matrix.get("counts_by_status_v2") or {}).items()})
    if stated_v3 != observed_v3:
        failures.append("counts_by_status_v3 does not match template rows")
    if stated_v2 != observed_v2:
        failures.append("counts_by_status_v2 does not match conservative v2 projections")

    top_evidence = matrix.get("source_profile_evidence")
    if isinstance(top_evidence, dict):
        for intent_id, payload in top_evidence.items():
            if isinstance(payload, dict) and "strict_eligible" in payload:
                failures.append(
                    f"{intent_id}: top-level local source-profile evidence must not expose strict_eligible"
                )
    return failures


def write_conformance_matrix(repo_root: Path, output: Path) -> dict[str, Any]:
    matrix = build_conformance_matrix(repo_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return matrix
