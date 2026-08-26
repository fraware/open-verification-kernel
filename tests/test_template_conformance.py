"""Tests for Template Conformance v3 builder and gate logic."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.template_conformance_v3 import (
    REQUIRED_ROW_FIELDS,
    build_conformance_matrix,
    classify_template,
    domain_counts_markdown,
    validate_matrix,
    write_conformance_matrix,
)


def test_build_matrix_covers_all_templates() -> None:
    repo = Path(__file__).resolve().parents[1]
    matrix = build_conformance_matrix(repo)
    on_disk = len(list((repo / "templates").rglob("*.intent.json")))
    assert matrix["template_count"] == on_disk == 100
    assert matrix["schema_version"] == "ovk.template_conformance.v3"
    assert matrix["maturity_contract"]["normative_status_field"] == "conformance_status_v3"
    assert set(matrix["required_row_fields"]) == set(REQUIRED_ROW_FIELDS)


def test_legacy_strict_eligible_lanes_have_complete_links() -> None:
    repo = Path(__file__).resolve().parents[1]
    matrix = build_conformance_matrix(repo)
    strict = [row for row in matrix["templates"] if row["production_status"] == "strict_eligible"]
    assert len(strict) >= 5
    for row in strict:
        assert row["missing_executable_links"] == []
        assert row["lane"] in {
            "authorization",
            "self_protection",
            "infrastructure",
            "ci_secrets",
            "deployment",
        }


def test_native_named_without_executable_path_is_catalog_only() -> None:
    repo = Path(__file__).resolve().parents[1]
    path = repo / "templates" / "data_boundary" / "cbmc_buffer_bounds.intent.json"
    template = json.loads(path.read_text(encoding="utf-8"))
    row = classify_template(repo_root=repo, intent_path=path, template=template)
    assert row.production_status == "catalog_only"
    assert "cbmc" in row.claimed_backends
    assert any("downgraded" in note for note in row.notes)


def test_validate_matrix_rejects_legacy_strict_with_missing_links() -> None:
    matrix = {
        "schema_version": "ovk.template_conformance.v3",
        "maturity_contract": {"normative_status_field": "conformance_status_v3"},
        "counts_by_status_v3": {"executable_advisory": 1},
        "counts_by_status_v2": {"executable_advisory": 1},
        "templates": [
            {
                "intent_id": "fake",
                "path": "templates/x.intent.json",
                "domain": "authorization",
                "version": "0.1.0",
                "production_status": "strict_eligible",
                "conformance_status_v3": "executable_advisory",
                "conformance_status_v2": "executable_advisory",
                "risk_severity": "high",
                "property_kind": "access_control",
                "acceptable_evidence_kinds": [],
                "claimed_backends": [],
                "executable_links": {},
                "missing_executable_links": ["fail_example"],
                "lane": "authorization",
                "notes": [],
            }
        ],
    }
    failures = validate_matrix(matrix)
    assert any("legacy strict_eligible requires empty" in item for item in failures)


def test_domain_counts_derived_from_matrix() -> None:
    repo = Path(__file__).resolve().parents[1]
    matrix = build_conformance_matrix(repo)
    md = domain_counts_markdown(matrix)
    assert "| `authorization/` |" in md
    assert f"**{matrix['template_count']}**" in md
    assert matrix["counts_by_domain"]["authorization"] == 18
    assert matrix["counts_by_domain"]["infrastructure"] == 19


def test_write_and_check_round_trip(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    output = tmp_path / "template-conformance.json"
    matrix = write_conformance_matrix(repo, output)
    assert output.is_file()
    assert validate_matrix(matrix) == []
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded["template_count"] == matrix["template_count"]
    assert loaded["schema_version"] == "ovk.template_conformance.v3"


def test_v3_local_qualification_stays_candidate_until_execution_attested() -> None:
    repo = Path(__file__).resolve().parents[1]
    matrix = build_conformance_matrix(repo)
    assert set(matrix["conformance_statuses_v3"]) == {
        "catalog_only",
        "executable_advisory",
        "source_profile_candidate",
        "source_profile_strict_eligible",
        "externally_calibrated_strict",
        "deprecated",
    }
    assert matrix["counts_by_status_v3"].get("externally_calibrated_strict", 0) == 0
    assert matrix["counts_by_status_v3"].get("source_profile_strict_eligible", 0) == 0
    assert matrix["counts_by_status_v3"].get("source_profile_candidate", 0) >= 1
    assert matrix["counts_by_status_v3"].get("executable_advisory", 0) >= 1

    by_id = {row["intent_id"]: row for row in matrix["templates"]}
    authorization = by_id["no-admin-route-bypass"]
    assert authorization["conformance_status_v3"] == "source_profile_candidate"
    assert authorization["conformance_status_v2"] == "executable_advisory"
    qualification = authorization["source_profile_qualification"]
    assert qualification["candidate_ready"] is True
    assert qualification["execution_attested"] is False
    assert qualification["strict_ready"] is False
    assert "candidate_bound_execution_attestation" in qualification["unmet_strict_obligations"]
    # Local evidence still cannot self-assert strict maturity.
    assert "strict_eligible" not in authorization["source_profile_evidence"]
    assert authorization["source_profile_evidence"]["maturity_effect"] == "candidate_only"

    self_protection = by_id["agent-cannot-disable-own-ci-gate"]
    assert self_protection["conformance_status_v3"] == "executable_advisory"


def test_v3_validation_rejects_local_external_calibration_claim() -> None:
    repo = Path(__file__).resolve().parents[1]
    matrix = build_conformance_matrix(repo)
    by_id = {row["intent_id"]: row for row in matrix["templates"]}
    row = by_id["no-admin-route-bypass"]
    prior_v3 = row["conformance_status_v3"]
    prior_v2 = row["conformance_status_v2"]
    row["conformance_status_v3"] = "externally_calibrated_strict"
    row["conformance_status_v2"] = "externally_calibrated_strict"
    matrix["counts_by_status_v3"][prior_v3] = matrix["counts_by_status_v3"].get(prior_v3, 1) - 1
    matrix["counts_by_status_v3"]["externally_calibrated_strict"] = (
        matrix["counts_by_status_v3"].get("externally_calibrated_strict", 0) + 1
    )
    matrix["counts_by_status_v2"][prior_v2] = matrix["counts_by_status_v2"].get(prior_v2, 1) - 1
    matrix["counts_by_status_v2"]["externally_calibrated_strict"] = (
        matrix["counts_by_status_v2"].get("externally_calibrated_strict", 0) + 1
    )
    failures = validate_matrix(matrix)
    assert any("external calibration" in item for item in failures)
