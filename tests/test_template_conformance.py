"""Tests for template conformance builder and gate logic."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.template_conformance import (
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
    assert matrix["schema_version"] == "ovk.template_conformance.v1"
    assert set(matrix["required_row_fields"]) == set(REQUIRED_ROW_FIELDS)


def test_strict_eligible_lanes_have_complete_links() -> None:
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


def test_validate_matrix_rejects_strict_with_missing_links() -> None:
    matrix = {
        "schema_version": "ovk.template_conformance.v1",
        "templates": [
            {
                "intent_id": "fake",
                "path": "templates/x.intent.json",
                "domain": "authorization",
                "version": "0.1.0",
                "production_status": "strict_eligible",
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
    assert any("strict_eligible" in item for item in failures)


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
