"""Validate published OVK-PR8 pilot reports under docs/pilots/."""

from __future__ import annotations

from pathlib import Path

from ovk.core.json_io import read_json_file
from ovk.core.schema_validation import require_schema_valid

ROOT = Path(__file__).resolve().parents[1]
PILOTS_DIR = ROOT / "docs" / "pilots"
PILOT_REPORT_SCHEMA = ROOT / "schemas" / "pilot.report.schema.json"
REGISTRY = ROOT / "docs" / "benchmarks" / "external-pilots-registry.json"

REQUIRED_SLUGS = (
    "fastapi-terraform",
    "express-actions",
    "infra-terraform-k8s",
)

REQUIRED_REPORT_SECTIONS = (
    "Repository profile",
    "Checks selected",
    "False positives",
    "False negatives",
    "Unknowns",
    "Human review burden",
    "Configuration changes",
    "Strict-mode recommendation",
)


def test_three_pilot_reports_published() -> None:
    for slug in REQUIRED_SLUGS:
        report_md = PILOTS_DIR / slug / "REPORT.md"
        pilot_report = PILOTS_DIR / slug / "pilot-report.json"
        external_report = PILOTS_DIR / slug / "external_pilot_report.json"
        assert report_md.is_file(), f"missing {report_md}"
        assert pilot_report.is_file(), f"missing {pilot_report}"
        assert external_report.is_file(), f"missing {external_report}"


def test_published_pilot_reports_match_schema() -> None:
    schema = read_json_file(PILOT_REPORT_SCHEMA)
    for slug in REQUIRED_SLUGS:
        payload = read_json_file(PILOTS_DIR / slug / "pilot-report.json")
        require_schema_valid(payload, schema, context=f"docs/pilots/{slug}/pilot-report.json")
        assert payload["manifests_total"] >= 1
        assert payload["manifests_passed"] == payload["manifests_total"]


def test_published_report_markdown_covers_required_sections() -> None:
    for slug in REQUIRED_SLUGS:
        text = (PILOTS_DIR / slug / "REPORT.md").read_text(encoding="utf-8")
        for section in REQUIRED_REPORT_SECTIONS:
            assert section in text, f"{slug} REPORT.md missing section: {section}"


def test_external_reports_mark_maintained_vs_oss_and_remain_advisory() -> None:
    fastapi = read_json_file(PILOTS_DIR / "fastapi-terraform" / "external_pilot_report.json")
    express = read_json_file(PILOTS_DIR / "express-actions" / "external_pilot_report.json")
    infra = read_json_file(PILOTS_DIR / "infra-terraform-k8s" / "external_pilot_report.json")

    assert fastapi["consumer_kind"] == "maintained_consumer"
    assert express["consumer_kind"] == "maintained_consumer"
    assert infra["consumer_kind"] == "in_repo_maintained_profile"
    assert fastapi["complete_workflow_reproduction"] is True
    assert express["complete_workflow_reproduction"] is True
    assert infra["complete_workflow_reproduction"] is False

    for payload in (fastapi, express, infra):
        assert payload["strict_enabled"] is False
        assert payload["strict_mode_recommendation"] == "remain_advisory"
        assert payload["measurement_basis"] == "fixture_and_dogfood"
        assert payload["false_positive_rate"] == 0.0


def test_registry_includes_published_pilots() -> None:
    registry = read_json_file(REGISTRY)
    repos = {str(item["repository"]) for item in registry["external_pilots"]}
    assert "fraware/ovk-consumer-fastapi-terraform" in repos
    assert "fraware/ovk-consumer-express-actions" in repos
    assert "in-repo/ovk-pilot-infra-terraform-k8s" in repos
    assert any(item.get("status") == "recruiting" for item in registry["external_pilots"])


def test_infra_profile_scaffold_exists() -> None:
    profile = PILOTS_DIR / "infra-terraform-k8s" / "profile"
    assert (profile / "README.md").is_file()
    assert (profile / "ovk-pilot.workflow.yml").is_file()
    assert (ROOT / "examples" / "pilot_repos" / "infra_terraform_k8s.json").is_file()
    assert (ROOT / "examples" / "pilot_repos" / "fastapi_terraform_consumer.json").is_file()
    assert (ROOT / "examples" / "pilot_repos" / "express_actions_consumer.json").is_file()
