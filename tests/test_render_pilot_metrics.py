"""Tests for adoption summary rendering."""

from __future__ import annotations

from pathlib import Path

from ovk.core.json_io import read_json_file, write_json_file
from ovk.core.schema_validation import require_schema_valid
from scripts.collect_pilot_metrics import collect_pilot_metrics, validate_metrics
from scripts.render_pilot_metrics import (
    load_external_pilots_registry,
    merge_external_pilots,
    render_adoption_summary,
    validate_summary,
)


def test_render_adoption_summary_shape() -> None:
    metrics = collect_pilot_metrics(source="local")
    validate_metrics(metrics)
    summary = render_adoption_summary(metrics)
    validate_summary(summary)
    assert summary["real_diff_recall"] == 1.0
    assert summary["formal_pr_bench"]["cases_total"] == 130
    assert summary["formal_pr_bench"]["pass_rate"] == 1.0
    assert summary["updated_at"] is not None
    assert summary["pilot_dogfood"]["ovk_version_pin"] == metrics["ovk_version"]
    assert summary["pilot_dogfood"]["manifests_passed"] == metrics["adoption"]["pilot_dogfood"]["manifests_passed"]


def test_adoption_summary_template_is_schema_valid() -> None:
    template = read_json_file(Path("docs/benchmarks/adoption-summary.json"))
    schema = read_json_file(Path("schemas/adoption.summary.schema.json"))
    require_schema_valid(template, schema, context="adoption summary template")


def test_render_preserves_registry_external_pilots() -> None:
    registry_path = Path("docs/benchmarks/external-pilots-registry.json")
    metrics = collect_pilot_metrics(source="local")
    summary = render_adoption_summary(metrics, registry_path=registry_path)
    validate_summary(summary)
    registry_rows = load_external_pilots_registry(registry_path)
    assert len(registry_rows) >= 1
    assert len(summary["external_pilots"]) >= len(registry_rows)
    assert any(item.get("status") == "recruiting" for item in summary["external_pilots"])


def test_render_merge_preserves_registry_on_rerender(tmp_path: Path) -> None:
    registry_path = tmp_path / "registry.json"
    write_json_file(
        registry_path,
        {
            "schema_version": "ovk.external_pilots_registry.v1",
            "updated_at": "2026-06-10T00:00:00Z",
            "external_pilots": [
                {
                    "repository": "example/oss-pilot",
                    "status": "advisory",
                    "check_types": ["ci_secrets"],
                    "advisory_start": "2026-06-01",
                    "advisory_end": None,
                    "prs_evaluated": 3,
                    "prs_blocked": 1,
                    "false_positives": 0,
                    "false_positive_rate": 0.0,
                    "median_check_latency_ms": 120.0,
                    "strict_enabled": False,
                    "ovk_version_pin": "1.2.0",
                    "workflow_path": ".github/workflows/ovk-pilot.yml",
                }
            ],
        },
    )
    metrics = collect_pilot_metrics(source="local")
    first = render_adoption_summary(metrics, registry_path=registry_path)
    second = render_adoption_summary(
        metrics,
        registry_path=registry_path,
        existing_summary={
            "external_pilots": [
                {
                    "repository": "example/oss-pilot",
                    "status": "recruiting",
                    "check_types": ["ci_secrets"],
                    "strict_enabled": False,
                    "ovk_version_pin": "1.2.0",
                    "prs_evaluated": 1,
                }
            ]
        },
    )
    validate_summary(second)
    assert any(item["repository"] == "example/oss-pilot" for item in second["external_pilots"])
    oss_row = next(item for item in second["external_pilots"] if item["repository"] == "example/oss-pilot")
    assert oss_row["status"] == "advisory"
    assert oss_row["prs_evaluated"] == 3
    rerendered = render_adoption_summary(metrics, registry_path=registry_path, existing_summary=first)
    assert any(item["repository"] == "example/oss-pilot" for item in rerendered["external_pilots"])


def test_merge_external_pilots_registry_wins_on_conflict() -> None:
    merged = merge_external_pilots(
        [{"repository": "org/repo", "status": "advisory", "check_types": ["ci_secrets"], "strict_enabled": False, "ovk_version_pin": "1.2.0", "prs_evaluated": 5}],
        [{"repository": "org/repo", "status": "recruiting", "check_types": ["ci_secrets"], "strict_enabled": False, "ovk_version_pin": "1.2.0", "prs_evaluated": 1}],
    )
    assert len(merged) == 1
    assert merged[0]["status"] == "advisory"
    assert merged[0]["prs_evaluated"] == 5
