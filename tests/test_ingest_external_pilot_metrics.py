"""Tests for external pilot metrics ingest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.core.json_io import read_json_file, write_json_file
from ovk.core.schema_validation import require_schema_valid
from scripts.ingest_external_pilot_metrics import (
    build_pilot_row,
    load_registry,
    upsert_pilot_row,
    validate_registry,
)
from scripts.render_pilot_metrics import render_adoption_summary


def test_build_pilot_row_from_artifacts(tmp_path: Path) -> None:
    artifacts_dir = tmp_path / "artifacts"
    bundle_dir = artifacts_dir / "ovk-pilot-bundle"
    bundle_dir.mkdir(parents=True)
    (artifacts_dir / "ovk-evidence.json").write_text(
        json.dumps({"decision": {"merge_recommendation": "block"}, "timing_ms": {"p50": 88.5}}),
        encoding="utf-8",
    )
    (artifacts_dir / "external_pilot_report.json").write_text(
        json.dumps(
            {
                "repository": "example/oss-pilot",
                "advisory_start": "2026-06-01",
                "prs_evaluated": 4,
                "false_positive_rate": 0.0,
                "strict_enabled": False,
            }
        ),
        encoding="utf-8",
    )

    row = build_pilot_row("example/oss-pilot", artifacts_dir=artifacts_dir, ovk_version="1.2.0")
    assert row["repository"] == "example/oss-pilot"
    assert row["prs_evaluated"] == 4
    assert row["false_positive_rate"] == 0.0
    assert row["median_check_latency_ms"] == 88.5
    assert row["status"] == "advisory"


def test_upsert_pilot_row_updates_registry(tmp_path: Path) -> None:
    registry_path = tmp_path / "registry.json"
    write_json_file(
        registry_path,
        {
            "schema_version": "ovk.external_pilots_registry.v1",
            "updated_at": "2026-06-10T00:00:00Z",
            "external_pilots": [
                {
                    "repository": "example/oss-pilot",
                    "status": "recruiting",
                    "check_types": ["ci_secrets"],
                    "strict_enabled": False,
                    "ovk_version_pin": "1.2.0",
                }
            ],
        },
    )
    registry = load_registry(registry_path)
    write_json_file(
        tmp_path / "report.json",
        {
            "repository": "example/oss-pilot",
            "advisory_start": "2026-06-01",
            "prs_evaluated": 2,
            "false_positive_rate": 0.0,
            "strict_enabled": False,
        },
    )
    row = build_pilot_row(
        "example/oss-pilot",
        report_path=tmp_path / "report.json",
        ovk_version="1.2.0",
        existing=registry["external_pilots"][0],
    )
    updated = upsert_pilot_row(registry, row)
    validate_registry(updated)
    assert updated["external_pilots"][0]["status"] == "advisory"
    assert updated["external_pilots"][0]["prs_evaluated"] == 2


def test_ingest_then_render_preserves_registry_row(tmp_path: Path) -> None:
    from scripts.collect_pilot_metrics import collect_pilot_metrics
    from scripts.ingest_external_pilot_metrics import main as ingest_main

    registry_path = tmp_path / "registry.json"
    write_json_file(
        registry_path,
        {
            "schema_version": "ovk.external_pilots_registry.v1",
            "updated_at": "2026-06-10T00:00:00Z",
            "external_pilots": [],
        },
    )
    report_path = tmp_path / "external_pilot_report.json"
    write_json_file(
        report_path,
        {
            "repository": "example/oss-pilot",
            "advisory_start": "2026-06-01",
            "prs_evaluated": 5,
            "false_positive_rate": 0.0,
            "strict_enabled": False,
        },
    )

    import sys

    argv = [
        "ingest_external_pilot_metrics.py",
        "--repo",
        "example/oss-pilot",
        "--report",
        str(report_path),
        "--registry",
        str(registry_path),
    ]
    old_argv = sys.argv
    try:
        sys.argv = argv
        assert ingest_main() == 0
    finally:
        sys.argv = old_argv

    metrics = collect_pilot_metrics(source="local")
    summary = render_adoption_summary(metrics, registry_path=registry_path)
    require_schema_valid(summary, read_json_file(Path("schemas/adoption.summary.schema.json")), context="summary")
    assert any(item["repository"] == "example/oss-pilot" for item in summary["external_pilots"])


def test_validate_registry_rejects_invalid_row(tmp_path: Path) -> None:
    registry = {
        "schema_version": "ovk.external_pilots_registry.v1",
        "updated_at": "2026-06-10T00:00:00Z",
        "external_pilots": [{"repository": "bad/repo", "status": "unknown", "check_types": ["ci_secrets"], "strict_enabled": False, "ovk_version_pin": "1.2.0"}],
    }
    with pytest.raises(ValueError, match="external pilots registry failed schema validation"):
        validate_registry(registry)
