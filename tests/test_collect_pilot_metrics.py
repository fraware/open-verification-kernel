"""Tests for pilot metrics collection."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.json_io import read_json_file
from ovk.core.schema_validation import require_schema_valid
from scripts.collect_pilot_metrics import collect_from_artifacts_dir, collect_pilot_metrics, validate_metrics


def test_collect_pilot_metrics_schema_valid() -> None:
    metrics = collect_pilot_metrics(source="local")
    schema = read_json_file(Path("schemas/pilot.metrics.schema.json"))
    require_schema_valid(metrics, schema, context="pilot metrics")
    validate_metrics(metrics)
    assert metrics["pilot_report"]["manifests_passed"] == metrics["pilot_report"]["manifests_total"]
    assert metrics["adoption"]["pilot_dogfood"]["false_positive_rate"] == 0.0


def test_collect_pilot_metrics_with_evidence(tmp_path: Path) -> None:
    evidence_path = tmp_path / "ovk-evidence.json"
    evidence_path.write_text(
        json.dumps({"decision": {"merge_recommendation": "block"}}),
        encoding="utf-8",
    )
    metrics = collect_pilot_metrics(source="pilot-dogfood", evidence_path=evidence_path)
    assert metrics["adoption"]["pilot_dogfood"]["block_rate_on_unsafe_fixture"] == 1.0


def test_collect_from_artifacts_dir(tmp_path: Path) -> None:
    metrics = collect_pilot_metrics(source="local")
    (tmp_path / "pilot-report.json").write_text(json.dumps(metrics["pilot_report"]), encoding="utf-8")
    (tmp_path / "ovk-evidence.json").write_text(
        json.dumps({"decision": {"merge_recommendation": "block"}}),
        encoding="utf-8",
    )
    bundle_dir = tmp_path / "pilot-dogfood-bundle"
    bundle_dir.mkdir()
    (bundle_dir / "marker.txt").write_text("bundle", encoding="utf-8")

    parsed = collect_from_artifacts_dir(tmp_path, source="pilot_dogfood", ovk_version="1.2.0")
    validate_metrics(parsed)
    assert parsed["bundle_artifacts"]
