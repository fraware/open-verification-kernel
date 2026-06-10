"""Tests for adoption summary rendering."""

from __future__ import annotations

from pathlib import Path

from ovk.core.json_io import read_json_file
from ovk.core.schema_validation import require_schema_valid
from scripts.collect_pilot_metrics import collect_pilot_metrics, validate_metrics
from scripts.render_pilot_metrics import render_adoption_summary, validate_summary


def test_render_adoption_summary_shape() -> None:
    metrics = collect_pilot_metrics(source="pilot-dogfood")
    validate_metrics(metrics)
    summary = render_adoption_summary(metrics)
    validate_summary(summary)
    assert summary["real_diff_recall"] is not None or summary["real_diff_recall"] is None
    assert summary["pilot_dogfood"]["ovk_version_pin"] == metrics["ovk_version"]
    assert summary["pilot_dogfood"]["manifests_passed"] == metrics["adoption"]["pilot_dogfood"]["manifests_passed"]


def test_adoption_summary_template_is_schema_valid() -> None:
    template = read_json_file(Path("docs/benchmarks/adoption-summary.json"))
    schema = read_json_file(Path("schemas/adoption.summary.schema.json"))
    require_schema_valid(template, schema, context="adoption summary template")
