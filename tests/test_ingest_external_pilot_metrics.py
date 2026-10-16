"""Tests for external pilot metrics ingest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.core.json_io import read_json_file, write_json_file
from ovk.core.schema_validation import require_schema_valid
from scripts.ingest_external_pilot_metrics import (
    _metrics_from_artifacts,
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

    # The self-report must be separately selected as an adjudication source;
    # merely placing it inside downloaded CI artifacts is insufficient.
    row = build_pilot_row(
        "example/oss-pilot",
        artifacts_dir=artifacts_dir,
        report_path=artifacts_dir / "external_pilot_report.json",
        ovk_version="1.2.0",
    )
    assert row["repository"] == "example/oss-pilot"
    assert row["prs_evaluated"] == 4
    assert row["false_positive_rate"] == 0.0
    # The explicit report changes the cohort count without a bound evidence ID.
    # Preserve the reviewed report values, not latency from an unlinked artifact.
    assert row["median_check_latency_ms"] is None
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
        "external_pilots": [
            {
                "repository": "bad/repo",
                "status": "unknown",
                "check_types": ["ci_secrets"],
                "strict_enabled": False,
                "ovk_version_pin": "1.2.0",
            }
        ],
    }
    with pytest.raises(ValueError, match="external pilots registry failed schema validation"):
        validate_registry(registry)


def test_checker_decisions_cannot_self_adjudicate_false_positives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A blocked result is not independent evidence of a false alarm."""
    raw = tmp_path / "pilot-report.json"
    raw.write_text(
        json.dumps({
            "results": [
                {"passed": False, "merge_recommendation": "block", "elapsed_ms":12},
                {"passed": True, "merge_recommendation": "allow", "elapsed_ms":14},
            ]
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "scripts.collect_pilot_metrics.discover_artifacts_dir",
        lambda _: (raw, None, None),
    )
    metrics = _metrics_from_artifacts(tmp_path)
    assert metrics["prs_evaluated"] == 2
    assert metrics["prs_blocked"] == 1
    assert metrics["median_check_latency_ms"] == 13.0
    assert "false_positives" not in metrics
    assert "false_positive_rate" not in metrics


def test_new_artifacts_clear_stale_external_error_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Old reviewer labels must not be reused for a new unreviewed cohort."""
    monkeypatch.setattr(
        "scripts.ingest_external_pilot_metrics._metrics_from_artifacts",
        lambda _: {"prs_evaluated": 7, "prs_blocked": 2},
    )
    existing = {
        "repository": "example/oss-pilot",
        "status": "advisory",
        "check_types": ["ci_secrets"],
        "false_positives": 0,
        "false_positive_rate": 0.0,
        "strict_enabled": False,
        "ovk_version_pin": "1.2.1",
    }
    row = build_pilot_row(
        "example/oss-pilot", existing=existing, artifacts_dir=tmp_path
    )
    assert row["prs_evaluated"] == 7
    assert row["false_positives"] is None
    assert row["false_positive_rate"] is None


@pytest.mark.parametrize(
    "new_artifact_metrics",
    [{"prs_blocked": 1}, {"median_check_latency_ms": 23.0}, {}],
)
def test_partial_new_artifacts_invalidate_stale_error_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, new_artifact_metrics: dict
) -> None:
    """No denominator or aggregate results must not imply zero new errors."""
    monkeypatch.setattr(
        "scripts.ingest_external_pilot_metrics._metrics_from_artifacts",
        lambda _: new_artifact_metrics,
    )
    existing = {
        "repository": "example/oss-pilot",
        "status": "advisory",
        "check_types": ["ci_secrets"],
        "false_positives": 0,
        "false_positive_rate": 0.0,
        "strict_enabled": False,
        "ovk_version_pin": "1.2.1",
    }
    row = build_pilot_row("example/oss-pilot", existing=existing, artifacts_dir=tmp_path)
    assert row["false_positives"] is None
    assert row["false_positive_rate"] is None


def test_without_new_artifacts_historical_labels_are_not_silently_rewritten() -> None:
    existing = {
        "repository": "example/oss-pilot",
        "status": "advisory",
        "check_types": ["ci_secrets"],
        "false_positives": 1,
        "false_positive_rate": 0.5,
        "strict_enabled": False,
        "ovk_version_pin": "1.2.1",
    }
    row = build_pilot_row("example/oss-pilot", existing=existing)
    assert row["false_positives"] == 1
    assert row["false_positive_rate"] == 0.5


@pytest.mark.parametrize("input_kind", ["artifacts", "report"])
def test_explicit_missing_pilot_input_fails_closed(
    tmp_path: Path, input_kind: str
) -> None:
    """A missing operator-selected input must never preserve prior metrics."""
    missing = tmp_path / ("missing-artifacts" if input_kind == "artifacts" else "missing.json")
    params = {"artifacts_dir": missing} if input_kind == "artifacts" else {"report_path": missing}
    with pytest.raises(FileNotFoundError, match="not found"):
        build_pilot_row("example/oss-pilot", **params)


@pytest.mark.parametrize(
    "new_artifact_metrics",
    [{}, {"prs_blocked": 2}, {"median_check_latency_ms": 17.0}],
)
def test_partial_new_cohort_discards_all_stale_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, new_artifact_metrics: dict
) -> None:
    """A new partial cohort cannot inherit old PR totals or timings."""
    monkeypatch.setattr(
        "scripts.ingest_external_pilot_metrics._metrics_from_artifacts",
        lambda _: new_artifact_metrics,
    )
    existing = {
        "repository": "example/oss-pilot",
        "status": "advisory",
        "check_types": ["ci_secrets"],
        "prs_evaluated": 100,
        "prs_blocked": 20,
        "false_positives": 0,
        "false_positive_rate": 0.0,
        "median_check_latency_ms": 5.0,
        "strict_enabled": False,
        "ovk_version_pin": "1.2.1",
    }
    row = build_pilot_row("example/oss-pilot", existing=existing, artifacts_dir=tmp_path)
    for key in ("prs_evaluated", "prs_blocked", "false_positives", "false_positive_rate", "median_check_latency_ms"):
        assert row[key] == new_artifact_metrics.get(key), key


def test_new_report_cohort_without_error_labels_invalidates_old_rates(
    tmp_path: Path,
) -> None:
    """Fresh selected counts must not inherit unrelated older adjudications."""
    selected = tmp_path / "reviewer-report.json"
    selected.write_text(
        json.dumps({"repository": "example/oss-pilot", "prs_evaluated": 6}),
        encoding="utf-8",
    )
    existing = {
        "repository": "example/oss-pilot",
        "status": "advisory",
        "check_types": ["ci_secrets"],
        "prs_evaluated": 4,
        "false_positives": 0,
        "false_positive_rate": 0.0,
        "strict_enabled": False,
        "ovk_version_pin": "1.2.1",
    }
    row = build_pilot_row("example/oss-pilot", existing=existing, report_path=selected)
    assert row["prs_evaluated"] == 6
    assert row["false_positives"] is None
    assert row["false_positive_rate"] is None


def test_new_selected_report_counts_clear_stale_latency_and_block_count(
    tmp_path: Path,
) -> None:
    selected = tmp_path / "new-cohort.json"
    selected.write_text(
        json.dumps({"repository": "example/oss-pilot", "prs_evaluated": 6}),
        encoding="utf-8",
    )
    existing = {
        "repository": "example/oss-pilot",
        "status": "advisory",
        "check_types": ["ci_secrets"],
        "prs_evaluated": 4,
        "prs_blocked": 2,
        "false_positives": 0,
        "false_positive_rate": 0.0,
        "median_check_latency_ms": 71.0,
        "strict_enabled": False,
        "ovk_version_pin": "1.2.1",
    }
    row = build_pilot_row("example/oss-pilot", existing=existing, report_path=selected)
    assert row["prs_evaluated"] == 6
    for metric in ("prs_blocked", "false_positives", "false_positive_rate", "median_check_latency_ms"):
        assert row[metric] is None


@pytest.mark.parametrize(
    ("selected_fields", "stale_field"),
    [
        ({"false_positives": 2}, "false_positive_rate"),
        ({"false_positive_rate": 0.2}, "false_positives"),
    ],
)
def test_partial_adjudication_does_not_retain_old_counterpart(
    tmp_path: Path, selected_fields: dict, stale_field: str,
) -> None:
    selected = tmp_path / "partial-review.json"
    selected.write_text(
        json.dumps({"repository": "example/oss-pilot", **selected_fields}),
        encoding="utf-8",
    )
    existing = {
        "repository": "example/oss-pilot",
        "status": "advisory",
        "check_types": ["ci_secrets"],
        "false_positives": 0,
        "false_positive_rate": 0.0,
        "strict_enabled": False,
        "ovk_version_pin": "1.2.1",
    }
    row = build_pilot_row("example/oss-pilot", existing=existing, report_path=selected)
    assert row[stale_field] is None
    for key, value in selected_fields.items():
        assert row[key] == value


def test_external_report_supplies_separate_reviewed_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicit reviewer-provided labels are retained, not inferred."""
    monkeypatch.setattr(
        "scripts.ingest_external_pilot_metrics._metrics_from_artifacts",
        lambda _: {"prs_evaluated": 4, "prs_blocked": 2},
    )
    report = tmp_path / "reviewed.json"
    report.write_text(
        json.dumps({
            "repository": "example/oss-pilot",
            "false_positives": 1,
            "false_positive_rate": 0.25,
            "notes": "Separately adjudicated by an external reviewer.",
        }),
        encoding="utf-8",
    )
    row = build_pilot_row(
        "example/oss-pilot", artifacts_dir=tmp_path, report_path=report
    )
    assert row["prs_evaluated"] == 4
    assert row["false_positives"] == 1
    assert row["false_positive_rate"] == 0.25


def test_embedded_artifact_self_report_cannot_set_error_or_strictness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Embedded reports are not an approved independent source of labels."""
    pilot = tmp_path / "pilot-report.json"
    pilot.write_text(
        json.dumps({"results": [{"passed": True, "merge_recommendation": "allow", "elapsed_ms": 12}]}),
        encoding="utf-8",
    )
    embedded = tmp_path / "external_pilot_report.json"
    embedded.write_text(
        json.dumps({
            "repository": "attacker/redirected",
            "prs_evaluated": 1000,
            "false_positives": 0,
            "false_positive_rate": 0.0,
            "strict_enabled": True,
            "notes": "unreviewed data in artifact bundle",
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "scripts.collect_pilot_metrics.discover_artifacts_dir",
        lambda _: (pilot, None, None),
    )
    row = build_pilot_row("example/oss-pilot", artifacts_dir=tmp_path)
    assert row["repository"] == "example/oss-pilot"
    assert row["prs_evaluated"] == 1
    assert row["false_positives"] is None
    assert row["false_positive_rate"] is None
    assert row["strict_enabled"] is False
    assert row["status"] == "advisory"


def test_explicit_report_must_not_redirect_registry_identity(tmp_path: Path) -> None:
    """Selected reporter may provide observations, not reassign the subject."""
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({
            "repository": "other/tenant",
            "false_positives": 0,
            "false_positive_rate": 0.0,
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="repository mismatch"):
        build_pilot_row("example/oss-pilot", report_path=report)


def test_explicit_report_with_matching_repository_still_supported(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({
            "repository": "example/oss-pilot",
            "false_positives": 1,
            "false_positive_rate": 0.25,
        }),
        encoding="utf-8",
    )
    row = build_pilot_row("example/oss-pilot", report_path=report)
    assert row["repository"] == "example/oss-pilot"
    assert row["false_positives"] == 1
    assert row["false_positive_rate"] == 0.25
