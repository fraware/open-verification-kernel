"""Cross-PR contract for a non-blocking, attributable pilot entry point.

This guards copyable workflow safety and reporting provenance. It is not an
independent assessment of the pilot's scientific accuracy or adopter identity.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_ACTION = "fraware/open-verification-kernel@a27d5720f4350c00bca34f71d991c31f5a2f38c7"


def test_fork_adopter_example_has_no_publication_or_write_token() -> None:
    workflow_path = ROOT / "examples/github_workflows/pilot_fork_adopter.yml"
    raw = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(raw)
    permissions = workflow["permissions"]
    assert permissions["contents"] == "read"
    assert "checks" not in permissions
    assert permissions.get("pull-requests", "read") == "read"

    steps = workflow["jobs"]["ovk-ci-secrets-pilot"]["steps"]
    checkouts = [s for s in steps if s.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 1
    assert checkouts[0]["with"]["persist-credentials"] is False
    assert re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkouts[0]["uses"])

    ovk_steps = [s for s in steps if s.get("uses", "").startswith("fraware/open-verification-kernel@")]
    assert len(ovk_steps) == 2
    for step in ovk_steps:
        assert step["uses"] == HISTORICAL_ACTION
        assert step["with"]["mode"] == "advisory"
        assert step["with"]["emit-check"] == "false"
        assert step["with"]["post-comment"] == "false"

    assert ovk_steps[0]["with"]["changed-files"] == "ovk-pr.diff"
    assert "unbound source input" in (ROOT / "docs/EXTERNAL_PILOT_PLAYBOOK.md").read_text(encoding="utf-8")
    assert "external_pilot_report.json" not in raw


def test_copyable_readme_example_is_least_privilege() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## GitHub Actions", 1)[1].split("## Built for agents", 1)[0]
    assert "contents: read" in section
    assert "checks: write" not in section
    assert "pull-requests: write" not in section
    assert HISTORICAL_ACTION in section
    assert 'emit-check: "false"' in section
    assert 'post-comment: "false"' in section
    assert "falls back to its checkout" in section


def test_pilot_template_never_invents_measured_zeroes() -> None:
    report = json.loads(
        (ROOT / "docs/templates/external_pilot_report.template.json").read_text(encoding="utf-8")
    )
    for field in (
        "advisory_start", "advisory_end", "prs_evaluated", "prs_blocked",
        "false_positives", "false_positive_rate", "median_check_latency_ms",
    ):
        assert report[field] is None, field
    assert report["strict_enabled"] is False


def test_release_docs_and_strict_example_are_explicitly_qualified() -> None:
    status = (ROOT / "docs/CURRENT_RELEASE_STATUS.md").read_text(encoding="utf-8")
    integration = (ROOT / "docs/INTEGRATION.md").read_text(encoding="utf-8")
    assert "protected=false" in status
    assert "verification.verified=false" in status
    assert "immutable=false" in status
    assert "v1.3.0-rc.1" in status
    assert "shared HMAC secret" in integration
    assert "No currently approved copyable workflow" in integration


def test_published_fixture_error_rates_are_unadjudicated_unknown() -> None:
    """Corrected archived aggregates must not advertise 0% without ground truth."""
    registry = json.loads(
        (ROOT / "docs/benchmarks/external-pilots-registry.json").read_text(encoding="utf-8")
    )
    summary = json.loads(
        (ROOT / "docs/benchmarks/adoption-summary.json").read_text(encoding="utf-8")
    )
    assert summary["pilot_dogfood"]["false_positive_rate"] is None

    for data in (registry, summary):
        maintained = [
            row for row in data["external_pilots"]
            if "Maintained consumer" in row.get("notes", "")
            or "In-repo maintained" in row.get("notes", "")
        ]
        assert len(maintained) == 3
        for row in maintained:
            assert row["false_positives"] is None
            assert row["false_positive_rate"] is None
            assert "not independently" in row["notes"] or "no independent" in row["notes"]

    study = (ROOT / "docs/PILOT_CASE_STUDIES.md").read_text(encoding="utf-8")
    assert "0.0 (fixtures)" not in study
    assert "Target: under 5%" not in study
    assert "reported as unknown" in study
