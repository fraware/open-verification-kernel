"""Release workflow event and exact-head checkout provenance tests."""

from __future__ import annotations

from pathlib import Path

from scripts.verify_release_ledger_github import validate_release_workflow_run

REPO = Path(__file__).resolve().parents[1]


def test_release_authorizer_accepts_only_workflow_dispatch_runs() -> None:
    assert validate_release_workflow_run({"event": "workflow_dispatch"}) == []
    assert validate_release_workflow_run({"event": "pull_request"}) == [
        "release workflow event must be workflow_dispatch, got pull_request"
    ]
    assert validate_release_workflow_run({}) == [
        "release workflow event must be workflow_dispatch, got <empty>"
    ]


def test_required_generic_validation_workflows_checkout_recorded_head() -> None:
    required = (
        ".github/workflows/ci.yml",
        ".github/workflows/repro-baseline.yml",
        ".github/workflows/native-backends-tier1.yml",
        ".github/workflows/native-backends-tier1b.yml",
    )
    exact_ref = "ref: ${{ github.event.pull_request.head.sha || github.sha }}"
    for relative in required:
        text = (REPO / relative).read_text(encoding="utf-8")
        checkout_count = text.count("uses: actions/checkout@")
        assert checkout_count >= 1, relative
        assert text.count(exact_ref) == checkout_count, relative


def test_release_collector_supports_dispatch_only_filter() -> None:
    text = (REPO / "scripts" / "collect_workflow_evidence.py").read_text(encoding="utf-8")
    assert '"--required-event"' in text
    assert 'command.extend(["--event", required_event])' in text
