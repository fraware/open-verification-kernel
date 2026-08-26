"""Workflow-evidence collector contract tests."""

from __future__ import annotations

import json

import scripts.collect_workflow_evidence as collector
from ovk.core.release_ledger import REQUIRED_WORKFLOWS

SHA = "a" * 40


def _runs() -> list[dict]:
    return [
        {
            "databaseId": index + 1,
            "workflowName": name,
            "status": "completed",
            "conclusion": "success",
            "url": f"https://github.com/fraware/open-verification-kernel/actions/runs/{index + 1}",
            "headSha": SHA,
            "createdAt": f"2026-08-26T10:{index:02d}:00Z",
        }
        for index, name in enumerate(REQUIRED_WORKFLOWS)
    ]


def test_collector_uses_central_release_workflow_contract(monkeypatch) -> None:
    runs = _runs()

    def fake_run_gh(args: list[str]) -> tuple[int, str, str]:
        fields = next(item for item in args if item.startswith("databaseId,"))
        assert "path" not in fields
        return 0, json.dumps(runs), ""

    monkeypatch.setattr(collector, "_run_gh", fake_run_gh)
    payload = collector.collect_for_sha(
        repo="fraware/open-verification-kernel",
        sha=SHA,
    )
    assert payload["ok"] is True
    assert payload["collection_ok"] is True
    assert payload["complete_required_set"] is True
    assert payload["required_workflow_names"] == list(REQUIRED_WORKFLOWS)
    assert payload["missing_workflow_names"] == []
    assert payload["verified_source_sha"] is None
    assert "Bench Badge" not in payload["required_workflow_names"]


def test_collector_fails_closed_when_required_workflow_missing(monkeypatch) -> None:
    runs = _runs()[:-1]

    def fake_run_gh(args: list[str]) -> tuple[int, str, str]:
        return 0, json.dumps(runs), ""

    monkeypatch.setattr(collector, "_run_gh", fake_run_gh)
    payload = collector.collect_for_sha(
        repo="fraware/open-verification-kernel",
        sha=SHA,
    )
    assert payload["collection_ok"] is True
    assert payload["complete_required_set"] is False
    assert payload["ok"] is False
    assert payload["blocker"] == "required_workflows_missing"
    assert payload["missing_workflow_names"] == [REQUIRED_WORKFLOWS[-1]]
    assert payload["verified_source_sha"] is None


def test_collector_transport_failure_cannot_claim_complete(monkeypatch) -> None:
    monkeypatch.setattr(
        collector,
        "_run_gh",
        lambda args: (1, "", "authentication failed"),
    )
    payload = collector.collect_for_sha(
        repo="fraware/open-verification-kernel",
        sha=SHA,
    )
    assert payload["ok"] is False
    assert payload["collection_ok"] is False
    assert payload["complete_required_set"] is False
    assert payload["verified_source_sha"] is None
