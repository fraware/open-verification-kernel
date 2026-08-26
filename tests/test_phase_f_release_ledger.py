"""WP-17 release ledger offline verifier (no real publish)."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.release_ledger import (
    REQUIRED_WORKFLOWS,
    build_release_ledger,
    verify_release_ledger,
    write_release_ledger,
)

REPO = Path(__file__).resolve().parents[1]
SHA = "58bee916492f7aa4f550ea6ced9f7271f065656e"


def _complete_runs() -> list[dict]:
    return [
        {
            "workflowName": name,
            "databaseId": index + 1,
            "headSha": SHA,
            "conclusion": "success",
            "url": f"https://example.test/{index}",
        }
        for index, name in enumerate(REQUIRED_WORKFLOWS)
    ]


def test_ledger_builder_starts_unauthorized() -> None:
    ledger = build_release_ledger(
        REPO,
        candidate_sha=SHA,
        workflow_evidence={"ok": True, "runs": _complete_runs()},
    )
    assert ledger["schema_version"] == "ovk.release_ledger.v1"
    assert ledger["release_state"]["authorized"] is False
    assert ledger["release_state"]["verified_source_sha"] is None
    assert ledger["release_state"]["published"] is False
    assert ledger["toolchain"]["lock_sha256"]


def test_offline_verifier_authorizes_complete_ledger() -> None:
    ledger = build_release_ledger(
        REPO,
        candidate_sha=SHA,
        workflow_evidence={"ok": True, "runs": _complete_runs()},
    )
    ok, failures, authorized = verify_release_ledger(ledger, repo_root=REPO)
    assert failures == []
    assert ok is True
    assert authorized["release_state"]["authorized"] is True
    assert authorized["release_state"]["verified_source_sha"] == SHA
    assert authorized["release_state"]["published"] is False
    assert authorized["release_state"]["tag"] is None


def test_offline_verifier_fail_closed_on_missing_workflow() -> None:
    runs = _complete_runs()[:-1]
    ledger = build_release_ledger(
        REPO,
        candidate_sha=SHA,
        workflow_evidence={"ok": True, "runs": runs},
    )
    ok, failures, authorized = verify_release_ledger(ledger, repo_root=REPO)
    assert ok is False
    assert any("missing_required_workflow" in item for item in failures)
    assert authorized["release_state"]["verified_source_sha"] is None


def test_offline_verifier_rejects_published_claim() -> None:
    ledger = build_release_ledger(
        REPO,
        candidate_sha=SHA,
        workflow_evidence={"ok": True, "runs": _complete_runs()},
    )
    ledger["release_state"]["published"] = True
    ok, failures, _ = verify_release_ledger(ledger, repo_root=REPO)
    assert ok is False
    assert any("published" in item for item in failures)


def test_write_release_ledger(tmp_path: Path) -> None:
    ledger = build_release_ledger(
        REPO,
        candidate_sha=SHA,
        workflow_evidence={"ok": True, "runs": _complete_runs()},
    )
    path = tmp_path / "input-ledger.json"
    path.write_text(json.dumps(ledger), encoding="utf-8")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    ok, _, authorized = verify_release_ledger(loaded, repo_root=REPO)
    assert ok
    out = write_release_ledger(tmp_path, authorized)
    assert out == tmp_path / ".verification" / "release-ledger.json"
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk["release_state"]["verified_source_sha"] == SHA
    assert not (REPO / ".verification" / "release-ledger.json").is_file() or REPO != tmp_path
