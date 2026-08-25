"""Fixture-driven Action hardening suite (OVK-PR6 / OVK-07).

Covers fork PRs, empty changes, renames, deleted policies, workflow mods,
malicious filenames, large diffs, missing permissions, repeated reruns,
concurrent runs, stale check results, and workflow_dispatch metadata.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from ovk.core.change_detection import detect_change_surfaces
from ovk.core.changed_files import load_changed_files
from ovk.core.check import run_check
from ovk.core.github_check import (
    StaleCheckRunError,
    build_check_run_payload,
    check_run_external_id,
    validate_check_run_head_sha,
)
from ovk.core.github_event import load_github_event_metadata
from ovk.core.models import EvidenceBundle
from scripts.emit_github_check import emit_or_update_check_run, main as emit_main
from scripts.pin_action_shas import check_paths, floating_uses_in_file, is_sha_pinned

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "action_hardening"
SCENARIOS_PATH = FIXTURE_ROOT / "scenarios.json"


def _load_scenarios() -> list[dict[str, Any]]:
    payload = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))
    scenarios = payload.get("scenarios", [])
    assert isinstance(scenarios, list) and scenarios
    return scenarios


def _scenario_map() -> dict[str, dict[str, Any]]:
    return {str(item["id"]): item for item in _load_scenarios()}


def _decision_state(bundle: EvidenceBundle) -> str:
    decision = bundle.decision or {}
    if decision.get("decision_state"):
        return str(decision["decision_state"])
    return str(decision.get("merge_recommendation", ""))


def _write_evidence(
    path: Path,
    *,
    head_sha: str = "abc123def456",
    repo: str = "owner/repo",
    recommendation: str = "block",
    decision_state: str | None = None,
) -> EvidenceBundle:
    state = decision_state or (
        "block"
        if recommendation == "block"
        else "allow"
        if recommendation == "allow"
        else "needs_review"
    )
    payload = {
        "schema_version": "ovk.bundle.v1",
        "bundle_id": "action-hardening",
        "subject": {"repo": repo, "head_sha": head_sha},
        "evidence": [],
        "open_obligations": [],
        "decision": {
            "decision_state": state,
            "merge_recommendation": recommendation,
            "reason": "action-hardening fixture",
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return EvidenceBundle.model_validate(payload)


def test_scenarios_manifest_covers_required_ids() -> None:
    required = {
        "fork_pr",
        "no_changed_files",
        "renamed_files",
        "deleted_policies",
        "workflow_modifications",
        "malicious_filenames",
        "large_diffs",
        "missing_permissions",
        "repeated_reruns",
        "concurrent_runs",
        "stale_check_results",
        "workflow_dispatch",
    }
    assert required <= set(_scenario_map())


def test_fork_pr_blocks_untrusted_secrets_and_skips_emit_without_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    scenario = _scenario_map()["fork_pr"]
    event_path = FIXTURE_ROOT / scenario["event"]
    diff_path = FIXTURE_ROOT / scenario["changed_files"]
    meta = load_github_event_metadata(event_path)
    assert meta.pull_request_number == 42
    assert meta.head_sha.startswith("forkhead")

    result = run_check(
        diff_text=diff_path.read_text(encoding="utf-8"),
        github_event_path=event_path,
        repo=meta.repository,
        head_sha=meta.head_sha,
        use_cache=False,
    )
    assert _decision_state(result.bundle) in scenario["expected_decision_states"]

    evidence = tmp_path / "ovk-evidence.json"
    _write_evidence(evidence, head_sha=meta.head_sha, repo=meta.repository, recommendation="block")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with patch(
        "sys.argv",
        [
            "emit_github_check.py",
            "--evidence",
            str(evidence),
            "--repo",
            meta.repository,
            "--head-sha",
            meta.head_sha,
        ],
    ):
        assert emit_main() == 0
    assert "missing GITHUB_TOKEN" in capsys.readouterr().out


def test_no_changed_files_does_not_crash() -> None:
    scenario = _scenario_map()["no_changed_files"]
    paths = load_changed_files(FIXTURE_ROOT / scenario["changed_files"])
    assert paths == []
    result = run_check(changed_files=paths, repo="owner/repo", head_sha="empty001", use_cache=False)
    assert _decision_state(result.bundle) in scenario["expected_decision_states"]


def test_renamed_files_detected() -> None:
    scenario = _scenario_map()["renamed_files"]
    diff_path = FIXTURE_ROOT / scenario["changed_files"]
    paths = load_changed_files(diff_path)
    for expected in scenario["expect_paths_include"]:
        assert expected in paths
    result = run_check(
        diff_text=diff_path.read_text(encoding="utf-8"),
        repo="owner/repo",
        head_sha="rename001",
        use_cache=False,
    )
    assert _decision_state(result.bundle) in scenario["expected_decision_states"]


def test_deleted_policies_surface() -> None:
    scenario = _scenario_map()["deleted_policies"]
    diff_path = FIXTURE_ROOT / scenario["changed_files"]
    paths = load_changed_files(diff_path)
    for expected in scenario["expect_paths_include"]:
        assert expected in paths
    surfaces = detect_change_surfaces(paths)
    domains = {surface.domain for surface in surfaces}
    for expected in scenario["expect_domains_include"]:
        assert expected in domains
    result = run_check(
        diff_text=diff_path.read_text(encoding="utf-8"),
        repo="owner/repo",
        head_sha="delete001",
        use_cache=False,
    )
    assert _decision_state(result.bundle) in scenario["expected_decision_states"]


def test_workflow_modifications_block() -> None:
    scenario = _scenario_map()["workflow_modifications"]
    diff_path = FIXTURE_ROOT / scenario["changed_files"]
    result = run_check(
        diff_text=diff_path.read_text(encoding="utf-8"),
        repo="owner/repo",
        head_sha="wfmod001",
        use_cache=False,
    )
    assert _decision_state(result.bundle) in scenario["expected_decision_states"]


def test_malicious_filenames_no_crash() -> None:
    scenario = _scenario_map()["malicious_filenames"]
    diff_path = FIXTURE_ROOT / scenario["changed_files"]
    paths = load_changed_files(diff_path)
    assert paths  # ingested something
    result = run_check(
        diff_text=diff_path.read_text(encoding="utf-8"),
        changed_files=paths,
        repo="owner/repo",
        head_sha="malicious001",
        use_cache=False,
    )
    assert _decision_state(result.bundle) in scenario["expected_decision_states"]


def test_large_diffs_complete_within_budget() -> None:
    scenario = _scenario_map()["large_diffs"]
    file_count = int(scenario["file_count"])
    lines = []
    for index in range(file_count):
        path = f"generated/file_{index:04d}.md"
        lines.extend(
            [
                f"diff --git a/{path} b/{path}",
                "new file mode 100644",
                "index 0000000..1111111",
                "--- /dev/null",
                f"+++ b/{path}",
                "@@ -0,0 +1 @@",
                f"+content {index}",
                "",
            ]
        )
    diff_text = "\n".join(lines)
    started = time.perf_counter()
    result = run_check(
        diff_text=diff_text,
        repo="owner/repo",
        head_sha="large001",
        use_cache=False,
    )
    elapsed = time.perf_counter() - started
    assert elapsed < float(scenario["max_seconds"])
    assert _decision_state(result.bundle) in scenario["expected_decision_states"]


def test_missing_permissions_emit_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scenario = _scenario_map()["missing_permissions"]
    evidence = tmp_path / "ovk-evidence.json"
    head_sha = "permsha000000000000000000000000000001"
    _write_evidence(evidence, head_sha=head_sha, recommendation="allow", decision_state="allow")
    monkeypatch.setenv("GITHUB_TOKEN", "no-checks-write")

    with patch(
        "sys.argv",
        [
            "emit_github_check.py",
            "--evidence",
            str(evidence),
            "--repo",
            "owner/repo",
            "--head-sha",
            head_sha,
        ],
    ):
        with patch("scripts.emit_github_check._request", return_value=(403, None)):
            assert emit_main() == int(scenario["expect_emit_exit"])


def test_repeated_reruns_idempotent_external_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _ = _scenario_map()["repeated_reruns"]
    evidence = tmp_path / "ovk-evidence.json"
    head_sha = "rerunsha00000000000000000000000000001"
    bundle = _write_evidence(evidence, head_sha=head_sha, recommendation="block")
    payload = build_check_run_payload(bundle, head_sha=head_sha)
    external_id = payload["external_id"]
    assert external_id == check_run_external_id(repo="owner/repo", head_sha=head_sha)

    state = {"created": False}
    calls: list[str] = []

    def fake_request(url: str, *, token: str, method: str = "GET", payload: dict | None = None):
        _ = token, payload, url
        if method == "GET":
            if state["created"]:
                return 200, {
                    "check_runs": [
                        {"id": 99, "external_id": external_id, "name": "Open Verification Kernel"}
                    ]
                }
            return 200, {"check_runs": []}
        if method == "POST":
            state["created"] = True
            calls.append("POST")
            return 201, {"id": 99}
        if method == "PATCH":
            calls.append("PATCH")
            return 200, {"id": 99}
        return 0, None

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    with patch("scripts.emit_github_check._request", side_effect=fake_request):
        assert emit_or_update_check_run("https://api.github.com", "owner/repo", "token", payload)
        assert emit_or_update_check_run("https://api.github.com", "owner/repo", "token", payload)
    assert calls == ["POST", "PATCH"]


def test_concurrent_runs_share_external_id() -> None:
    _ = _scenario_map()["concurrent_runs"]
    head_sha = "concurrentsha000000000000000000000001"
    bundle = EvidenceBundle.model_validate(
        {
            "schema_version": "ovk.bundle.v1",
            "bundle_id": "concurrent",
            "subject": {"repo": "owner/repo", "head_sha": head_sha},
            "evidence": [],
            "open_obligations": [],
            "decision": {"decision_state": "allow", "merge_recommendation": "allow"},
        }
    )
    payloads = [build_check_run_payload(bundle, head_sha=head_sha) for _ in range(4)]
    external_ids = {item["external_id"] for item in payloads}
    assert len(external_ids) == 1

    lock = threading.Lock()
    created_id: dict[str, int | None] = {"id": None}
    methods: list[str] = []

    def fake_request(url: str, *, token: str, method: str = "GET", payload: dict | None = None):
        _ = token, payload, url
        with lock:
            if method == "GET":
                if created_id["id"] is None:
                    return 200, {"check_runs": []}
                return 200, {
                    "check_runs": [
                        {
                            "id": created_id["id"],
                            "external_id": payloads[0]["external_id"],
                            "name": "Open Verification Kernel",
                        }
                    ]
                }
            methods.append(method)
            if method == "POST":
                created_id["id"] = 7
                return 201, {"id": 7}
            return 200, {"id": 7}

    with patch("scripts.emit_github_check._request", side_effect=fake_request):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(
                pool.map(
                    lambda _: emit_or_update_check_run(
                        "https://api.github.com", "owner/repo", "token", payloads[0]
                    ),
                    range(4),
                )
            )
    assert all(results)
    assert "POST" in methods
    assert methods.count("POST") >= 1


def test_stale_check_results_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scenario = _scenario_map()["stale_check_results"]
    evidence = tmp_path / "ovk-evidence.json"
    _write_evidence(evidence, head_sha="evidence-sha-aaaa", recommendation="allow", decision_state="allow")
    monkeypatch.setenv("GITHUB_TOKEN", "token")

    with patch(
        "sys.argv",
        [
            "emit_github_check.py",
            "--evidence",
            str(evidence),
            "--repo",
            "owner/repo",
            "--head-sha",
            "stale-target-bbbb",
        ],
    ):
        assert emit_main() == int(scenario["expect_stale_exit"])

    bundle = EvidenceBundle.model_validate(json.loads(evidence.read_text(encoding="utf-8")))
    with pytest.raises(StaleCheckRunError, match="mismatch"):
        validate_check_run_head_sha(bundle, "stale-target-bbbb")
    with pytest.raises(StaleCheckRunError):
        build_check_run_payload(bundle, head_sha="stale-target-bbbb")


def test_workflow_dispatch_event_metadata() -> None:
    scenario = _scenario_map()["workflow_dispatch"]
    meta = load_github_event_metadata(FIXTURE_ROOT / scenario["event"])
    assert meta.pull_request_number == scenario["expect_pr_number"]
    assert meta.head_sha.startswith("dispatchsha")
    assert meta.repository == "acme/consumer-app"


def test_pin_action_shas_release_paths_clean() -> None:
    root = Path(__file__).resolve().parents[1]
    failures = check_paths([root / "action.yml", root / ".github" / "workflows" / "publish.yml"])
    assert failures == []


def test_pin_action_shas_detects_floating_tag(tmp_path: Path) -> None:
    workflow = tmp_path / "publish.yml"
    workflow.write_text(
        "jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    floating = floating_uses_in_file(workflow)
    assert floating == ["actions/checkout@v4"]
    assert not is_sha_pinned("actions/checkout@v4")
    assert is_sha_pinned("actions/checkout@" + ("a" * 40))


def test_build_check_run_payload_includes_external_id() -> None:
    bundle = EvidenceBundle.model_validate(
        {
            "schema_version": "ovk.bundle.v1",
            "bundle_id": "x",
            "subject": {"repo": "o/r", "head_sha": "deadbeef"},
            "evidence": [],
            "open_obligations": [],
            "decision": {"decision_state": "block", "merge_recommendation": "block"},
        }
    )
    payload = build_check_run_payload(bundle, head_sha="deadbeef")
    assert payload["external_id"] == "ovk:o/r:deadbeef"
    assert payload["conclusion"] == "failure"
