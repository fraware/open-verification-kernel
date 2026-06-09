from pathlib import Path

from ovk.core.check_metadata import load_required_check_metadata
from ovk.core.github_event import load_github_event_metadata, metadata_to_self_protection_defaults
from ovk.core.sprint1_runner import build_metadata_from_inputs, run_sprint1_self_protection


def test_load_github_pull_request_event_metadata() -> None:
    metadata = load_github_event_metadata(Path("examples/github_events/pull_request_bot.json"))
    assert metadata.repository == "fraware/open-verification-kernel"
    assert metadata.head_sha == "head-demo-sha"
    assert metadata.base_sha == "base-demo-sha"
    assert metadata.pull_request_number == 7
    assert metadata.actor_login == "codex-bot"


def test_github_event_defaults_detect_bot_as_ai_agent() -> None:
    metadata = load_github_event_metadata(Path("examples/github_events/pull_request_bot.json"))
    defaults = metadata_to_self_protection_defaults(metadata)
    assert defaults["actor_type"] == "ai_agent"
    assert defaults["agent_id"] == "codex-bot"


def test_load_github_shaped_required_checks() -> None:
    checks = load_required_check_metadata(
        Path("examples/no_agent_self_approval/check_metadata_github_shape_removed.json")
    )
    assert checks["before_required_checks"] == ["unit-tests", "ovk-verify"]
    assert checks["after_required_checks"] == ["unit-tests"]


def test_github_shaped_metadata_drives_removed_gate_failure() -> None:
    metadata = build_metadata_from_inputs(
        metadata_path=Path("examples/no_agent_self_approval/metadata_missing_required_checks.json"),
        changed_files_path=Path("examples/no_agent_self_approval/changed_files_workflow.txt"),
        check_metadata_path=Path("examples/no_agent_self_approval/check_metadata_github_shape_removed.json"),
    )
    result = run_sprint1_self_protection(metadata=metadata, repo="example/repo", head_sha="abc")
    assert result.recommendation == "block"
    assert result.bundle.evidence[0].backend_claims[0].status.value == "fail"
