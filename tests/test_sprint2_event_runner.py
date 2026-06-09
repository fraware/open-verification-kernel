from pathlib import Path

from ovk.core.sprint1_runner import build_metadata_from_inputs, run_sprint1_self_protection


def test_runner_uses_github_event_defaults_for_subject_metadata() -> None:
    metadata = build_metadata_from_inputs(
        github_event_path=Path("examples/github_events/pull_request_bot.json"),
        metadata_path=Path("examples/no_agent_self_approval/metadata_missing_required_checks.json"),
        changed_files_path=Path("examples/no_agent_self_approval/changed_files_workflow.txt"),
        check_metadata_path=Path("examples/no_agent_self_approval/check_metadata_github_shape_removed.json"),
    )
    result = run_sprint1_self_protection(metadata=metadata)
    assert result.bundle.subject["repo"] == "fraware/open-verification-kernel"
    assert result.bundle.subject["head_sha"] == "head-demo-sha"
    assert result.bundle.subject["base_sha"] == "base-demo-sha"
    assert result.recommendation == "block"


def test_metadata_file_overrides_github_actor_defaults_when_present() -> None:
    metadata = build_metadata_from_inputs(
        github_event_path=Path("examples/github_events/pull_request_bot.json"),
        metadata_path=Path("examples/no_agent_self_approval/metadata_missing_required_checks.json"),
        changed_files_path=Path("examples/no_agent_self_approval/changed_files_workflow.txt"),
    )
    assert metadata["actor_type"] == "ai_agent"
    assert metadata["agent_id"] == "codex"
