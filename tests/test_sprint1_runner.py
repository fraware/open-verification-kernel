import json
from pathlib import Path

from ovk.core.changed_files import load_changed_files
from ovk.core.sprint1_runner import (
    build_metadata_from_inputs,
    run_sprint1_self_protection,
    write_sprint1_outputs,
)


def test_load_changed_files_from_newline_fixture() -> None:
    files = load_changed_files(Path("examples/no_agent_self_approval/changed_files_workflow.txt"))
    assert files == [".github/workflows/verify.yml"]


def test_build_metadata_from_separate_inputs() -> None:
    metadata = build_metadata_from_inputs(
        metadata_path=Path("examples/no_agent_self_approval/metadata_missing_required_checks.json"),
        changed_files_path=Path("examples/no_agent_self_approval/changed_files_workflow.txt"),
        check_metadata_path=Path("examples/no_agent_self_approval/check_metadata_gate_removed.json"),
    )
    assert metadata["changed_files"] == [".github/workflows/verify.yml"]
    assert metadata["before_required_checks"] == ["unit-tests", "ovk-verify"]
    assert metadata["after_required_checks"] == ["unit-tests"]


def test_sprint1_runner_removed_gate_blocks() -> None:
    metadata = build_metadata_from_inputs(
        metadata_path=Path("examples/no_agent_self_approval/metadata_missing_required_checks.json"),
        changed_files_path=Path("examples/no_agent_self_approval/changed_files_workflow.txt"),
        check_metadata_path=Path("examples/no_agent_self_approval/check_metadata_gate_removed.json"),
    )
    result = run_sprint1_self_protection(metadata=metadata, repo="example/repo", head_sha="abc")
    assert result.recommendation == "block"
    assert result.bundle.evidence[0].backend_claims[0].status.value == "fail"
    assert "Open Verification Kernel" in result.markdown
    assert result.attestation["predicateType"] == "https://openverification.dev/predicate/verification/v1"


def test_sprint1_runner_missing_metadata_requires_review() -> None:
    metadata = build_metadata_from_inputs(
        metadata_path=Path("examples/no_agent_self_approval/metadata_missing_required_checks.json"),
        changed_files_path=Path("examples/no_agent_self_approval/changed_files_workflow.txt"),
    )
    result = run_sprint1_self_protection(metadata=metadata, repo="example/repo", head_sha="abc")
    assert result.recommendation == "require_human_review"
    assert result.bundle.evidence[0].backend_claims[0].status.value == "unknown"


def test_sprint1_runner_accepts_backend_strategy_argument() -> None:
    metadata = build_metadata_from_inputs(
        metadata_path=Path("examples/no_agent_self_approval/metadata_missing_required_checks.json"),
        changed_files_path=Path("examples/no_agent_self_approval/changed_files_workflow.txt"),
        check_metadata_path=Path("examples/no_agent_self_approval/check_metadata_gate_removed.json"),
    )
    result = run_sprint1_self_protection(
        metadata=metadata,
        repo="example/repo",
        head_sha="abc",
        backend_strategy="deterministic",
    )
    assert result.recommendation == "block"


def test_sprint1_outputs_are_written(tmp_path: Path) -> None:
    metadata = json.loads(
        Path("examples/no_agent_self_approval/metadata_gate_removed.json").read_text(encoding="utf-8")
    )
    result = run_sprint1_self_protection(metadata=metadata, repo="example/repo", head_sha="abc")
    evidence_output = tmp_path / "evidence.json"
    markdown_output = tmp_path / "comment.md"
    attestation_output = tmp_path / "attestation.json"
    manifest_output = tmp_path / "manifest.json"
    quality_output = tmp_path / "quality.json"
    write_sprint1_outputs(
        result,
        evidence_output=evidence_output,
        markdown_output=markdown_output,
        attestation_output=attestation_output,
        manifest_output=manifest_output,
        quality_output=quality_output,
    )
    assert evidence_output.exists()
    assert markdown_output.exists()
    assert attestation_output.exists()
    assert manifest_output.exists()
    assert quality_output.exists()
    payload = json.loads(quality_output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "ovk.evidence_quality.v1"
    assert payload["passed"] is True
