import json
from pathlib import Path

from ovk.adapters.opa import evaluate_self_protection
from ovk.core.self_protection_input import SelfProtectionMetadata, build_self_protection_input


def test_missing_required_check_metadata_returns_unknown() -> None:
    data = json.loads(
        Path("examples/no_agent_self_approval/input_missing_metadata.json").read_text(encoding="utf-8")
    )
    evidence = evaluate_self_protection(data, repo="example/repo", head_sha="abc")
    assert evidence.backend_claims[0].status.value == "unknown"
    assert evidence.decision["merge_recommendation"] == "require_human_review"
    assert evidence.counterexamples[0]["failure_mode"] == "missing_required_metadata"


def test_configuration_change_by_agent_still_fails_without_metadata() -> None:
    data = {
        "actor": {"type": "ai_agent", "id": "codex"},
        "changed_files": [".verification/config.yml"],
        "before": {},
        "after": {},
    }
    evidence = evaluate_self_protection(data, repo="example/repo", head_sha="abc")
    assert evidence.backend_claims[0].status.value == "fail"
    assert evidence.decision["merge_recommendation"] == "block"
    assert evidence.counterexamples[0]["failure_mode"] == "verification_config_changed_by_agent"


def test_structured_input_builder_preserves_optional_metadata() -> None:
    payload = build_self_protection_input(
        SelfProtectionMetadata(
            actor_type="ai_agent",
            agent_id="codex",
            changed_files=[".github/workflows/verify.yml"],
            before_required_checks=["unit-tests", "ovk-verify"],
            after_required_checks=["unit-tests"],
        )
    )
    assert payload["actor"]["type"] == "ai_agent"
    assert payload["before"]["required_checks"] == ["unit-tests", "ovk-verify"]
    assert payload["after"]["required_checks"] == ["unit-tests"]


def test_builder_missing_metadata_drives_unknown() -> None:
    payload = build_self_protection_input(
        SelfProtectionMetadata(
            actor_type="ai_agent",
            agent_id="codex",
            changed_files=[".github/workflows/verify.yml"],
        )
    )
    evidence = evaluate_self_protection(payload, repo="example/repo", head_sha="abc")
    assert evidence.backend_claims[0].status.value == "unknown"
