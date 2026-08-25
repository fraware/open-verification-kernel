"""Phase A WP-01 acceptance tests for protected metadata provenance."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.core.adapter_runtime import execute_obligations
from ovk.core.check_metadata import load_required_check_metadata, normalize_required_check_metadata
from ovk.core.lane_compiler import compile_lane_inputs_from_plan
from ovk.core.metadata_provenance import (
    ProtectedMetadataArtifact,
    ProtectedSubject,
    expected_artifact_payload_digest,
    expected_branch_metadata_digest,
    merge_loaded_protected_metadata,
    sign_acquisition_record,
    sign_protected_artifact,
    trusted_protected_environment_names,
)
from ovk.core.self_protection_compiler import resolve_metadata_trusted

KEY = "test-metadata-verification-key"


def _preserved_payload() -> dict:
    return {
        "before": {"required_checks": ["unit-tests", "ovk-verify"]},
        "after": {"required_checks": ["unit-tests", "ovk-verify"]},
    }


def _signed_artifact(*, kind: str = "branch_protection", payload: dict | None = None) -> ProtectedMetadataArtifact:
    payload = payload or _preserved_payload()
    artifact = ProtectedMetadataArtifact(
        kind=kind,  # type: ignore[arg-type]
        subject=ProtectedSubject(repository="r", branch="main", base_sha="b", head_sha="h"),
        payload=payload,
        collector_id="ovk.collect_branch_metadata",
        collector_version="1.0.0",
        acquisition_method="hmac_local",
        collected_at="2026-08-24T00:00:00Z",
        payload_digest=expected_artifact_payload_digest(payload, kind=kind),
        source_endpoint="https://api.github.com/repos/r/branches/main/protection",
        extensions={"provenance_kind": "protected_base_workflow"},
    )
    return sign_protected_artifact(artifact, hmac_key=KEY)


def _data_from_artifact(artifact: ProtectedMetadataArtifact) -> dict:
    dumped = artifact.model_dump(mode="json")
    data = {
        **artifact.payload,
        "_ovk_protected_artifact": dumped,
        "_ovk_acquisition": artifact.to_acquisition_record().model_dump(mode="json"),
    }
    return data


def test_valid_subject_bound_artifact_can_allow(monkeypatch) -> None:
    monkeypatch.setenv("OVK_METADATA_VERIFY_KEY", KEY)
    fixture = json.loads(Path("examples/no_agent_self_approval/input_gate_preserved.json").read_text(encoding="utf-8"))
    artifact = _signed_artifact(payload={"before": fixture["before"], "after": fixture["after"]})
    data = {**fixture, **_data_from_artifact(artifact)}
    assert resolve_metadata_trusted({}, data=data, repo="r", head_sha="h", base_sha="b") is True
    evidence = execute_obligations(
        [{"lane": "self_protection", "input": data, "intent_id": "agent-cannot-disable-own-ci-gate"}],
        {},
        repo="r",
        head_sha="h",
        base_sha="b",
        use_cache=False,
        policy={
            "routing": {
                "enforced_lanes": ["self_protection"],
                "prefer_deterministic": True,
                "allow_fallback": False,
            },
        },
    )[0]
    assert evidence.decision.get("merge_recommendation") == "allow"


def test_payload_signature_subject_kind_and_collector_tamper_fail_closed() -> None:
    artifact = _signed_artifact()
    data = _data_from_artifact(artifact)
    data["after"]["required_checks"] = []
    assert resolve_metadata_trusted({}, data=data, repo="r", head_sha="h", base_sha="b", verification_key=KEY) is False

    data = _data_from_artifact(_signed_artifact())
    data["_ovk_acquisition"]["signature"]["digest"] = "0" * 64
    data["_ovk_protected_artifact"]["signature"]["digest"] = "0" * 64
    assert resolve_metadata_trusted({}, data=data, repo="r", head_sha="h", base_sha="b", verification_key=KEY) is False

    data = _data_from_artifact(_signed_artifact())
    assert resolve_metadata_trusted({}, data=data, repo="other", head_sha="h", base_sha="b", verification_key=KEY) is False

    data = _data_from_artifact(_signed_artifact())
    data["_ovk_acquisition"]["collector_id"] = "forged-collector"
    data["_ovk_protected_artifact"]["collector_id"] = "forged-collector"
    assert resolve_metadata_trusted({}, data=data, repo="r", head_sha="h", base_sha="b", verification_key=KEY) is False

    env_artifact = _signed_artifact(
        kind="protected_environment",
        payload={"protected_environments": ["pypi"]},
    )
    env_data = _data_from_artifact(env_artifact)
    env_data["_ovk_protected_artifact"]["kind"] = "branch_protection"
    assert (
        resolve_metadata_trusted({}, data=env_data, repo="r", head_sha="h", base_sha="b", verification_key=KEY) is False
    )


def test_caller_forged_acquisition_cannot_become_authoritative(tmp_path: Path) -> None:
    loaded_artifact = _signed_artifact()
    loaded_path = tmp_path / "loaded.json"
    loaded_path.write_text(json.dumps(loaded_artifact.model_dump(mode="json")), encoding="utf-8")
    forged = {
        "schema_version": "ovk.metadata_acquisition.v1",
        "collector_id": "attacker",
        "collector_version": "9.9.9",
        "source_type": "branch_protection",
        "repository": "r",
        "branch": "main",
        "base_sha": "b",
        "head_sha": "h",
        "collected_at": "2026-08-24T00:00:00Z",
        "payload_digest": expected_branch_metadata_digest(_preserved_payload()),
        "authentication_method": "protected_hmac_key",
        "provenance_kind": "protected_base_workflow",
    }
    forged = sign_acquisition_record(forged, key=KEY).model_dump(mode="json")
    caller = {"_ovk_acquisition": forged, "actor_type": "ai_agent", "changed_files": [".github/workflows/ci.yml"]}
    jobs = compile_lane_inputs_from_plan(
        {"candidate_intents": ["agent-cannot-disable-own-ci-gate"], "changed_files": [".github/workflows/ci.yml"]},
        metadata=caller,
        check_metadata_path=loaded_path,
    )
    data = jobs[0]["data"]
    acquisition = data.get("_ovk_acquisition") or {}
    assert acquisition.get("collector_id") != "attacker"
    assert resolve_metadata_trusted({}, data=data, repo="r", head_sha="h", base_sha="b", verification_key=KEY) is False

    empty_loaded = tmp_path / "empty.json"
    empty_loaded.write_text("{}", encoding="utf-8")
    forged_only = compile_lane_inputs_from_plan(
        {"candidate_intents": ["agent-cannot-disable-own-ci-gate"], "changed_files": []},
        metadata={"_ovk_acquisition": forged},
        check_metadata_path=empty_loaded,
    )[0]["data"]
    assert "_ovk_provenance_conflicts" in forged_only
    assert resolve_metadata_trusted(
        {}, data=forged_only, repo="r", head_sha="h", base_sha="b", verification_key=KEY
    ) is False


def test_collector_unavailable_never_clean_allow() -> None:
    data = {
        "actor": {"type": "ai_agent", "id": "bot"},
        "changed_files": [".github/workflows/ci.yml"],
        "before": {"required_checks": ["ovk-verify"]},
        "after": {"required_checks": ["ovk-verify"]},
    }
    evidence = execute_obligations(
        [{"lane": "self_protection", "input": data, "intent_id": "agent-cannot-disable-own-ci-gate"}],
        {},
        repo="r",
        head_sha="h",
        base_sha="b",
        use_cache=False,
        policy={
            "routing": {
                "enforced_lanes": ["self_protection"],
                "prefer_deterministic": True,
                "allow_fallback": False,
            },
        },
    )[0]
    assert evidence.decision.get("merge_recommendation") != "allow"


def test_dangerous_findings_still_block_when_trust_is_missing() -> None:
    data = json.loads(Path("examples/no_agent_self_approval/input_gate_removed.json").read_text(encoding="utf-8"))
    evidence = execute_obligations(
        [{"lane": "self_protection", "input": data, "intent_id": "agent-cannot-disable-own-ci-gate"}],
        {},
        repo="example/repo",
        head_sha="abc",
        base_sha="def",
        use_cache=False,
        policy={
            "routing": {
                "enforced_lanes": ["self_protection"],
                "prefer_deterministic": True,
                "allow_fallback": False,
            },
        },
    )[0]
    assert evidence.decision.get("merge_recommendation") == "block"


def test_loader_preserves_acquisition_and_does_not_duplicate_head_state(tmp_path: Path) -> None:
    artifact = _signed_artifact(
        payload={"before": {}, "after": {"required_checks": ["ovk-verify"]}},
    )
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(artifact.model_dump(mode="json")), encoding="utf-8")
    loaded = load_required_check_metadata(path)
    assert loaded["after_required_checks"] == ["ovk-verify"]
    assert loaded["before_required_checks"] is None or loaded["before_required_checks"] == []
    assert loaded["_ovk_acquisition"]["collector_id"] == "ovk.collect_branch_metadata"
    assert "_ovk_protected_artifact" in loaded


def test_merge_conflicts_are_typed_and_fail_closed() -> None:
    loaded = normalize_required_check_metadata(_signed_artifact().model_dump(mode="json"))
    caller = {"_ovk_acquisition": {"collector_id": "forged"}, "task": "ok-context"}
    merged, conflicts = merge_loaded_protected_metadata(caller, loaded)
    assert conflicts
    assert merged.get("task") == "ok-context"
    assert merged.get("_ovk_provenance_conflicts")


def test_protected_environment_names_require_trusted_artifact() -> None:
    artifact = _signed_artifact(kind="protected_environment", payload={"protected_environments": ["pypi"]})
    data = _data_from_artifact(artifact)
    names = trusted_protected_environment_names(
        data, repo="r", head_sha="h", base_sha="b", verification_key=KEY
    )
    assert names == frozenset({"pypi"})
    data["protected_environments"] = ["forged"]
    unsigned = {"protected_environments": ["pypi"], "repository": "r", "head_sha": "h"}
    assert trusted_protected_environment_names(
        unsigned, repo="r", head_sha="h", base_sha="b", verification_key=KEY
    ) == frozenset()
