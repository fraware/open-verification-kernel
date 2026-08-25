"""Security tests for authenticated branch-protection metadata provenance."""

from __future__ import annotations

from ovk.core.metadata_provenance import (
    expected_branch_metadata_digest,
    sign_acquisition_record,
)
from ovk.core.self_protection_compiler import (
    compile_self_protection_obligation,
    resolve_metadata_trusted,
)

KEY = "test-metadata-verification-key"


def _data() -> dict:
    return {
        "before": {"required_checks": ["ovk-verify"]},
        "after": {"required_checks": ["ovk-verify"]},
    }


def _with_record(
    *,
    provenance_kind: str = "protected_base_workflow",
    signed: bool = True,
) -> dict:
    data = _data()
    record = {
        "schema_version": "ovk.metadata_acquisition.v1",
        "collector_id": "ovk.collect_branch_metadata",
        "collector_version": "1.0.0",
        "source_type": "branch_protection",
        "repository": "r",
        "branch": "main",
        "base_sha": "b",
        "head_sha": "h",
        "collected_at": "2026-08-24T00:00:00Z",
        "payload_digest": expected_branch_metadata_digest(data),
        "authentication_method": "protected_hmac_key",
        "provenance_kind": provenance_kind,
    }
    if signed:
        record = sign_acquisition_record(record, key=KEY).model_dump(mode="json")
    data["_ovk_acquisition"] = record
    return data


def test_policy_boolean_and_string_cannot_assert_metadata_trust() -> None:
    policy = {
        "trust": {
            "metadata_trusted": True,
            "provenance_kind": "protected_base_workflow",
        }
    }
    assert resolve_metadata_trusted(policy) is False
    assert resolve_metadata_trusted(
        policy,
        data=_data(),
        repo="r",
        head_sha="h",
        base_sha="b",
        verification_key=KEY,
    ) is False


def test_unsigned_digest_bound_record_is_still_untrusted() -> None:
    data = _with_record(signed=False)
    assert resolve_metadata_trusted(
        {},
        data=data,
        repo="r",
        head_sha="h",
        base_sha="b",
        verification_key=KEY,
    ) is False


def test_authenticated_digest_bound_record_can_satisfy_trust_contract() -> None:
    data = _with_record()
    assert resolve_metadata_trusted(
        {},
        data=data,
        repo="r",
        head_sha="h",
        base_sha="b",
        verification_key=KEY,
    ) is True


def test_wrong_verification_key_invalidates_trust() -> None:
    data = _with_record()
    assert resolve_metadata_trusted(
        {},
        data=data,
        repo="r",
        head_sha="h",
        base_sha="b",
        verification_key="wrong-key",
    ) is False


def test_tampering_metadata_after_collection_invalidates_trust() -> None:
    data = _with_record()
    data["after"]["required_checks"] = []
    assert resolve_metadata_trusted(
        {},
        data=data,
        repo="r",
        head_sha="h",
        base_sha="b",
        verification_key=KEY,
    ) is False


def test_repository_or_revision_substitution_invalidates_trust() -> None:
    data = _with_record()
    assert resolve_metadata_trusted(
        {}, data=data, repo="other", head_sha="h", base_sha="b", verification_key=KEY
    ) is False
    assert resolve_metadata_trusted(
        {}, data=data, repo="r", head_sha="other", base_sha="b", verification_key=KEY
    ) is False
    assert resolve_metadata_trusted(
        {}, data=data, repo="r", head_sha="h", base_sha="other", verification_key=KEY
    ) is False


def test_untrusted_collector_kind_cannot_be_upgraded_by_policy() -> None:
    data = _with_record(provenance_kind="github_api_current_state")
    policy = {
        "trust": {
            "metadata_trusted": True,
            "provenance_kind": "protected_base_workflow",
        }
    }
    assert resolve_metadata_trusted(
        policy,
        data=data,
        repo="r",
        head_sha="h",
        base_sha="b",
        verification_key=KEY,
    ) is False


def test_compiler_binds_acquisition_record_signature_into_material_set() -> None:
    data = _with_record()
    obligation = compile_self_protection_obligation(
        data,
        repo="r",
        head_sha="h",
        base_sha="b",
        metadata_trusted=True,
    )
    acquisition = obligation.abstraction["metadata_acquisition"]
    assert acquisition["payload_digest"] == expected_branch_metadata_digest(data)
    assert acquisition["signature"]["algorithm"] == "hmac-sha256"
    branch_materials = [item for item in obligation.materials if item.kind == "branch_protection"]
    assert branch_materials and all(item.trusted for item in branch_materials)
