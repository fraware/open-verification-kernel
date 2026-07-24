from ovk.core.ci_secrets_compiler import compile_ci_secrets_obligation
from ovk.core.compiler_bridge import material_refs_from_digest
from ovk.core.materials import canonical_material_bytes, material_reference_from_payload
from ovk.core.self_protection_compiler import compile_self_protection_obligation
from ovk.core.shadow_obligation import build_shadow_obligation


def test_material_reference_size_matches_canonical_payload_bytes() -> None:
    payload = {"z": [1, 2, 3], "a": {"enabled": True}}
    reference = material_reference_from_payload(
        material_id="material-1",
        kind="policy",
        uri="ovk-material:test/policy",
        payload=payload,
        source_revision="abc",
    )
    assert reference.size_bytes == len(canonical_material_bytes(payload))
    assert reference.size_bytes != len(reference.sha256)


def test_self_protection_material_sizes_bind_each_payload() -> None:
    data = {
        "actor": {"type": "ai_agent", "id": "agent-1"},
        "task": "preserve the gate",
        "changed_files": [".github/workflows/ci.yml"],
        "before": {"required_checks": ["ovk-verify"]},
        "after": {"required_checks": ["ovk-verify"]},
    }
    obligation = compile_self_protection_obligation(
        data,
        repo="example/repo",
        head_sha="head",
        base_sha="base",
    )
    by_id = {item.material_id: item for item in obligation.materials}
    assert by_id["self-protection-before"].size_bytes == len(canonical_material_bytes(data["before"]))
    assert by_id["self-protection-after"].size_bytes == len(canonical_material_bytes(data["after"]))
    assert by_id["self-protection-input"].size_bytes == len(canonical_material_bytes(data))


def test_ci_secrets_material_size_binds_payload_not_digest() -> None:
    data = {
        "workflows": {
            "ci.yml": {
                "on": "pull_request_target",
                "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": []}},
            }
        }
    }
    obligation = compile_ci_secrets_obligation(data, repo="example/repo", head_sha="head")
    material = obligation.materials[0]
    assert material.size_bytes == len(canonical_material_bytes(data))
    assert material.size_bytes != len(material.sha256)


def test_shadow_and_bridge_material_sizes_bind_payload() -> None:
    data = {"routes": [{"path": "/admin", "methods": ["GET"]}]}
    shadow = build_shadow_obligation(
        lane="authorization",
        data=data,
        repo="example/repo",
        head_sha="head",
        base_sha="base",
        intent_id="admin-only-routes",
    )
    assert shadow.materials[0].size_bytes == len(canonical_material_bytes(data))
    bridged = material_refs_from_digest(
        material_id="bridge-material",
        kind="diff",
        uri="ovk-material:bridge",
        payload=data,
        source_revision="head",
    )
    assert bridged.size_bytes == len(canonical_material_bytes(data))
    assert bridged.size_bytes != len(bridged.sha256)


def test_ci_secrets_legacy_material_size_binds_input_payload() -> None:
    data = {
        "trust_context": "untrusted_fork_pr",
        "workflows": [
            {
                "workflow_id": "ci",
                "triggers": ["pull_request"],
                "secrets_used": [],
                "runs_untrusted_code": False,
            }
        ],
    }
    obligation = compile_ci_secrets_obligation(
        data,
        repo="example/repo",
        head_sha="head",
        base_sha="base",
    )
    assert len(obligation.materials) == 1
    reference = obligation.materials[0]
    assert reference.size_bytes == len(canonical_material_bytes(data))
    assert reference.size_bytes != len(reference.sha256)
