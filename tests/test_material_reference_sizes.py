from ovk.core.materials import canonical_material_bytes, material_reference_from_payload
from ovk.core.self_protection_compiler import compile_self_protection_obligation


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
