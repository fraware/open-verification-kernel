from pathlib import Path

from ovk.adapters.opa.policy_assets import SELF_PROTECTION_REGO, write_self_protection_rego


def test_self_protection_rego_contains_expected_rules() -> None:
    assert "package ovk.self_protection" in SELF_PROTECTION_REGO
    assert "after_has_gate(gate)" in SELF_PROTECTION_REGO
    assert "not after_has_gate(gate)" in SELF_PROTECTION_REGO
    assert "required verification gate removed" in SELF_PROTECTION_REGO
    assert "verification configuration changed" in SELF_PROTECTION_REGO
    assert "workflow actions permission escalated" in SELF_PROTECTION_REGO
    # OPA 0.67 rejects `some path` followed by `path := ...` as redeclaration.
    assert "some path" not in SELF_PROTECTION_REGO
    assert "path := input.changed_files[_]" in SELF_PROTECTION_REGO


def test_materialized_rego_fixture_matches_asset() -> None:
    fixture = Path("adapters/opa/policies/self_protection.rego").read_text(encoding="utf-8")
    assert fixture == SELF_PROTECTION_REGO


def test_write_self_protection_rego(tmp_path: Path) -> None:
    output = tmp_path / "policy.rego"
    write_self_protection_rego(output)
    assert output.read_text(encoding="utf-8") == SELF_PROTECTION_REGO
