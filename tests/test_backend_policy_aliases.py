from ovk.core.backend_ids import normalize_allowed_backends, normalize_denied_backends
from ovk.core.context import budget_from_policy
from ovk.core.execution_budget import execution_budget_from_policy


def test_legacy_starter_allowlist_is_migrated_to_unrestricted() -> None:
    policy = {"budget": {"allowed_backends": ["opa", "z3", "cedar"]}}
    assert normalize_allowed_backends(["opa", "z3", "cedar"]) is None
    assert execution_budget_from_policy(policy).allowed_backends is None
    assert budget_from_policy(policy).allowed_backends is None


def test_short_backend_aliases_expand_to_control_plane_ids() -> None:
    allowed = normalize_allowed_backends(["opa", "z3"])
    assert allowed is not None
    assert {"opa", "opa-native", "z3", "z3-native"}.issubset(set(allowed))


def test_lane_aliases_expand_for_explicit_enforcement_policy() -> None:
    denied = normalize_denied_backends(["authorization", "infrastructure"])
    assert "z3-native" in denied
    assert "authorization-deterministic" in denied
    assert "infrastructure-deterministic" in denied
    assert "lane-infrastructure" in denied
