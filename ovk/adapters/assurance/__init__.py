"""Assurance-mode backends (opt-in; not mixed into ordinary lane routing)."""

from __future__ import annotations

from ovk.core.backend_registry import BackendRegistry


def build_assurance_registry() -> BackendRegistry:
    """Register assurance-capable backends for ``ovk verifier`` only."""
    # Local imports avoid circular import with ovk.assurance.registry.
    from ovk.adapters.assurance.auth_state import AuthoritativeStateAdapter
    from ovk.adapters.assurance.lean_pfcore import LeanPfCoreAssuranceAdapter
    from ovk.adapters.assurance.model_judge import ModelJudgeAdapter
    from ovk.adapters.assurance.opa_policy import OpaPolicyAssuranceAdapter
    from ovk.adapters.assurance.pytest_suite import PytestSuiteAdapter
    from ovk.adapters.assurance.sql_diff import SqlStateDiffAdapter

    registry = BackendRegistry()
    for cls in (
        AuthoritativeStateAdapter,
        PytestSuiteAdapter,
        OpaPolicyAssuranceAdapter,
        LeanPfCoreAssuranceAdapter,
        SqlStateDiffAdapter,
        ModelJudgeAdapter,
    ):
        registry.register(cls())
    return registry


__all__ = [
    "build_assurance_registry",
]
