"""Tests for Sprint 6 source-profile scaffolding."""

from __future__ import annotations

from ovk.core.source_profiles import (
    is_known_source_profile,
    profiles_from_policy,
    source_profile_strict_eligible,
)


def test_known_profiles() -> None:
    assert is_known_source_profile("authorization.fastapi.ast_v1")
    assert not is_known_source_profile("made.up.profile")


def test_strict_eligible_requires_all_gates() -> None:
    assert source_profile_strict_eligible(
        profile_id="authorization.fastapi.ast_v1",
        materials_trusted=True,
        coverage_complete=True,
        enforcement_test_present=True,
    )
    assert not source_profile_strict_eligible(
        profile_id="authorization.fastapi.ast_v1",
        materials_trusted=False,
        coverage_complete=True,
        enforcement_test_present=True,
    )


def test_profiles_from_policy() -> None:
    policy = {
        "source_profiles": {
            "authorization": ["authorization.fastapi.ast_v1", "bogus"],
        }
    }
    assert profiles_from_policy(policy, lane="authorization") == ["authorization.fastapi.ast_v1"]
