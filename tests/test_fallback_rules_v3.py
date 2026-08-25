"""Explicit fallback authorization contract tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ovk.core.authoritative_runtime import AuthoritativePlanError, execute_authoritative_plan
from ovk.core.fallback_rules import FallbackAuthorizationRule, FallbackRule, strict_fallback_rules_from_policy
from ovk.core.routing_pipeline import build_authoritative_routing_plan


def _auth_input() -> dict:
    return json.loads(
        Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8")
    )


def _base_policy() -> dict:
    return {
        "routing": {
            "enforced_lanes": ["authorization"],
            "prefer_deterministic": True,
            "max_selected_backends": 1,
        },
        "budget": {"allowed_backends": ["authorization-deterministic"]},
    }


def test_fallback_authorization_rule_has_stable_identity() -> None:
    rule = FallbackAuthorizationRule(
        primary_backend="z3-native",
        primary_guarantee="smt_refutation_search",
        fallback_backend="authorization-deterministic",
        fallback_guarantee="deterministic_witness",
        allowed_causes=["tool_unavailable"],
        proposition_id="no-admin-route-bypass",
        profile_id="authorization.fastapi.ast_v1",
        proof_relation="subsumes",
    )
    assert rule.rule_id
    again = FallbackAuthorizationRule(
        primary_backend="z3-native",
        primary_guarantee="smt_refutation_search",
        fallback_backend="authorization-deterministic",
        fallback_guarantee="deterministic_witness",
        allowed_causes=["tool_unavailable"],
        proposition_id="no-admin-route-bypass",
        profile_id="authorization.fastapi.ast_v1",
        proof_relation="subsumes",
    )
    assert again.rule_id == rule.rule_id
    assert FallbackRule is FallbackAuthorizationRule


def test_fallback_rule_matches_full_tuple_only() -> None:
    rule = FallbackRule(
        primary_backend="z3-native",
        primary_guarantee="smt_refutation_search",
        fallback_backend="authorization-deterministic",
        fallback_guarantee="deterministic_witness",
        allowed_causes=["tool_unavailable"],
    )
    assert rule.authorizes(
        primary_backend="z3-native",
        primary_guarantee="smt_refutation_search",
        fallback_backend="authorization-deterministic",
        fallback_guarantee="deterministic_witness",
        cause="tool_unavailable",
    )
    assert not rule.authorizes(
        primary_backend="z3-native",
        primary_guarantee="smt_refutation_search",
        fallback_backend="authorization-deterministic",
        fallback_guarantee="deterministic_witness",
        cause="timeout",
    )


def test_strict_rules_reject_post_execution_failure_causes() -> None:
    policy = _base_policy()
    policy["routing"]["fallback_rules"] = [
        {
            "primary_backend": "z3-native",
            "primary_guarantee": "smt_refutation_search",
            "fallback_backend": "authorization-deterministic",
            "fallback_guarantee": "deterministic_witness",
            "allowed_causes": ["timeout"],
        }
    ]
    with pytest.raises(ValueError, match="tool_unavailable"):
        strict_fallback_rules_from_policy(policy)


def test_legacy_broad_fallback_cannot_enter_authoritative_execution() -> None:
    policy = _base_policy()
    policy["routing"]["allow_fallback"] = True
    obligations = [
        {"lane": "authorization", "input": _auth_input(), "intent_id": "no-admin-route-bypass"}
    ]
    plan = build_authoritative_routing_plan(
        obligations, policy=policy, repo="r", head_sha="h"
    )
    with pytest.raises(AuthoritativePlanError, match="legacy broad allow_fallback"):
        execute_authoritative_plan(
            obligations,
            plan,
            repo="r",
            head_sha="h",
            policy=policy,
            use_cache=False,
            parallel=False,
        )


def test_explicit_rule_is_not_silently_ignored_or_overclaimed() -> None:
    policy = _base_policy()
    policy["routing"]["fallback_rules"] = [
        {
            "primary_backend": "z3-native",
            "primary_guarantee": "smt_refutation_search",
            "fallback_backend": "authorization-deterministic",
            "fallback_guarantee": "deterministic_witness",
            "allowed_causes": ["tool_unavailable"],
        }
    ]
    obligations = [
        {"lane": "authorization", "input": _auth_input(), "intent_id": "no-admin-route-bypass"}
    ]
    plan = build_authoritative_routing_plan(
        obligations, policy=policy, repo="r", head_sha="h"
    )
    with pytest.raises(AuthoritativePlanError, match="not yet evidence-bound"):
        execute_authoritative_plan(
            obligations,
            plan,
            repo="r",
            head_sha="h",
            policy=policy,
            use_cache=False,
            parallel=False,
        )
