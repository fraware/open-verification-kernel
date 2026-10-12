"""Synthetic adversarial schema tests. Real Lean.collectAxioms evidence comes from CI."""

from __future__ import annotations

import hashlib
import json

import pytest

from experiments.rtk.lean_axiom_support_v1 import (
    _read_record, compare_native_axiom_support,
)


def _log(root, kind, axioms=(), refs=("Nat", "op"), root_axioms=()):
    return "fixture: info: RTK_NATIVE_AXIOM_SUPPORT_JSON=" + json.dumps({
        "schema_version": "rtk.lean_native_axiom_dependency.v1-development",
        "root_name": root,
        "root_kind": kind,
        "op_name": "op",
        "direct_root_references": list(refs),
        "direct_op_references": ["Nat"],
        "op_transitive_axioms": [
            {"name": n, "module": m, "kind": "axiom"}
            for n, m in axioms
        ],
        "source_proof_transitive_axioms": [
            {"name": n, "module": m, "kind": "axiom"}
            for n, m in root_axioms
        ],
        "synthetic_target_axiom_not_counted_as_proof": True,
        "transitive_dependency_closure_proved": False,
        "trusted_axiom_policy_authenticated": False,
        "historic_target_proof_replayed": False,
        "historical_applicability_established": False,
    })


def _case():
    source = _log("historical_claim", "theorem")
    target = _log("rtk_unproven_target_claim", "unproved_goal_placeholder")
    changed = _log("rtk_unproven_target_claim", "unproved_goal_placeholder",
                   axioms=[("rtkExternal", "RTKSemanticSupport")])
    return {
        "source_log": source, "target_log": target,
        "changed_target_log": changed,
        "environment": {
            "schema_version": "rtk.lean_dual_installed_environment.v1-development",
            "target_claim_established": False,
            "historical_proof_replayed_on_target": False,
            "reliance_authorization": False,
            "transport_applicability": "UNDETERMINED",
            "target_modules": {"RTKSemanticSupport": {}, "Init.Prelude": {}},
            "target_module_inventory_sha256": "a" * 64,
        },
    }


def test_injected_target_axiom_causes_conservative_revalidation():
    result = compare_native_axiom_support(**_case())
    assert result["injected_axioms"] == ["rtkExternal"]
    assert result["historical_evidence_applicability"] == "UNDETERMINED"
    assert result["trusted_axiom_policy_authenticated"] is False
    assert result["target_historical_proof_replayed"] is False
    assert result["conservative_action"] == "REVALIDATION_REQUIRED"
    assert result["source_native_axiom_log_sha256"] == hashlib.sha256(
        _case()["source_log"].encode()
    ).hexdigest()


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda x: x.update(changed_target_log=x["target_log"]),
         "injected adversarial axiom"),
        (lambda x: x["environment"].update(target_claim_established=True),
         "unqualified prior"),
        (lambda x: x["environment"].update(target_modules={}),
         "missing observed imported"),
        (lambda x: x.update(source_log=x["source_log"] + "\n" + x["source_log"]),
         "exactly one"),
        (lambda x: x.update(changed_target_log=x["changed_target_log"].replace(
            "RTKSemanticSupport", "Other.Module")),
         "wrong imported module"),
        (lambda x: x.update(changed_target_log=x["changed_target_log"].replace(
            "rtkExternal", "sorryAx")), "sorryAx"),
        (lambda x: x.update(target_log=x["target_log"].replace(
            '"historic_target_proof_replayed": false',
            '"historic_target_proof_replayed": true')),
         "unsupported closure"),
        (lambda x: x.update(source_log=x["source_log"].replace(
            '"root_kind": "theorem"', '"root_kind": "unproved_goal_placeholder"')),
         "unexpected axiom proof"),
        (lambda x: x.update(changed_target_log=x["changed_target_log"].replace(
            '"direct_root_references": ["Nat", "op"]',
            '"direct_root_references": ["Nat"]')),
         "claim dependency"),
    ],
)
def test_axiom_support_fail_closed(edit, message):
    case = _case()
    edit(case)
    with pytest.raises(ValueError, match=message):
        compare_native_axiom_support(**case)


def test_synthetic_unproved_goal_never_returns_proof_axiom_set():
    source = _log("rtk_unproven_target_claim", "unproved_goal_placeholder",
                  root_axioms=[("rtkExternal", "RTKSemanticSupport")])
    with pytest.raises(ValueError, match="synthetic target goal"):
        _read_record(source, "rtk_unproven_target_claim", "unproved_goal_placeholder")


def test_axiom_record_duplicate_names_rejected():
    case = _case()
    case["changed_target_log"] = _log(
        "rtk_unproven_target_claim", "unproved_goal_placeholder",
        axioms=[
            ("rtkExternal", "RTKSemanticSupport"),
            ("rtkExternal", "RTKSemanticSupport"),
        ],
    )
    with pytest.raises(ValueError, match="duplicate native axiom names"):
        compare_native_axiom_support(**case)
