"""Synthetic adversarial checks: actual Lean traversal runs in native workflow."""

from __future__ import annotations

import copy
import json

import pytest

from experiments.rtk.lean_strict_decl_closure_v1 import (
    _graph, compare_native_strict_closures,
)


def _name(name: str):
    return ["str", ["anonymous"], name]


def _node(name, kind, module, refs=()):
    return {
        "name": name,
        "name_ast": _name(name),
        "kind": kind,
        "module": module,
        "unsafe": False,
        "partial": False,
        "level_parameter_count": 0,
        "direct_references": list(refs),
        "direct_reference_asts": [_name(n) for n in refs],
    }


def _graph_record(root, *, goal=False, injected=False, op_only=False):
    entries = {
        "Nat": _node("Nat", "inductive", "Init.Prelude"),
        "op": _node(
            "op", "definition", "RTKSemanticSupport",
            ("Nat", "rtkExternal") if injected else ("Nat",),
        ),
    }
    if injected:
        entries["rtkExternal"] = _node(
            "rtkExternal", "axiom", "RTKSemanticSupport", ("Nat",)
        )
    if not op_only:
        entries[root] = _node(
            root, "axiom" if goal else "theorem", "LOCAL", ("op",)
        )
    result = list(entries.values())
    return {
        "root_name": "op" if op_only else root,
        "root_name_ast": _name("op" if op_only else root),
        "node_count": len(result),
        "edge_count": sum(len(v["direct_references"]) for v in result),
        "nodes": result,
        "missing_references_rejected": True,
        "budget_exhaustion_rejected": True,
        "reported_reference_relation": "ConstantInfo.getUsedConstantsAsSet",
        "complete_for_reported_reference_relation_under_budget": True,
        "semantic_dependency_closure_proved": False,
    }


def _log(*, goal=False, injected=False):
    root = "rtk_unproven_target_claim" if goal else "historical_claim"
    data = {
        "schema_version": "rtk.lean_native_strict_decl_closure.v1-development",
        "root_name": root,
        "root_kind": "target_goal_placeholder" if goal else "source_theorem",
        "root_declaration_closure": _graph_record(
            root, goal=goal, injected=injected
        ),
        "imported_definition_closure": _graph_record(
            root, injected=injected, op_only=True
        ),
        "target_historical_proof_replayed": False,
        "target_claim_established": False,
        "axiom_policy_authenticated": False,
        "source_target_environment_authenticity_verified": False,
        "semantic_support_complete": False,
        "transport_applicability": "UNDETERMINED",
        "reliance_authorization": False,
    }
    return "file: info: RTK_NATIVE_STRICT_CLOSURE_JSON=" + json.dumps(data)


def _case():
    return {
        "source_log": _log(),
        "target_log": _log(goal=True),
        "changed_target_log": _log(goal=True, injected=True),
        "source_modules": {"Init.Prelude": {}, "RTKSemanticSupport": {}},
        "baseline_target_modules": {
            "Init.Prelude": {},
            "RTKSemanticSupport": {"file_sha256": "a" * 64},
        },
        "changed_target_module_sha256": "b" * 64,
    }


def test_complete_bounded_graph_and_target_axiom_delta():
    result = compare_native_strict_closures(**_case())
    assert result["introduced_target_axioms"] == [{
        "name": "rtkExternal", "module": "RTKSemanticSupport", "kind": "axiom",
    }]
    assert result["strict_reference_relation_graph_closed_for_observed_native_environment"]
    assert result["historical_evidence_applicability"] == "UNDETERMINED"
    assert result["reliance_authorization"] is False


@pytest.mark.parametrize(
    ("which", "field", "reason"),
    [
        ("changed_target_log", "missing_edge", "UNRESOLVED_REFERENCED_DECLARATION"),
        ("source_log", "extra_node", "unreachable declaration"),
        ("changed_target_log", "duplicate", "duplicate structural"),
        ("target_log", "budget", "graph node count mismatch"),
        ("target_log", "oracle", "unsupported trust"),
        ("source_log", "partial_claim", "unsupported native safety"),
        ("target_log", "wrong_root_kind", "checked theorem/target placeholder"),
    ],
)
def test_structural_graph_tampering_fail_closed(which, field, reason):
    case = _case()
    prefix, raw = case[which].split("RTK_NATIVE_STRICT_CLOSURE_JSON=", 1)
    item = json.loads(raw)
    graph = item["root_declaration_closure"]
    if field == "missing_edge":
        # Keep aggregate counts consistent so the dangling op reference,
        # rather than malformed graph bookkeeping, causes the rejection.
        removed = next(
            entry for entry in graph["nodes"] if entry["name"] == "rtkExternal"
        )
        graph["nodes"].remove(removed)
        graph["node_count"] -= 1
        graph["edge_count"] -= len(removed["direct_reference_asts"])
    elif field == "extra_node":
        graph["nodes"].append(_node("ghost", "axiom", "Init.Prelude"))
        graph["node_count"] += 1
    elif field == "duplicate":
        graph["nodes"].append(copy.deepcopy(graph["nodes"][0]))
        graph["node_count"] += 1
        graph["edge_count"] += len(graph["nodes"][0]["direct_references"])
    elif field == "budget":
        graph["node_count"] = 999
    elif field == "oracle":
        item["target_claim_established"] = True
    elif field == "partial_claim":
        graph["nodes"][-1]["partial"] = "false"
    elif field == "wrong_root_kind":
        for node in graph["nodes"]:
            if node["name"] == "rtk_unproven_target_claim":
                node["kind"] = "theorem"
    case[which] = prefix + "RTK_NATIVE_STRICT_CLOSURE_JSON=" + json.dumps(item)
    with pytest.raises(ValueError, match=reason):
        compare_native_strict_closures(**case)


def test_graph_rejects_inconsistent_edge_count():
    graph = _graph_record("historical_claim")
    graph["edge_count"] -= 1
    with pytest.raises(ValueError, match="graph edge count mismatch"):
        _graph(graph, "historical_claim")


def test_numeric_and_string_names_are_distinct():
    graph = _graph_record("historical_claim")
    alternate = _node("Nat", "inductive", "Init.Prelude")
    alternate["name_ast"] = ["num", ["anonymous"], 42]
    graph["nodes"].append(alternate)
    graph["node_count"] += 1
    with pytest.raises(ValueError, match="unreachable declaration"):
        _graph(graph, "historical_claim")


def test_unregistered_declaration_module_is_rejected():
    case = _case()
    raw = json.loads(case["changed_target_log"].split(
        "RTK_NATIVE_STRICT_CLOSURE_JSON=", 1
    )[1])
    for node in raw["imported_definition_closure"]["nodes"]:
        if node["name"] == "rtkExternal":
            node["module"] = "Unrecorded.Module"
    case["changed_target_log"] = "RTK_NATIVE_STRICT_CLOSURE_JSON=" + json.dumps(raw)
    with pytest.raises(ValueError, match="module outside checked environment"):
        compare_native_strict_closures(**case)


def test_byte_unchanged_target_is_not_accepted_as_changed():
    case = _case()
    case["changed_target_module_sha256"] = "a" * 64
    with pytest.raises(ValueError, match="module file bytes did not change"):
        compare_native_strict_closures(**case)


def test_native_scope_flag_cannot_be_promoted_to_semantic_closure():
    case = _case()
    raw = json.loads(case["source_log"].split(
        "RTK_NATIVE_STRICT_CLOSURE_JSON=", 1
    )[1])
    raw["root_declaration_closure"]["semantic_dependency_closure_proved"] = True
    case["source_log"] = "RTK_NATIVE_STRICT_CLOSURE_JSON=" + json.dumps(raw)
    with pytest.raises(ValueError, match="unqualified native graph closure flags"):
        compare_native_strict_closures(**case)


def test_graph_rejects_invalid_reference_name_without_partial_success():
    graph = _graph_record("historical_claim")
    graph["nodes"][0]["direct_reference_asts"] = [
        ["mvar", ["anonymous"]]
    ]
    graph["nodes"][0]["direct_references"] = ["forged"]
    with pytest.raises(ValueError, match="unknown structural Lean Name component"):
        _graph(graph, "historical_claim")
