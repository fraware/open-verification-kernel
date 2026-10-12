"""Validate bounded Lean ConstantInfo reference graphs from real native logs.

The native walker uses ConstantInfo.getUsedConstantsAsSet, checks env.find?
for every referenced name, rejects node/edge budget exhaustion and emits an
explicit graph. The Python validator independently rechecks graph closure,
structural Name identities, counts, module inventory scope and provenance
boundaries. This does NOT prove complete kernel semantic dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

_MARKER = "RTK_NATIVE_STRICT_CLOSURE_JSON="
_SCHEMA = "rtk.lean_native_strict_decl_closure.v1-development"
_KINDS = {
    "axiom", "definition", "theorem", "opaque",
    "quotient", "inductive", "constructor", "recursor",
}
_MAX_NODES = 12000
_MAX_EDGES = 180000


def _sha(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _key(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _name(value: object, depth: int = 0) -> None:
    if depth > 128 or not isinstance(value, list) or not value:
        raise ValueError("malformed or unbounded structural Lean Name")
    tag = value[0]
    if tag == "anonymous" and len(value) == 1:
        return
    if tag not in ("str", "num") or len(value) != 3:
        raise ValueError("unknown structural Lean Name component")
    _name(value[1], depth + 1)
    if tag == "str":
        if not isinstance(value[2], str) or not value[2] or len(value[2]) > 512:
            raise ValueError("invalid structural Lean Name text")
    elif type(value[2]) is not int or value[2] < 0:
        raise ValueError("invalid structural Lean Name number")


def _graph(value: object, root_label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "root_name", "root_name_ast", "node_count", "edge_count",
        "nodes", "missing_references_rejected", "budget_exhaustion_rejected",
        "reported_reference_relation",
        "complete_for_reported_reference_relation_under_budget",
        "semantic_dependency_closure_proved",
    }:
        raise ValueError("unexpected strict native graph shape")
    _name(value["root_name_ast"])
    if value["root_name"] != root_label:
        raise ValueError("strict native graph root mismatch")
    if (
        value["missing_references_rejected"] is not True
        or value["budget_exhaustion_rejected"] is not True
        or value["complete_for_reported_reference_relation_under_budget"] is not True
        or value["reported_reference_relation"]
        != "ConstantInfo.getUsedConstantsAsSet"
        or value["semantic_dependency_closure_proved"] is not False
    ):
        raise ValueError("unqualified native graph closure flags")
    nodes = value["nodes"]
    if not isinstance(nodes, list) or not (1 <= len(nodes) <= _MAX_NODES):
        raise ValueError("strict graph node budget violated")
    if type(value["node_count"]) is not int or value["node_count"] != len(nodes):
        raise ValueError("strict graph node count mismatch")
    if type(value["edge_count"]) is not int or not (0 <= value["edge_count"] <= _MAX_EDGES):
        raise ValueError("invalid bounded graph edge count")

    index: dict[str, dict] = {}
    actual_edges = 0
    for entry in nodes:
        if not isinstance(entry, dict) or set(entry) != {
            "name", "name_ast", "kind", "module", "unsafe", "partial",
            "level_parameter_count", "direct_references",
            "direct_reference_asts",
        }:
            raise ValueError("malformed native declaration record")
        _name(entry["name_ast"])
        k = _key(entry["name_ast"])
        if k in index:
            raise ValueError("duplicate structural declaration identity")
        if not isinstance(entry["name"], str) or not entry["name"] or (
            len(entry["name"]) > 512
        ):
            raise ValueError("invalid native declaration label")
        if entry["kind"] not in _KINDS or (
            not isinstance(entry["module"], str)
            or not entry["module"] or len(entry["module"]) > 512
        ):
            raise ValueError("invalid native declaration kind or module")
        if type(entry["unsafe"]) is not bool or type(entry["partial"]) is not bool:
            raise ValueError("unsupported native safety/partiality flags")
        if type(entry["level_parameter_count"]) is not int or not (
            0 <= entry["level_parameter_count"] <= 1024
        ):
            raise ValueError("invalid universe parameter count")
        refs = entry["direct_reference_asts"]
        displays = entry["direct_references"]
        if not isinstance(refs, list) or not isinstance(displays, list) or (
            len(refs) != len(displays) or len(refs) > _MAX_EDGES
        ):
            raise ValueError("malformed native references")
        for ref, label in zip(refs, displays):
            _name(ref)
            if not isinstance(label, str) or not label or len(label) > 512:
                raise ValueError("bad displayed native reference")
        if len({_key(r) for r in refs}) != len(refs):
            raise ValueError("duplicate structural direct dependency")
        actual_edges += len(refs)
        if actual_edges > _MAX_EDGES:
            raise ValueError("graph edge budget exceeded")
        index[k] = entry
    if actual_edges != value["edge_count"]:
        raise ValueError("graph edge count mismatch")
    start = _key(value["root_name_ast"])
    if start not in index:
        raise ValueError("source or target graph lacks root declaration")
    reachable: set[str] = set()
    pending = [start]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        if current not in index:
            raise ValueError("UNRESOLVED_REFERENCED_DECLARATION")
        reachable.add(current)
        for ref in index[current]["direct_reference_asts"]:
            dep = _key(ref)
            if dep not in index:
                raise ValueError("UNRESOLVED_REFERENCED_DECLARATION")
            if dep not in reachable:
                pending.append(dep)
    if reachable != set(index):
        raise ValueError("unreachable declaration inserted into closure")
    return {
        "root": root_label, "nodes": nodes, "index": index,
        "nodes_count": len(nodes), "edges_count": actual_edges,
    }


def _parse(raw: str, subject: str, kind: str) -> dict[str, Any]:
    results = [
        line.partition(_MARKER)[2].strip()
        for line in raw.splitlines() if _MARKER in line
    ]
    if len(results) != 1 or len(results[0]) > 12_000_000:
        raise ValueError("one bounded native closure record required")
    try:
        record = json.loads(results[0])
    except json.JSONDecodeError as e:
        raise ValueError("invalid native closure JSON") from e
    required = {
        "schema_version", "root_name", "root_kind",
        "root_declaration_closure", "imported_definition_closure",
        "target_historical_proof_replayed", "target_claim_established",
        "axiom_policy_authenticated", "source_target_environment_authenticity_verified",
        "semantic_support_complete", "transport_applicability",
        "reliance_authorization",
    }
    if not isinstance(record, dict) or set(record) != required or (
        record["schema_version"] != _SCHEMA or record["root_name"] != subject
        or record["root_kind"] != kind
    ):
        raise ValueError("wrong native declaration support record")
    if any(record[k] is not False for k in (
        "target_historical_proof_replayed", "target_claim_established",
        "axiom_policy_authenticated", "source_target_environment_authenticity_verified",
        "semantic_support_complete", "reliance_authorization",
    )) or record["transport_applicability"] != "UNDETERMINED":
        raise ValueError("unsupported trust or historical reuse authority")
    root = _graph(record["root_declaration_closure"], subject)
    op = _graph(record["imported_definition_closure"], "op")
    expected = "theorem" if kind == "source_theorem" else "axiom"
    if root["index"][_key(record["root_declaration_closure"]["root_name_ast"])]["kind"] != expected:
        raise ValueError("checked theorem/target placeholder kind mismatch")
    if op["index"][_key(record["imported_definition_closure"]["root_name_ast"])]["kind"] != "definition":
        raise ValueError("imported op changed declaration kind")
    return {"record": record, "root": root, "op": op}


def _axioms(graph: dict[str, Any]) -> dict[str, dict]:
    return {
        _key(entry["name_ast"]): entry
        for entry in graph["nodes"] if entry["kind"] == "axiom"
    }


def compare_native_strict_closures(
    *,
    source_log: str,
    target_log: str,
    changed_target_log: str,
    source_modules: dict,
    baseline_target_modules: dict,
    changed_target_module_sha256: str,
) -> dict[str, Any]:
    source = _parse(source_log, "historical_claim", "source_theorem")
    target = _parse(target_log, "rtk_unproven_target_claim", "target_goal_placeholder")
    changed = _parse(
        changed_target_log, "rtk_unproven_target_claim", "target_goal_placeholder"
    )
    if not isinstance(source_modules, dict) or not isinstance(baseline_target_modules, dict):
        raise ValueError("missing native module inventory")
    for group, inventory in (
        (source, source_modules),
        (target, baseline_target_modules),
        (changed, baseline_target_modules),
    ):
        for graph in (group["root"], group["op"]):
            for n in graph["nodes"]:
                if n["module"] != "LOCAL" and n["module"] not in inventory:
                    raise ValueError("declaration module outside checked environment")
        root = group["record"]["root_declaration_closure"]["root_name_ast"]
        if _key(root) not in group["root"]["index"]:
            raise ValueError("missing root declaration")
        op = group["record"]["imported_definition_closure"]["root_name_ast"]
        if _key(op) not in group["root"]["index"]:
            raise ValueError("claim graph omitted imported op dependency")
    op_before = _axioms(target["op"])
    op_after = _axioms(changed["op"])
    introduced = [v for k, v in op_after.items() if k not in op_before]
    removed = [v for k, v in op_before.items() if k not in op_after]
    if sorted(n["name"] for n in introduced) != ["rtkExternal"]:
        raise ValueError("native injected target axiom closure missing")
    new = introduced[0]
    if new["module"] != "RTKSemanticSupport" or new["kind"] != "axiom":
        raise ValueError("injected target axiom has wrong module or kind")
    if any(n["name"] == "rtkExternal" for n in _axioms(source["root"]).values()):
        raise ValueError("target-only axiom leaked into source proof closure")
    if not isinstance(changed_target_module_sha256, str) or len(
        changed_target_module_sha256
    ) != 64 or any(x not in "0123456789abcdef" for x in changed_target_module_sha256):
        raise ValueError("invalid changed imported module byte fingerprint")
    old = baseline_target_modules.get("RTKSemanticSupport", {})
    if changed_target_module_sha256 == old.get("file_sha256"):
        raise ValueError("changed target module file bytes did not change")
    return {
        "schema_version": "rtk.lean_strict_decl_closure_delta.v1-development",
        "source_root_node_count": source["root"]["nodes_count"],
        "baseline_target_root_node_count": target["root"]["nodes_count"],
        "changed_target_root_node_count": changed["root"]["nodes_count"],
        "source_imported_op_node_count": source["op"]["nodes_count"],
        "baseline_target_imported_op_node_count": target["op"]["nodes_count"],
        "changed_target_imported_op_node_count": changed["op"]["nodes_count"],
        "introduced_target_axioms": [
            {"name": a["name"], "module": a["module"], "kind": a["kind"]}
            for a in introduced
        ],
        "removed_target_axioms": [
            {"name": a["name"], "module": a["module"], "kind": a["kind"]}
            for a in removed
        ],
        "source_native_closure_log_sha256": _sha(source_log.encode()),
        "baseline_target_native_closure_log_sha256": _sha(target_log.encode()),
        "changed_target_native_closure_log_sha256": _sha(changed_target_log.encode()),
        "changed_target_imported_olean_sha256": changed_target_module_sha256,
        "strict_reference_relation_graph_closed_for_observed_native_environment": True,
        "structural_name_identity_used": True,
        "missing_decl_and_resource_budget_fail_closed": True,
        "semantic_support_complete": False,
        "kernel_environment_dependency_completeness_proved": False,
        "policy_and_provenance_authenticated": False,
        "target_historical_proof_replayed": False,
        "target_claim_established": False,
        "historical_evidence_applicability": "UNDETERMINED",
        "conservative_action": "REVALIDATION_REQUIRED",
        "reliance_authorization": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in (
        "source-log", "target-log", "changed-target-log",
        "prior-environment", "changed-target-olean", "output",
    ):
        parser.add_argument("--" + arg, type=Path, required=True)
    args = parser.parse_args()
    environment = json.loads(args.prior_environment.read_text())
    if environment.get("transport_applicability") != "UNDETERMINED" or (
        environment.get("native_transport_oracle_executed") is not False
        or environment.get("reliance_authorization") is not False
    ):
        raise ValueError("native context contaminated by oracle")
    result = compare_native_strict_closures(
        source_log=args.source_log.read_text(),
        target_log=args.target_log.read_text(),
        changed_target_log=args.changed_target_log.read_text(),
        source_modules=environment["source_modules"],
        baseline_target_modules=environment["target_modules"],
        changed_target_module_sha256=_sha(args.changed_target_olean.read_bytes()),
    )
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(result, f, sort_keys=True, indent=2)
        f.write("\n")
    print("STRICT_LEAN_REFERENCE_CLOSURE_COMPLETED_NO_VALID_TRANSPORT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
