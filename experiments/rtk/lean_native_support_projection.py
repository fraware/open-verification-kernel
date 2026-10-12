"""Strict, deliberately *incomplete* projection of native Lean support logs.

The input is a JSON payload produced by a separate pinned native Lean run.
This module authenticates neither those bytes nor the runner; callers must
retain and independently verify native execution and checked source inputs.

Each generated node digest hashes pinned-checker diagnostic Expr.repr text,
NOT a canonical Lean proof/kernel expression serialization. Imported support
is boundary-only, so every projection is permanently flagged INCOMPLETE.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

_SHA = re.compile(r"^[a-f0-9]{64}$")
_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.']*$")
_SCHEMA = "rtk.lean_native_support_probe.v1-development"


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def project_native_probe(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version", "root", "items",
        "imported_boundary_expansion_complete",
    }:
        raise ValueError("wrong native support probe schema")
    if raw["schema_version"] != _SCHEMA:
        raise ValueError("unknown native support probe version")
    if raw["imported_boundary_expansion_complete"] is not False:
        raise ValueError("imported-boundary completeness unsupported")
    if not isinstance(raw["root"], str) or not _SYMBOL.fullmatch(raw["root"]):
        raise ValueError("unsupported theorem root symbol")
    if not isinstance(raw["items"], list) or not 1 <= len(raw["items"]) <= 2048:
        raise ValueError("missing or oversized support nodes")

    nodes: dict[str, dict[str, Any]] = {}
    for node in raw["items"]:
        if not isinstance(node, dict) or set(node) != {
            "symbol", "kind", "expanded", "type_repr",
            "value_repr", "references",
        }:
            raise ValueError("unexpected native node fields")
        name = node["symbol"]
        if not isinstance(name, str) or not _SYMBOL.fullmatch(name):
            raise ValueError("unrepresentable native constant symbol")
        if name in nodes:
            raise ValueError("duplicate native support symbol")
        if node["kind"] not in {
            "theorem", "definition", "opaque", "axiom",
            "constructor", "recursor", "inductive", "quotient",
        } or type(node["expanded"]) is not bool:
            raise ValueError("invalid native constant classification")
        if (not isinstance(node["type_repr"], str) or
                not isinstance(node["value_repr"], str)):
            raise ValueError("invalid native expression serialization")
        refs = node["references"]
        if not isinstance(refs, list) or any(
            not isinstance(x, str) or not _SYMBOL.fullmatch(x) for x in refs
        ) or len(set(refs)) != len(refs):
            raise ValueError("invalid native referenced constants")
        if not node["expanded"] and (
            node["type_repr"] or node["value_repr"] or refs
        ):
            raise ValueError("imported boundary must stay opaque")
        if node["expanded"] and not node["type_repr"]:
            raise ValueError("expanded constant has no native type")
        nodes[name] = node

    root = raw["root"]
    if root not in nodes or not nodes[root]["expanded"]:
        raise ValueError("theorem root absent or opaque")
    for node in nodes.values():
        if any(ref not in nodes for ref in node["references"]):
            raise ValueError("missing referenced native constant")

    # Require every emitted node to be transitively reachable from the root;
    # no silently dropped extra or substituted proof-support records.
    pending = [root]
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        pending.extend(nodes[name]["references"])
    if seen != set(nodes):
        raise ValueError("unexpected unreachable native support nodes")

    output: list[dict[str, Any]] = []
    imported: list[str] = []
    for name in sorted(nodes):
        node = nodes[name]
        semantic = {
            "name": name,
            "kind": node["kind"],
            "native_type_repr": node["type_repr"],
            "native_value_repr": node["value_repr"],
            "native_expanded": node["expanded"],
        }
        if not node["expanded"]:
            imported.append(name)
        output.append({
            "symbol": name,
            "semantic_sha256": _digest(semantic),
            "dependencies": sorted(node["references"]),
            "expanded_in_source_environment": node["expanded"],
        })
    return {
        "schema_version": "rtk.lean_native_support_projection.v1-development",
        "root_symbol": root,
        "source_probe_sha256": _digest(raw),
        "support_nodes": output,
        "imported_boundaries": imported,
        "support_claimed_complete": False,
        "semantic_serialization_soundness_established": False,
        "source_authenticity_verified": False,
        "applicability_proved": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-development-result", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    data = json.loads(args.native_development_result.read_text())
    if not isinstance(data, dict) or set(data) != {
        "schema_version", "checker_version", "checker_binary_sha256",
        "source", "target", "adjudication_is_independent",
        "semantic_support_complete", "development_only",
    }:
        parser.error("unexpected native development evidence structure")
    if data["checker_version"] != "4.14.0" or not (
        isinstance(data["checker_binary_sha256"], str)
        and _SHA.fullmatch(data["checker_binary_sha256"])
    ):
        parser.error("unsupported checker version/identity")
    if data["semantic_support_complete"] is not False or (
        data["adjudication_is_independent"] is not False
        or data["development_only"] is not True
    ):
        parser.error("invalid native development research classification")
    projections = {}
    for side in ("source", "target"):
        record = data[side]
        if not isinstance(record, dict) or set(record) != {
            "manifest", "native_log_sha256", "checked_input_sha256"
        }:
            parser.error("invalid native evidence payload")
        if any(not isinstance(record[k], str) or not _SHA.fullmatch(record[k])
               for k in ("native_log_sha256", "checked_input_sha256")):
            parser.error("invalid referenced native output identities")
        projections[side] = project_native_probe(record["manifest"])
    result = {
        "schema_version": "rtk.lean_native_support_pair.v1-development",
        "checker_binary_sha256": data["checker_binary_sha256"],
        "source": projections["source"],
        "target": projections["target"],
        "native_authenticity_verified": False,
        "semantic_completeness_proved": False,
        "native_oracle_independence_established": False,
    }
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print("LEAN_NATIVE_SUPPORT_INCOMPLETE_PROJECTION_CREATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
