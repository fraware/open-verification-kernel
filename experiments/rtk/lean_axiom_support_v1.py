"""Strict development comparison of native Lean declaration/axiom dependencies.

Native Lean.collectAxioms recursively visits declaration references, but
silently ignores unresolved names and does not prove a complete semantic,
axiom or policy support closure. This module reports observed deltas, never
admissible historical proof transport.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

_MARKER = "RTK_NATIVE_AXIOM_SUPPORT_JSON="
_SCHEMA = "rtk.lean_native_axiom_dependency.v1-development"
_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.'·]*$")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_record(native_log: str, expected_root: str, expected_kind: str) -> dict[str, Any]:
    entries = [line.split(_MARKER, 1)[1].strip()
               for line in native_log.splitlines() if _MARKER in line]
    if len(entries) != 1 or len(entries[0]) > 200_000:
        raise ValueError("expected exactly one bounded native axiom marker")
    try:
        data = json.loads(entries[0])
    except json.JSONDecodeError as error:
        raise ValueError("invalid Lean native axiom JSON") from error
    required = {
        "schema_version", "root_name", "root_kind", "op_name",
        "direct_root_references", "direct_op_references",
        "op_transitive_axioms", "source_proof_transitive_axioms",
        "synthetic_target_axiom_not_counted_as_proof",
        "transitive_dependency_closure_proved",
        "trusted_axiom_policy_authenticated",
        "historic_target_proof_replayed", "historical_applicability_established",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("unknown native axiom schema")
    if (
        data["schema_version"] != _SCHEMA
        or data["root_name"] != expected_root
        or data["root_kind"] != expected_kind
        or data["op_name"] != "op"
    ):
        raise ValueError("unexpected axiom proof/goal identity")
    if data["synthetic_target_axiom_not_counted_as_proof"] is not True:
        raise ValueError("target placeholder incorrectly used as proof")
    for field in (
        "transitive_dependency_closure_proved",
        "trusted_axiom_policy_authenticated",
        "historic_target_proof_replayed",
        "historical_applicability_established",
    ):
        if data[field] is not False:
            raise ValueError("unsupported closure, policy or oracle authority claim")

    for field in ("direct_root_references", "direct_op_references"):
        items = data[field]
        if (not isinstance(items, list) or len(items) > 8192
            or any(not isinstance(n, str) or not _SYMBOL.fullmatch(n)
                   for n in items)
            or len(items) != len(set(items))):
            raise ValueError("invalid direct native dependency references")
    for field in ("op_transitive_axioms", "source_proof_transitive_axioms"):
        axioms = data[field]
        if not isinstance(axioms, list) or len(axioms) > 8192:
            raise ValueError("invalid native axiom inventory")
        names: list[str] = []
        for record in axioms:
            if not isinstance(record, dict) or set(record) != {"name", "module", "kind"}:
                raise ValueError("invalid native axiom declaration")
            name, module, kind = record["name"], record["module"], record["kind"]
            if not isinstance(name, str) or not _SYMBOL.fullmatch(name) or (
                not isinstance(module, str) or (
                    module != "LOCAL" and not _SYMBOL.fullmatch(module)
                )
            ) or kind != "axiom":
                raise ValueError("untyped native axiom or module identity")
            if name == "sorryAx" or name.endswith(".sorryAx"):
                raise ValueError("Lean sorryAx dependency forbidden")
            names.append(name)
        if len(names) != len(set(names)):
            raise ValueError("duplicate native axiom names")
    if expected_kind == "unproved_goal_placeholder" and data[
        "source_proof_transitive_axioms"
    ]:
        raise ValueError("synthetic target goal returned a proof axiom set")
    return data


def _names(axioms: list[dict]) -> list[str]:
    return [x["name"] for x in axioms]


def compare_native_axiom_support(
    *,
    source_log: str, target_log: str,
    changed_target_log: str,
    environment: dict[str, Any],
) -> dict[str, Any]:
    source = _read_record(source_log, "historical_claim", "theorem")
    target = _read_record(
        target_log, "rtk_unproven_target_claim", "unproved_goal_placeholder"
    )
    changed = _read_record(
        changed_target_log, "rtk_unproven_target_claim", "unproved_goal_placeholder"
    )
    if (
        not isinstance(environment, dict)
        or environment.get("schema_version") !=
        "rtk.lean_dual_installed_environment.v1-development"
        or environment.get("target_claim_established") is not False
        or environment.get("historical_proof_replayed_on_target") is not False
        or environment.get("reliance_authorization") is not False
        or environment.get("transport_applicability") != "UNDETERMINED"
    ):
        raise ValueError("unqualified prior native environment record")
    modules = environment.get("target_modules")
    if not isinstance(modules, dict) or "RTKSemanticSupport" not in modules:
        raise ValueError("missing observed imported Lean module identity")

    for record in (source, target, changed):
        if "op" not in record["direct_root_references"]:
            raise ValueError("claim dependency on imported op is missing")
        for field in ("op_transitive_axioms", "source_proof_transitive_axioms"):
            for ax in record[field]:
                if ax["module"] not in ("LOCAL", *modules.keys()):
                    raise ValueError("axiom module absent from environment inventory")

    before = set(_names(target["op_transitive_axioms"]))
    after = set(_names(changed["op_transitive_axioms"]))
    introduced = sorted(after - before)
    removed = sorted(before - after)
    if "rtkExternal" not in introduced:
        raise ValueError("injected adversarial axiom not observed")
    if not any(
        a["name"] == "rtkExternal" and a["module"] == "RTKSemanticSupport"
        for a in changed["op_transitive_axioms"]
    ):
        raise ValueError("injected axiom has wrong imported module provenance")
    if "rtkExternal" in _names(source["source_proof_transitive_axioms"]):
        raise ValueError("target-only axiom leaked into source proof support")

    return {
        "schema_version": "rtk.lean_axiom_support_delta.v1-development",
        "source_proof_axioms": source["source_proof_transitive_axioms"],
        "source_imported_op_axioms": source["op_transitive_axioms"],
        "baseline_target_imported_op_axioms": target["op_transitive_axioms"],
        "mutated_target_imported_op_axioms": changed["op_transitive_axioms"],
        "injected_axioms": introduced,
        "removed_axioms": removed,
        "source_native_axiom_log_sha256": _hash(source_log.encode()),
        "target_native_axiom_log_sha256": _hash(target_log.encode()),
        "changed_target_native_axiom_log_sha256": _hash(changed_target_log.encode()),
        "baseline_target_environment_inventory_sha256":
            environment["target_module_inventory_sha256"],
        "source_proof_axiom_observation_present": True,
        "target_introduced_axiom_provenance_recorded": True,
        "conservative_action": "REVALIDATION_REQUIRED",
        "historical_evidence_applicability": "UNDETERMINED",
        "transitive_semantic_closure_proved": False,
        "trusted_axiom_policy_authenticated": False,
        "independent_native_attestation_verified": False,
        "target_historical_proof_replayed": False,
        "target_goal_established": False,
        "reliance_authorization": False,
        "development_fixture_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in (
        "source-log", "target-log", "changed-target-log",
        "prior-environment", "output",
    ):
        parser.add_argument("--" + key, type=Path, required=True)
    args = parser.parse_args()
    result = compare_native_axiom_support(
        source_log=args.source_log.read_text(),
        target_log=args.target_log.read_text(),
        changed_target_log=args.changed_target_log.read_text(),
        environment=json.loads(args.prior_environment.read_text()),
    )
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("LEAN_NATIVE_AXIOM_DELTA_DEVELOPMENT_NO_VALID_REUSE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
