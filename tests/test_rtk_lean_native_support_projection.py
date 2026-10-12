"""Development-only projection tests; synthetic records are not native evidence."""

from __future__ import annotations

from copy import deepcopy
import json
import sys

import pytest

from experiments.rtk.lean_native_support_projection import (
    main,
    project_native_probe,
)


def native_fixture(*, op_body: str = "Expr.bvar 0"):
    return {
        "schema_version": "rtk.lean_native_support_probe.v1-development",
        "root": "historical_claim",
        "imported_boundary_expansion_complete": False,
        "items": [
            {
                "symbol": "historical_claim",
                "kind": "theorem",
                "expanded": True,
                "imported_module": "",
                "type_repr": "Expr.app (Expr.const `op []) (Expr.bvar 0)",
                "value_repr": "Expr.const `Eq.refl []",
                "references": ["op", "Eq.refl", "Nat"],
            },
            {
                "symbol": "op",
                "kind": "definition",
                "expanded": True,
                "imported_module": "",
                "type_repr": "Expr.forallE Nat Nat",
                "value_repr": op_body,
                "references": ["Nat"],
            },
            {
                "symbol": "Eq.refl",
                "kind": "theorem",
                "expanded": False,
                "imported_module": "Init.Core",
                "type_repr": "",
                "value_repr": "",
                "references": [],
            },
            {
                "symbol": "Nat",
                "kind": "inductive",
                "expanded": False,
                "imported_module": "Init.Core",
                "type_repr": "",
                "value_repr": "",
                "references": [],
            },
        ],
    }


def test_native_projection_preserves_local_and_imported_boundaries():
    projected = project_native_probe(native_fixture())
    assert projected["root_symbol"] == "historical_claim"
    assert projected["imported_boundaries"] == ["Eq.refl", "Nat"]
    assert projected["imported_modules"] == {
        "Eq.refl": "Init.Core", "Nat": "Init.Core"
    }
    assert projected["support_claimed_complete"] is False
    assert projected["semantic_serialization_soundness_established"] is False
    assert projected["source_authenticity_verified"] is False
    assert projected["applicability_proved"] is False
    assert len(projected["support_nodes"]) == 4
    assert {x["symbol"] for x in projected["support_nodes"]} == {
        "historical_claim", "op", "Eq.refl", "Nat"
    }


def test_native_semantic_body_drift_changes_local_node_identity():
    source = project_native_probe(native_fixture())
    target = project_native_probe(native_fixture(op_body="Nat.zero_add"))
    def by_symbol(record):
        return {x["symbol"]: x for x in record["support_nodes"]}
    old, new = by_symbol(source), by_symbol(target)
    assert old["op"]["semantic_sha256"] != new["op"]["semantic_sha256"]
    assert old["historical_claim"]["semantic_sha256"] == (
        new["historical_claim"]["semantic_sha256"]
    )
    assert old["Eq.refl"]["semantic_sha256"] == new["Eq.refl"]["semantic_sha256"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda x: x.update({"imported_boundary_expansion_complete": True}),
         "completeness"),
        (lambda x: x["items"].append(deepcopy(x["items"][0])), "duplicate"),
        (lambda x: x["items"][0]["references"].append("Absent"), "missing referenced"),
        (lambda x: x["items"][2].update({"value_repr": "forged"}), "opaque"),
        (lambda x: x.update({"root": "Nat"}), "root"),
        (lambda x: x["items"].append({
            "symbol": "Unreachable", "kind": "definition",
            "expanded": True, "imported_module": "",
            "type_repr": "Nat", "value_repr": "Nat",
            "references": [],
        }), "unreachable"),
    ],
)
def test_native_projection_rejects_forged_or_missing_support(mutation, message):
    raw = native_fixture()
    mutation(raw)
    with pytest.raises(ValueError, match=message):
        project_native_probe(raw)


def test_unsupported_native_symbol_and_unexpected_fields_fail_closed():
    raw = native_fixture()
    raw["items"][0]["references"][0] = "@bad_symbol"
    with pytest.raises(ValueError, match="referenced"):
        project_native_probe(raw)
    raw = native_fixture()
    raw["oracle_label"] = "VALID"
    with pytest.raises(ValueError, match="schema"):
        project_native_probe(raw)


def test_lexical_equivalence_is_not_a_completeness_proof():
    source = project_native_probe(native_fixture())
    same = project_native_probe(native_fixture())
    assert source == same
    assert source["support_claimed_complete"] is False
    assert source["applicability_proved"] is False


def test_imported_module_origin_is_mandatory_and_bound_to_digest():
    base = native_fixture()
    alternate = deepcopy(base)
    alternate["items"][2]["imported_module"] = "Other.Module"
    old = project_native_probe(base)
    new = project_native_probe(alternate)
    src = {n["symbol"]: n for n in old["support_nodes"]}
    dst = {n["symbol"]: n for n in new["support_nodes"]}
    assert src["Eq.refl"]["semantic_sha256"] != dst["Eq.refl"]["semantic_sha256"]
    invalid = native_fixture()
    invalid["items"][2]["imported_module"] = ""
    with pytest.raises(ValueError, match="imported module"):
        project_native_probe(invalid)


def test_cli_refuses_unpinned_lean_binary(tmp_path, monkeypatch):
    payload = {
        "schema_version": "rtk.lean_native_support_probe.v1-development",
        "checker_version": "4.14.0",
        "checker_binary_sha256": "f" * 64,
        "source": {},
        "target": {},
        "adjudication_is_independent": False,
        "semantic_support_complete": False,
        "development_only": True,
    }
    path = tmp_path / "native.json"
    path.write_text(json.dumps(payload))
    monkeypatch.setattr(sys, "argv", [
        "projection", "--native-development-result", str(path),
        "--output", str(tmp_path / "out.json"),
    ])
    with pytest.raises(SystemExit):
        main()
    assert not (tmp_path / "out.json").exists()
