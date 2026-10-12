"""Development-only tests; fabricated Lean records are NOT native witnesses."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments.rtk.lean_imported_proofrefs_v1 import (
    _extract_json,
    _environment_modules,
    _reference_record,
    generate_reference_probe,
    imported_olean_snapshot,
    source_imported_symbols,
)


def _native_source_log() -> str:
    raw = {
        "schema_version": "rtk.lean_native_support_probe.v1-development",
        "root": "historical_claim",
        "imported_boundary_expansion_complete": False,
        "items": [
            {
                "symbol": "historical_claim", "kind": "theorem",
                "expanded": True, "imported_module": "",
                "type_repr": "Expr forall", "value_repr": "Expr proof",
                "references": ["Eq.refl", "op"],
            },
            {
                "symbol": "Eq.refl", "kind": "theorem",
                "expanded": False, "imported_module": "Init.Core",
                "type_repr": "", "value_repr": "", "references": [],
            },
            {
                "symbol": "op", "kind": "definition", "expanded": True,
                "imported_module": "", "type_repr": "Nat -> Nat",
                "value_repr": "fun n => n", "references": [],
            },
        ],
    }
    return "file.lean:14:0: info: RTK_NATIVE_SUPPORT_JSON=" + json.dumps(raw)


def _references_log(*, module="Init.Core", typed="Eq proof type") -> str:
    raw = {
        "schema_version": "rtk.lean_imported_ref_lookup.v1-development",
        "environment_modules": ["Init.Prelude", "Init.Core"],
        "items": [
            {
                "symbol": "Eq.refl", "kind": "theorem",
                "module": module, "type_repr": typed,
            }
        ],
    }
    return "file.lean:1:0: info: RTK_NATIVE_REFERENCE_JSON=" + json.dumps(raw)


def test_source_only_generates_const_lookups_without_historical_proof():
    source = _native_source_log()
    assert source_imported_symbols(source) == {"Eq.refl": "Init.Core"}
    generated = generate_reference_probe(source)
    assert "env.find? symbol" in generated
    assert "`Eq.refl" in generated
    assert "Eq.refl n" not in generated
    assert "RTK_NATIVE_REFERENCE_JSON=" in generated
    assert "theorem historical_claim" not in generated


def test_native_reference_identity_and_type_must_match():
    expected = {"Eq.refl": "Init.Core"}
    result = _reference_record(_references_log(), expected)
    assert result["Eq.refl"]["type_repr"] == "Eq proof type"
    with pytest.raises(ValueError, match="wrong module"):
        _reference_record(_references_log(module="Other.Module"), expected)
    with pytest.raises(ValueError, match="untyped"):
        _reference_record(_references_log(typed=""), expected)
    with pytest.raises(ValueError, match="missing or extra"):
        _reference_record(
            "RTK_NATIVE_REFERENCE_JSON=" + json.dumps({
                "schema_version": "rtk.lean_imported_ref_lookup.v1-development",
                "environment_modules": ["Init.Prelude", "Init.Core"],
                "items": [],
            }),
            expected,
        )


def test_duplicate_native_marker_is_not_accepted():
    source = _native_source_log()
    with pytest.raises(ValueError, match="exactly one"):
        _extract_json(source + "\n" + source, "RTK_NATIVE_SUPPORT_JSON=")


def test_exact_installed_olean_bytes_are_hashed(tmp_path: Path):
    olean = tmp_path / "lib" / "lean" / "Init" / "Core.olean"
    olean.parent.mkdir(parents=True)
    olean.write_bytes(b"opaque native module example")
    result = imported_olean_snapshot({"Eq.refl": "Init.Core"}, tmp_path)
    assert result["Init.Core"]["file_sha256"] == hashlib.sha256(
        olean.read_bytes()
    ).hexdigest()
    assert result["Init.Core"]["relative_path"] == "lib/lean/Init/Core.olean"
    assert result["Init.Core"]["file_size_bytes"] == olean.stat().st_size
    olean.write_bytes(b"changed module bytes")
    second = imported_olean_snapshot({"Eq.refl": "Init.Core"}, tmp_path)
    assert result["Init.Core"]["file_sha256"] != second["Init.Core"]["file_sha256"]


def test_missing_redirected_or_escaping_module_fails_closed(tmp_path: Path):
    with pytest.raises(ValueError, match="missing"):
        imported_olean_snapshot({"Eq.refl": "Init.Core"}, tmp_path)
    module_dir = tmp_path / "lib" / "lean" / "Init"
    module_dir.mkdir(parents=True)
    external = tmp_path / "not-installed.olean"
    external.write_bytes(b"contents")
    (module_dir / "Core.olean").symlink_to(external)
    with pytest.raises(ValueError, match="redirected"):
        imported_olean_snapshot({"Eq.refl": "Init.Core"}, tmp_path)
    with pytest.raises(ValueError, match="module path"):
        imported_olean_snapshot({"Eq.refl": "../outside"}, tmp_path)


def test_reference_forgery_cannot_impersonate_native_root():
    source = _native_source_log().replace("Init.Core", "Other.Module")
    assert source_imported_symbols(source) == {"Eq.refl": "Other.Module"}
    with pytest.raises(ValueError, match="wrong module"):
        _reference_record(_references_log(), {"Eq.refl": "Other.Module"})


def test_loaded_native_module_inventory_is_deterministic_and_rejects_poisoned_names():
    assert _environment_modules(_references_log()) == [
        "Init.Core", "Init.Prelude"
    ]
    invalid = json.loads(_references_log().split("RTK_NATIVE_REFERENCE_JSON=", 1)[1])
    invalid["environment_modules"] = ["Init.Core", "Init.Core"]
    with pytest.raises(ValueError, match="duplicated"):
        _environment_modules("RTK_NATIVE_REFERENCE_JSON=" + json.dumps(invalid))
    invalid["environment_modules"] = ["../outside"]
    with pytest.raises(ValueError, match="invalid"):
        _environment_modules("RTK_NATIVE_REFERENCE_JSON=" + json.dumps(invalid))


def test_loaded_olean_snapshot_spans_all_named_modules(tmp_path):
    base = tmp_path / "lib" / "lean" / "Init"
    base.mkdir(parents=True)
    (base / "Core.olean").write_bytes(b"one")
    (base / "Prelude.olean").write_bytes(b"two")
    modules = imported_olean_snapshot({
        "Init.Core": "Init.Core", "Init.Prelude": "Init.Prelude"
    }, tmp_path)
    assert len(modules) == 2
    assert all(len(item["file_sha256"]) == 64 for item in modules.values())
