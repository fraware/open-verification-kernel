"""Development tests for dual-install native Lean environment comparison.

Mocks the checker *digest constant* in disposable local filesystem fixtures.
These tests do not substitute for the pinned real Lean workflow or establish
transport soundness.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import experiments.rtk.lean_dual_installed_env_v1 as dual


def _info_log(root: str, imports: list[str], *, symbol: str = "historical_claim") -> str:
    nodes = [{
        "symbol": symbol,
        "kind": "axiom" if symbol.startswith("rtk_") else "theorem",
        "expanded": True,
        "imported_module": "",
        "type_repr": "Expr.claim_type",
        "value_repr": "" if symbol.startswith("rtk_") else "Expr.source_proof",
        "references": ["Eq.refl"],
    }, {
        "symbol": "Eq.refl",
        "kind": "constructor",
        "expanded": False,
        "imported_module": "Init.Prelude",
        "type_repr": "",
        "value_repr": "",
        "references": [],
    }]
    return "probe: info: RTK_NATIVE_SUPPORT_JSON=" + json.dumps({
        "schema_version": "rtk.lean_native_support_probe.v1-development",
        "root": root,
        "items": nodes,
        "imported_boundary_expansion_complete": False,
    })


def _refs(modules: list[str], *, typename: str = "Lean.Expr.type") -> str:
    return "probe: info: RTK_NATIVE_REFERENCE_JSON=" + json.dumps({
        "schema_version": "rtk.lean_imported_ref_lookup.v1-development",
        "environment_modules": modules,
        "items": [
            {
                "symbol": "Eq.refl", "module": "Init.Prelude",
                "kind": "constructor", "type_repr": typename,
            },
        ],
    })


def _installation(base: Path) -> tuple[Path, Path]:
    root = base / "toolchain"
    binary = root / "bin" / "lean"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"test-lean-pinned-executable")
    modules = root / "lib" / "lean" / "Init"
    modules.mkdir(parents=True)
    (modules / "Prelude.olean").write_bytes(b"pinned-prelude")
    (modules / "Core.olean").write_bytes(b"pinned-core")
    return root, binary


def _compare(source, target, *, source_types=None, target_types=None):
    source_root, source_lean = source
    target_root, target_lean = target
    return dual.compare_separately_installed_environments(
        source_root=source_root,
        target_root=target_root,
        source_lean=source_lean,
        target_lean=target_lean,
        source_native_log=_info_log("historical_claim", ["Init.Core", "Init.Prelude"]),
        source_refs_log=_refs(["Init.Core", "Init.Prelude"]),
        target_refs_log=_refs(["Init.Core", "Init.Prelude"]),
        target_unproved_goal_log=_info_log(
            "rtk_unproven_target_claim", ["Init.Core", "Init.Prelude"],
            symbol="rtk_unproven_target_claim",
        ),
    )


def test_two_distinct_matching_installations_do_not_imply_valid(monkeypatch, tmp_path):
    source = _installation(tmp_path / "source")
    target = _installation(tmp_path / "target")
    monkeypatch.setattr(dual, "_EXPECTED_LEAN_BINARY", hashlib.sha256(
        b"test-lean-pinned-executable"
    ).hexdigest())
    output = _compare(source, target)
    assert output["environment_byte_comparison"] == "BYTE_IDENTICAL"
    assert output["source_loaded_module_count"] == 2
    assert output["target_loaded_module_count"] == 2
    assert output["source_module_inventory_sha256"] == (
        output["target_module_inventory_sha256"]
    )
    assert output["transport_applicability"] == "UNDETERMINED"
    assert output["target_claim_established"] is False
    assert output["native_transport_oracle_executed"] is False
    assert output["independently_administered_builds_verified"] is False


def test_changed_target_imported_module_is_factual_drift(monkeypatch, tmp_path):
    source = _installation(tmp_path / "source")
    target = _installation(tmp_path / "target")
    monkeypatch.setattr(dual, "_EXPECTED_LEAN_BINARY", hashlib.sha256(
        b"test-lean-pinned-executable"
    ).hexdigest())
    (target[0] / "lib" / "lean" / "Init" / "Core.olean").write_bytes(b"changed-core")
    result = _compare(source, target)
    assert result["environment_byte_comparison"] == "DRIFT_DETECTED"
    assert result["changed_module_bytes"] == ["Init.Core"]
    assert result["transport_applicability"] == "UNDETERMINED"


def test_same_installation_is_rejected(monkeypatch, tmp_path):
    source = _installation(tmp_path / "source")
    monkeypatch.setattr(dual, "_EXPECTED_LEAN_BINARY", hashlib.sha256(
        b"test-lean-pinned-executable"
    ).hexdigest())
    with pytest.raises(ValueError, match="not distinct"):
        _compare(source, source)


def test_checker_binary_mismatch_rejected(tmp_path):
    source = _installation(tmp_path / "source")
    target = _installation(tmp_path / "target")
    with pytest.raises(ValueError, match="unregistered native"):
        _compare(source, target)


def test_hardlinked_olean_rejected(monkeypatch, tmp_path):
    source = _installation(tmp_path / "source")
    target = _installation(tmp_path / "target")
    monkeypatch.setattr(dual, "_EXPECTED_LEAN_BINARY", hashlib.sha256(
        b"test-lean-pinned-executable"
    ).hexdigest())
    old = target[0] / "lib" / "lean" / "Init" / "Core.olean"
    old.unlink()
    old.hardlink_to(source[0] / "lib" / "lean" / "Init" / "Core.olean")
    with pytest.raises(ValueError, match="share an imported"):
        _compare(source, target)


def test_symlinked_checker_or_toolchain_rejected(monkeypatch, tmp_path):
    source = _installation(tmp_path / "source")
    target = _installation(tmp_path / "target")
    monkeypatch.setattr(dual, "_EXPECTED_LEAN_BINARY", hashlib.sha256(
        b"test-lean-pinned-executable"
    ).hexdigest())
    alias = tmp_path / "source-link"
    alias.symlink_to(source[0], target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked"):
        _compare((alias, source[1]), target)


def test_historical_proof_absent_from_target_evidence_record(monkeypatch, tmp_path):
    source = _installation(tmp_path / "source")
    target = _installation(tmp_path / "target")
    monkeypatch.setattr(dual, "_EXPECTED_LEAN_BINARY", hashlib.sha256(
        b"test-lean-pinned-executable"
    ).hexdigest())
    result = _compare(source, target)
    assert result["fresh_target_proof_supplied"] is False
    assert result["historical_proof_replayed_on_target"] is False
    assert result["target_goal_is_unproved_axiom_placeholder"] is True
