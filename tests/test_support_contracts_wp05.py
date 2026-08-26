"""WP-05 support contracts, qualification generation, and compiler bridge wiring."""

from __future__ import annotations

import json
from pathlib import Path

from ovk.compilers.authorization import FastApiAstAuthorizationCompiler, materials_from_pair
from ovk.core.compiler_bridge import compile_authorization_ir
from ovk.core.source_profile_qualification import (
    build_source_profile_qualification,
    write_source_profile_qualification,
)
from ovk.core.source_profiles import KNOWN_SOURCE_PROFILES
from ovk.core.support_contracts import load_all_support_contracts, load_support_contract

REPO = Path(__file__).resolve().parents[1]


def test_all_known_profiles_have_support_contracts() -> None:
    contracts = load_all_support_contracts(repo_root=REPO)
    assert set(contracts) == set(KNOWN_SOURCE_PROFILES)
    for profile_id, contract in contracts.items():
        assert contract.contract_version
        assert contract.required_materials
        loaded = load_support_contract(profile_id, repo_root=REPO)
        assert loaded.profile_id == profile_id


def test_support_contract_forces_review_on_unsupported() -> None:
    contract = load_support_contract("authorization.fastapi.ast_v1", repo_root=REPO)
    raw = json.loads(
        (REPO / "profiles" / "authorization.fastapi.ast_v1" / "support-contract.json").read_text(
            encoding="utf-8"
        )
    )
    assert raw["coverage_criteria"]["unsupported_forces"] == "review"
    assert contract.compiler_binding.endswith("FastApiAstAuthorizationCompiler")


def test_qualification_counts_are_derived_not_hand_typed() -> None:
    payload = build_source_profile_qualification(REPO)
    assert payload["schema_version"] == "ovk.source_profile_qualification.v1"
    assert payload["maturity_contract"]["counts_are_hand_typed"] is False
    assert payload["maturity_contract"]["externally_calibrated_strict_locally_derivable"] is False
    fastapi = payload["profiles"]["authorization.fastapi.ast_v1"]
    assert fastapi["qualification"]["support_contract_version"] == "1.0.0"
    assert fastapi["evidence_count"] == len(fastapi["evidence"])
    assert fastapi["qualification"]["positive_cases"] == sum(
        1 for item in fastapi["evidence"] if item["bucket"] == "positive"
    )
    # Machine corpus meets WP-05 strict thresholds; external calibration remains non-local.
    assert fastapi["qualification"]["strict_ready"] is True
    assert fastapi["maturity"] == "source_profile_strict_eligible"
    assert fastapi["maturity"] != "externally_calibrated_strict"
    assert all(
        row["maturity"] != "externally_calibrated_strict" for row in payload["profiles"].values()
    )


def test_write_qualification_artifact(tmp_path: Path) -> None:
    out = tmp_path / "source-profile-qualification.json"
    payload = write_source_profile_qualification(REPO, out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded == payload
    assert set(loaded["profiles"]) == set(KNOWN_SOURCE_PROFILES)


def test_compiler_bridge_uses_fastapi_ast_not_regex() -> None:
    materials_data = {
        "framework": "fastapi",
        "materials": {
            "path": "app.py",
            "base_source": "from fastapi import FastAPI, Depends\napp = FastAPI()\n",
            "head_source": (
                "from fastapi import FastAPI, Depends\n"
                "app = FastAPI()\n"
                "def require_admin():\n    return True\n"
                "@app.get('/admin')\n"
                "def admin(user=Depends(require_admin)):\n    return {}\n"
            ),
        },
    }
    result = compile_authorization_ir(materials_data)
    assert result is not None
    ir, coverage, compiler_id, _materials = result
    assert "fastapi.profile:authorization.fastapi.ast_v1" in compiler_id
    assert "regex_advisory" not in compiler_id
    assert isinstance(
        FastApiAstAuthorizationCompiler().compile(
            materials_from_pair(
                path="app.py",
                base_source=materials_data["materials"]["base_source"],
                head_source=materials_data["materials"]["head_source"],
            )
        ),
        type(ir),
    )
    assert coverage is not None


def test_compiler_bridge_advisory_mode_keeps_regex() -> None:
    materials_data = {
        "framework": "fastapi",
        "compiler_mode": "advisory",
        "materials": {
            "path": "app.py",
            "base_source": "from fastapi import FastAPI\napp = FastAPI()\n",
            "head_source": "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/x')\ndef x():\n  return 1\n",
        },
    }
    result = compile_authorization_ir(materials_data, advisory=True)
    assert result is not None
    _ir, _coverage, compiler_id, _ = result
    assert compiler_id == "ovk.authorization.fastapi.regex_advisory.v1"


def test_conformance_matrix_declares_v3_normative() -> None:
    from ovk.core.template_conformance_v3 import build_conformance_matrix, validate_matrix

    matrix = build_conformance_matrix(REPO)
    assert matrix["maturity_contract"]["normative_status_field"] == "conformance_status_v3"
    assert validate_matrix(matrix) == []
    # Support contract version should appear on profile-backed rows when contracts exist.
    profile_rows = [
        row
        for row in matrix["templates"]
        if isinstance(row, dict) and row.get("source_profile_id") and row.get("source_profile_qualification")
    ]
    assert profile_rows
    assert any(
        (row.get("source_profile_qualification") or {}).get("support_contract_version") == "1.0.0"
        for row in profile_rows
    )
