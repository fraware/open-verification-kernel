"""CLI tests for ovk verify-evidence."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ovk.adapters.infra.evidence import evaluate_infra_exposure
from ovk.cli import app
from ovk.core.authoritative_runtime import execute_authoritative_plan
from ovk.core.bundle import make_bundle
from ovk.core.json_io import read_json_file
from ovk.core.release_bundle import ReleaseBundlePaths, write_release_bundle
from ovk.core.routing_pipeline import build_authoritative_routing_plan


def test_verify_evidence_cli_accepts_valid_bundle(tmp_path: Path) -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
    obligations = [
        {"lane": "authorization", "intent_id": "no-admin-route-bypass", "input": data, "input_format": "infra"}
    ]
    policy = {
        "routing": {
            "mode": "shadow",
            "enforced_lanes": ["authorization"],
            "max_selected_backends": 1,
            "prefer_deterministic": True,
            "allow_fallback": False,
        },
        "budget": {"allowed_backends": ["authorization-deterministic"], "allow_network": False, "allow_repository_write": False, "max_memory_mb": 512},
    }
    plan = build_authoritative_routing_plan(obligations, policy=policy, repo="example/repo", head_sha="head", base_sha="base")
    evidence = execute_authoritative_plan(
        obligations, plan, repo="example/repo", head_sha="head", base_sha="base", use_cache=False, parallel=False, policy=policy
    )
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(make_bundle(evidence, enforce=True).model_dump(mode="json")), encoding="utf-8")
    result = CliRunner().invoke(app, ["verify-evidence", str(bundle_path)])
    assert result.exit_code == 0, result.stdout
    report = json.loads(result.stdout)
    assert report["valid"] is True
    assert report["schema_version"] == "ovk.verifier.report.v1"


def test_verify_evidence_cli_rejects_tampered_bundle(tmp_path: Path) -> None:
    data = json.loads(Path("examples/auth_regression/input_admin_protected.json").read_text(encoding="utf-8"))
    obligations = [
        {"lane": "authorization", "intent_id": "no-admin-route-bypass", "input": data, "input_format": "infra"}
    ]
    policy = {
        "routing": {"prefer_deterministic": True, "allow_fallback": False, "max_selected_backends": 1},
        "budget": {"allowed_backends": ["authorization-deterministic"], "max_memory_mb": 512},
    }
    plan = build_authoritative_routing_plan(obligations, policy=policy, repo="example/repo", head_sha="head")
    evidence = execute_authoritative_plan(
        obligations, plan, repo="example/repo", head_sha="head", use_cache=False, parallel=False, policy=policy
    )
    payload = make_bundle(evidence, enforce=True).model_dump(mode="json")
    payload["evidence"][0]["decision"]["decision_state"] = "allow"
    bundle_path = tmp_path / "tampered.json"
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")
    result = CliRunner().invoke(app, ["verify-evidence", str(bundle_path)])
    assert result.exit_code == 1


def test_validate_outputs_is_directory_form_of_same_tcb(tmp_path: Path) -> None:
    data = read_json_file(Path("examples/infrastructure_exposure/input_private_sensitive_resource.json"))
    bundle = make_bundle([evaluate_infra_exposure(data, repo="test/repo", head_sha="abc")])
    write_release_bundle(bundle, ReleaseBundlePaths(root=tmp_path))
    result = CliRunner().invoke(app, ["validate-outputs", str(tmp_path)])
    assert result.exit_code == 0, result.stdout
    verify = CliRunner().invoke(app, ["verify-evidence", str(tmp_path)])
    assert verify.exit_code == 0, verify.stdout
