"""Tests for Sprint 6 source-profile hardening beyond scaffolding."""

from __future__ import annotations

from pathlib import Path

from ovk.compilers.authorization import FastApiAstAuthorizationCompiler, materials_from_pair
from ovk.compilers.infrastructure import compile_kubernetes_objects, compile_terraform_plan
from ovk.core.source_profile_evidence import (
    collect_source_profile_evidence,
    prove_actions_permissions_flow,
    prove_fastapi_ast_profile,
    prove_k8s_controller_profile,
    prove_terraform_recursive_profile,
)
from ovk.core.source_profiles import compiler_binding_for, source_profile_strict_eligible
from ovk.core.template_conformance import EXECUTABLE_CATALOG, build_conformance_matrix


def test_fastapi_ast_detects_admin_bypass() -> None:
    base = (
        "from fastapi import Depends, FastAPI\n"
        "def require_admin():\n"
        "    return 'admin'\n"
        "app = FastAPI()\n"
        "@app.get('/admin/users', dependencies=[Depends(require_admin)])\n"
        "def users():\n"
        "    return []\n"
    )
    head = "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/admin/users')\ndef users():\n    return []\n"
    materials = materials_from_pair(path="app.py", base_source=base, head_source=head)
    ir = FastApiAstAuthorizationCompiler().compile(materials)
    assert any("authorization.fastapi.ast_v1" in note for note in ir.warnings)
    assert any(route.admin_only_before and not route.admin_only_after for route in ir.routes)


def test_fastapi_ast_marks_dynamic_path_unsupported() -> None:
    source = (
        "from fastapi import FastAPI\napp = FastAPI()\npath = '/x'\n@app.get(path)\ndef handler():\n    return {}\n"
    )
    materials = materials_from_pair(path="app.py", base_source=source, head_source=source)
    ir = FastApiAstAuthorizationCompiler().compile(materials)
    assert any("dynamic_route_path" in item for item in ir.unsupported_constructs)


def test_terraform_recursive_child_modules() -> None:
    plan = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [],
                "child_modules": [
                    {
                        "address": "module.nested",
                        "resources": [
                            {
                                "address": "module.nested.aws_s3_bucket.data",
                                "type": "aws_s3_bucket",
                                "name": "data",
                                "values": {
                                    "tags": {"sensitivity": "confidential"},
                                    "acl": "public-read",
                                },
                            }
                        ],
                        "child_modules": [],
                    }
                ],
            }
        },
    }
    ir = compile_terraform_plan(plan)
    assert any("plan_recursive_v1" in note for note in ir.warnings)
    assert any(resource.resource_id.endswith("aws_s3_bucket.data") for resource in ir.resources)


def test_kubernetes_controller_selector_edge() -> None:
    objects = [
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "api", "namespace": "default"},
            "spec": {"type": "LoadBalancer", "selector": {"app": "api"}},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "api", "namespace": "default"},
            "spec": {
                "template": {
                    "metadata": {"labels": {"app": "api"}},
                    "spec": {"containers": [{"name": "api", "image": "api:1"}]},
                }
            },
        },
    ]
    ir = compile_kubernetes_objects(objects)
    assert any(edge.kind == "service_selector" for edge in ir.edges)
    assert any("controller_reachability_v1" in note for note in ir.warnings)


def test_profile_provers_and_bindings() -> None:
    repo = Path(__file__).resolve().parents[1]
    assert compiler_binding_for("authorization.fastapi.ast_v1")
    fastapi = prove_fastapi_ast_profile(repo, enforcement_test="tests/test_authorization_enforcement.py")
    assert fastapi.as_dict()["strict_eligible"] is True
    tf = prove_terraform_recursive_profile(repo, enforcement_test="tests/test_remaining_lane_enforcement.py")
    assert tf.as_dict()["strict_eligible"] is True
    k8s = prove_k8s_controller_profile(repo, enforcement_test="tests/test_remaining_lane_enforcement.py")
    assert k8s.as_dict()["strict_eligible"] is True
    actions = prove_actions_permissions_flow(repo, enforcement_test="tests/test_remaining_lane_enforcement.py")
    assert actions.as_dict()["strict_eligible"] is True


def test_template_v2_requires_semantic_evidence() -> None:
    repo = Path(__file__).resolve().parents[1]
    matrix = build_conformance_matrix(repo)
    assert "source_profile_evidence" in matrix
    by_id = {row["intent_id"]: row for row in matrix["templates"]}
    auth = by_id["no-admin-route-bypass"]
    assert auth["conformance_status_v2"] == "source_profile_strict_eligible"
    assert auth["source_profile_evidence"]["strict_eligible"] is True
    self_protection = by_id["agent-cannot-disable-own-ci-gate"]
    assert self_protection["conformance_status_v2"] == "executable_advisory"
    deployment = by_id["no-skipped-approval-state"]
    # Deployment remains advisory until an explicit trusted_profile material exists.
    assert deployment["conformance_status_v2"] == "executable_advisory"
    assert matrix["counts_by_status_v2"].get("externally_calibrated_strict", 0) == 0


def test_collect_evidence_covers_catalog_profiles() -> None:
    repo = Path(__file__).resolve().parents[1]
    evidence = collect_source_profile_evidence(repo, catalog_by_intent=EXECUTABLE_CATALOG)
    assert "no-admin-route-bypass" in evidence
    assert source_profile_strict_eligible(
        profile_id=evidence["no-admin-route-bypass"].profile_id,
        materials_trusted=evidence["no-admin-route-bypass"].materials_trusted,
        coverage_complete=evidence["no-admin-route-bypass"].coverage_complete,
        enforcement_test_present=evidence["no-admin-route-bypass"].enforcement_test_present,
    )
