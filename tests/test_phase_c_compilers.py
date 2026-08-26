"""Phase C bounded compiler semantics (WP-06..12)."""

from __future__ import annotations

from ovk.compilers.authorization import (
    ExpressAstAuthorizationCompiler,
    ExpressAuthorizationCompiler,
    FastApiAstAuthorizationCompiler,
    materials_from_pair,
)
from ovk.compilers.cbmc.project import CbmcHarness, CbmcProject
from ovk.compilers.deployment.deployment_state import compile_deployment_state
from ovk.compilers.github_actions.matrix import evaluate_matrix
from ovk.compilers.github_actions.reusable_workflows import parse_uses
from ovk.compilers.infrastructure.kubernetes import compile_kubernetes_objects
from ovk.compilers.infrastructure.terraform_plan import compile_terraform_plan
from ovk.core.compiler_bridge import compile_authorization_ir, compile_deployment_ir
from ovk.core.source_profiles import compiler_binding_for


def test_fastapi_module_graph_rejects_heuristic_admin() -> None:
    source = (
        "from fastapi import FastAPI, Depends\n"
        "def maybe_admin():\n"
        "    # admin helper by comment only\n"
        "    return True\n"
        "app = FastAPI()\n"
        "@app.get('/admin')\n"
        "def admin(user=Depends(maybe_admin)):\n"
        "    return {}\n"
    )
    materials = materials_from_pair(path="app.py", base_source=source, head_source=source)
    ir = FastApiAstAuthorizationCompiler().compile(materials)
    assert any("unknown_auth_wrapper" in item for item in ir.unsupported_constructs)
    assert all(not route.admin_only_after for route in ir.routes)


def test_express_ast_is_production_binding() -> None:
    assert "express_ast" in (compiler_binding_for("authorization.express.ast_v1") or "")
    source = (
        "const express = require('express');\n"
        "const { requireAdmin } = require('./auth');\n"
        "const app = express();\n"
        "app.get('/admin', requireAdmin, (req, res) => res.send('ok'));\n"
    )
    materials = materials_from_pair(path="app.js", base_source=source, head_source=source)
    ir = ExpressAstAuthorizationCompiler().compile(materials)
    assert any("authorization.express.ast_v1" in w for w in ir.warnings)
    assert any(route.admin_only_after for route in ir.routes)
    advisory = ExpressAuthorizationCompiler().compile(materials)
    assert "regex_compiler_advisory_only" in advisory.unsupported_constructs


def test_express_ast_path_segment_not_middleware() -> None:
    base = (
        "const express = require('express');\n"
        "const { requireAdmin } = require('./auth');\n"
        "const app = express();\n"
        "app.get('/admin', requireAdmin, (req, res) => res.end());\n"
    )
    head = (
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/admin', (req, res) => res.end());\n"
    )
    materials = materials_from_pair(path="app.js", base_source=base, head_source=head)
    ir = ExpressAstAuthorizationCompiler().compile(materials)
    assert any(route.admin_only_before and not route.admin_only_after for route in ir.routes)
    assert any("ovk.estree.subset.v2" in w for w in ir.warnings)


def test_terraform_after_unknown_forces_review_not_private() -> None:
    plan = {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "aws_security_group.web",
                "type": "aws_security_group",
                "change": {
                    "actions": ["update"],
                    "after": None,
                    "after_unknown": {"ingress": True, "cidr_blocks": True},
                },
            }
        ],
    }
    ir = compile_terraform_plan(plan)
    assert any("after_unknown" in item for item in ir.unsupported_constructs)
    assert ir.resources
    assert ir.resources[0].attributes.get("exposure_status") == "unknown_requires_review"
    assert ir.resources[0].public_exposure is False


def test_k8s_gateway_httproute_and_networkpolicy() -> None:
    objects = [
        {
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {"name": "gw", "namespace": "ns"},
            "spec": {
                "gatewayClassName": "istio",
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}],
                "addresses": [{"type": "IPAddress", "value": "1.2.3.4"}],
            },
        },
        {
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {"name": "route", "namespace": "ns"},
            "spec": {
                "parentRefs": [{"name": "gw"}],
                "rules": [{"backendRefs": [{"name": "svc", "port": 80}]}],
            },
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "deny", "namespace": "ns"},
            "spec": {"policyTypes": ["Ingress"], "podSelector": {}, "ingress": []},
        },
    ]
    ir = compile_kubernetes_objects(objects)
    assert any(e.kind == "gateway_parent_ref" for e in ir.edges)
    assert any(e.kind == "httproute_backend_ref" for e in ir.edges)
    np = next(r for r in ir.resources if r.resource_type == "NetworkPolicy")
    assert np.attributes.get("default_deny_ingress") is True


def test_actions_matrix_and_remote_sha() -> None:
    combos, unsupported = evaluate_matrix({"matrix": {"os": ["ubuntu", "windows"], "py": ["3.11", "3.12"]}})
    assert len(combos) == 4
    assert unsupported == []
    pinned = parse_uses("org/repo/.github/workflows/x.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert pinned.digest is not None
    assert pinned.mutable_ref is False
    mutable = parse_uses("org/repo/.github/workflows/x.yml@main")
    assert mutable.mutable_ref is True


def test_deployment_state_rejects_untrusted_approved() -> None:
    ir = compile_deployment_state({"approved": True, "schema_version": "ovk.deployment_state.v1"})
    assert "untrusted_approved_true_json" in ir.unsupported_constructs

    document = {
        "schema_version": "ovk.deployment_state.v1",
        "system_identity": "deployer-1",
        "environment": "prod",
        "revision": "sha256:abc",
        "signature": "sig",
        "prior_state": "staging",
        "required_gates": ["approved"],
        "production_states": ["production"],
        "events": [
            {"to": "approved", "actor": "alice", "approvals": ["alice"]},
            {"to": "production", "actor": "alice", "approvals": ["alice"]},
        ],
        # Deliberately adversarial: this embedded bit is diagnostic material only
        # and must never bootstrap trust in the document being evaluated.
        "_ovk_acquisition": {"trusted": True, "signature_ref": "sig"},
    }
    self_asserted = compile_deployment_state(document)
    assert "untrusted_deployment_state_acquisition" in self_asserted.unsupported_constructs

    # Only a caller that already authenticated the acquisition against an
    # external trust root may inject the trust result into compilation.
    authenticated = compile_deployment_state(document, acquisition_trusted=True)
    assert not authenticated.unsupported_constructs
    assert any(t.target == "production" for t in authenticated.transitions)


def test_cbmc_project_requires_unwind_and_tus() -> None:
    weak = CbmcProject(
        compile_commands_path="compile_commands.json",
        functions=[{"name": "foo", "selected_reason": "test"}],
        harnesses=[CbmcHarness(harness_id="h1", entry_function="foo", includes_project_code=True, bound=None)],
        source_roots=["src"],
    )
    assert weak.declare_guarantee() == "bounded_harness_model_check"
    strong = CbmcProject(
        compile_commands_path="compile_commands.json",
        functions=[{"name": "foo", "selected_reason": "test"}],
        harnesses=[CbmcHarness(harness_id="h1", entry_function="foo", includes_project_code=True, bound=8)],
        source_roots=["src"],
    )
    assert strong.declare_guarantee() == "bounded_project_model_check"


def test_bridge_express_uses_ast_profile() -> None:
    result = compile_authorization_ir(
        {
            "framework": "express",
            "materials": {
                "path": "app.js",
                "base_source": "const app = require('express')();\napp.get('/x', (req,res)=>res.end());\n",
                "head_source": "const app = require('express')();\napp.get('/x', (req,res)=>res.end());\n",
            },
        }
    )
    assert result is not None
    assert "express.profile:authorization.express.ast_v1" in result[2]


def test_bridge_deployment_state_preferred() -> None:
    result = compile_deployment_ir(
        {
            "schema_version": "ovk.deployment_state.v1",
            "system_identity": "s",
            "environment": "e",
            "revision": "r",
            "events": [],
            "signature": "x",
            "_ovk_acquisition": {"trusted": True},
        }
    )
    assert result is not None
    assert result[1] == "ovk.deployment.deployment_state.v1"
