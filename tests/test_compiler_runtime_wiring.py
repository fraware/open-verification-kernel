"""Tests proving source compilers participate in obligation_id and enforcement."""

from __future__ import annotations


from ovk.adapters.authorization import build_authorization_registry
from ovk.adapters.deployment import build_deployment_registry
from ovk.core.adapter_runtime import execute_obligations
from ovk.core.authorization_compiler import compile_authorization_obligation
from ovk.core.backend_control_plane import BackendControlPlane
from ovk.core.cbmc_compiler import compile_cbmc_obligation
from ovk.core.ci_secrets_compiler import compile_ci_secrets_obligation
from ovk.core.deployment_compiler import compile_deployment_obligation
from ovk.core.execution_models import ExecutionBudget, ExecutionContext
from ovk.core.infrastructure_compiler import compile_infrastructure_obligation
from ovk.core.router import RoutingConfig, route_obligation


def test_fastapi_source_compiler_changes_obligation_id_and_enforces() -> None:
    base = """
from fastapi import Depends, FastAPI
def require_admin():
    return "admin"
app = FastAPI()
@app.get("/admin/users", dependencies=[Depends(require_admin)])
def users():
    return []
""".strip()
    head = """
from fastapi import FastAPI
app = FastAPI()
@app.get("/admin/users")
def users():
    return []
""".strip()
    data = {
        "framework": "fastapi",
        "materials": {"path": "app.py", "base_source": base, "head_source": head},
        "author_type": "ai_agent",
        "agent": "test",
        "task": "bypass",
    }
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h", base_sha="b")
    assert obligation.compiler_id == "ovk.authorization.fastapi.v1"
    assert obligation.coverage.status in {"complete", "partial"}
    assert obligation.abstraction.get("source_compiler") == "ovk.authorization.fastapi.v1"
    assert any(m.kind == "source_file" for m in obligation.materials)

    # Obligation id must depend on compiled abstraction (compiler output is live).
    protected = compile_authorization_obligation(
        {
            "framework": "fastapi",
            "materials": {"path": "app.py", "base_source": base, "head_source": base},
        },
        repo="r",
        head_sha="h",
        base_sha="b",
    )
    assert obligation.obligation_id != protected.obligation_id

    evidence = execute_obligations(
        [{"lane": "authorization", "input": data, "intent_id": "no-admin-route-bypass"}],
        {},
        repo="r",
        head_sha="h",
        base_sha="b",
        use_cache=False,
        policy={"routing": {"mode": "shadow", "enforced_lanes": ["authorization"], "prefer_deterministic": True}},
    )[0]
    assert evidence.routing_enforced is True
    assert evidence.compiler and evidence.compiler["compiler_id"] == "ovk.authorization.fastapi.v1"
    assert evidence.decision["merge_recommendation"] == "block"


def test_incomplete_auth_abstraction_cannot_allow_under_strict() -> None:
    # Head-only materials => unknown coverage; even a "safe" head cannot allow.
    head = """
from fastapi import Depends, FastAPI
def require_admin():
    return "admin"
app = FastAPI()
@app.get("/admin", dependencies=[Depends(require_admin)])
def admin():
    return {}
""".strip()
    data = {
        "framework": "fastapi",
        "materials": {"path": "app.py", "base_source": None, "head_source": head},
    }
    obligation = compile_authorization_obligation(data, repo="r", head_sha="h")
    assert obligation.coverage.status == "unknown"
    assert obligation.abstraction.get("strict_allow_permitted") is False

    registry = build_authorization_registry()
    budget = ExecutionBudget(
        total_wall_time_seconds=30,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
        allowed_backends=["authorization-deterministic"],
    )
    context = ExecutionContext(subject=obligation.subject, budget=budget, policy_digest="p")
    routing = route_obligation(
        obligation,
        registry,
        context=context,
        config=RoutingConfig(
            prefer_deterministic=True,
            max_selected_backends=1,
            enforced_lanes=frozenset({"authorization"}),
            accept_partial_primary=True,
        ),
        policy={"budget": {"allowed_backends": ["authorization-deterministic"]}},
    )
    record = BackendControlPlane().execute(obligation, routing, registry=registry)
    from ovk.core.evidence_from_execution import execution_record_to_evidence

    evidence = execution_record_to_evidence(record, routing_enforced=True)
    assert evidence.decision["merge_recommendation"] != "allow"
    assert any(item.get("kind") == "incomplete_abstraction" for item in evidence.generated_artifacts) or (
        evidence.decision["merge_recommendation"] in {"require_human_review", "block", "require_stronger_check"}
    )


def test_terraform_plan_compiler_participates_in_obligation() -> None:
    data = {
        "terraform_plan": {
            "format_version": "1.2",
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.public",
                    "type": "aws_s3_bucket",
                    "change": {
                        "after": {
                            "acl": "public-read",
                            "tags": {"sensitivity": "confidential"},
                        }
                    },
                }
            ],
        }
    }
    obligation = compile_infrastructure_obligation(data, repo="r", head_sha="h")
    assert obligation.compiler_id == "ovk.infrastructure.terraform_plan.v1"
    assert obligation.abstraction.get("source_compiler")
    assert obligation.coverage.extracted_elements >= 1

    evidence = execute_obligations(
        [{"lane": "infrastructure", "input": data}],
        {},
        repo="r",
        head_sha="h",
        use_cache=False,
        policy={"routing": {"mode": "shadow", "enforced_lanes": ["infrastructure"], "prefer_deterministic": True}},
    )[0]
    assert evidence.compiler["compiler_id"] == "ovk.infrastructure.terraform_plan.v1"
    assert evidence.decision["merge_recommendation"] in {"block", "require_human_review"}


def test_github_actions_trust_compiler_in_ci_secrets_path() -> None:
    yaml_text = """
name: preview
on:
  pull_request_target:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo deploy
        env:
          KEY: ${{ secrets.DEPLOY_KEY }}
""".strip()
    data = {
        "trust_context": "untrusted_fork_pr",
        "workflows": [{"path": "preview.yml", "yaml": yaml_text}],
    }
    obligation = compile_ci_secrets_obligation(data, repo="r", head_sha="h")
    assert obligation.compiler_id == "ovk.github_actions.trust_flow.v1"
    assert obligation.abstraction.get("github_actions_irs")

    evidence = execute_obligations(
        [{"lane": "ci_secrets", "input": data}],
        {},
        repo="r",
        head_sha="h",
        use_cache=False,
        policy={"routing": {"mode": "shadow", "enforced_lanes": ["ci_secrets"], "prefer_deterministic": True}},
    )[0]
    assert evidence.compiler["compiler_id"] == "ovk.github_actions.trust_flow.v1"
    assert evidence.decision["merge_recommendation"] == "block"


def test_deployment_github_environments_compiler() -> None:
    data = {
        "environments": [
            {"name": "staging", "required_reviewers": 0},
            {"name": "production", "required_reviewers": 0, "production": True},
        ]
    }
    obligation = compile_deployment_obligation(data, repo="r", head_sha="h")
    assert obligation.compiler_id == "ovk.deployment.github_environments.v1"
    # Missing required reviewers on production path should surface as fail/review via state machine.
    registry = build_deployment_registry()
    budget = ExecutionBudget(
        total_wall_time_seconds=30,
        per_backend_wall_time_seconds=30,
        max_memory_mb=512,
        max_parallel_backends=1,
        allow_network=False,
        allow_repository_write=False,
    )
    routing = route_obligation(
        obligation,
        registry,
        context=ExecutionContext(subject=obligation.subject, budget=budget, policy_digest="p"),
        config=RoutingConfig(prefer_deterministic=True, max_selected_backends=1, enforced_lanes=frozenset({"deployment"})),
    )
    record = BackendControlPlane().execute(obligation, routing, registry=registry)
    assert record.results
    assert record.obligation.compiler_id == "ovk.deployment.github_environments.v1"


def test_cbmc_registration_honest_without_project_grounding() -> None:
    obligation = compile_cbmc_obligation({}, repo="r", head_sha="h")
    assert obligation.compiler_id == "ovk.cbmc.registry.v1"
    assert obligation.coverage.status == "unknown"
    assert obligation.abstraction.get("project_grounded") is False

    grounded = compile_cbmc_obligation(
        {
            "functions": [{"name": "foo", "file": "foo.c", "selected_reason": "changed"}],
            "harnesses": [
                {
                    "harness_id": "h1",
                    "entry_function": "harness",
                    "includes_project_code": True,
                    "traces_to_source_functions": ["foo"],
                }
            ],
        },
        repo="r",
        head_sha="h",
    )
    assert grounded.compiler_id == "ovk.cbmc.project_grounded.v1"
    assert grounded.coverage.status == "complete"
