"""Execute bounded source-profile proofs for template conformance v2.

Statuses such as ``source_profile_strict_eligible`` must derive from executed
semantic evidence (compiler runs on fixtures), not mere file presence.
``externally_calibrated_strict`` is never granted by local generation alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk.compilers.authorization.fastapi_ast import FastApiAstAuthorizationCompiler
from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.github_actions.permissions import extract_permissions, has_write_token
from ovk.compilers.github_actions.secrets import extract_secrets
from ovk.compilers.github_actions.trust_flow import compile_workflow_trust
from ovk.compilers.infrastructure.kubernetes import compile_kubernetes_objects
from ovk.compilers.infrastructure.terraform_plan import compile_terraform_plan
from ovk.core.source_profiles import (
    KNOWN_SOURCE_PROFILES,
    is_known_source_profile,
    source_profile_strict_eligible,
)


@dataclass(frozen=True)
class ProfileSemanticEvidence:
    profile_id: str
    materials_trusted: bool
    coverage_complete: bool
    enforcement_test_present: bool
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "materials_trusted": self.materials_trusted,
            "coverage_complete": self.coverage_complete,
            "enforcement_test_present": self.enforcement_test_present,
            "strict_eligible": source_profile_strict_eligible(
                profile_id=self.profile_id,
                materials_trusted=self.materials_trusted,
                coverage_complete=self.coverage_complete,
                enforcement_test_present=self.enforcement_test_present,
            ),
            "notes": list(self.notes),
        }


def _enforcement_present(repo_root: Path, relative: str | None) -> bool:
    return bool(relative) and (repo_root / relative).is_file()


def prove_fastapi_ast_profile(repo_root: Path, *, enforcement_test: str | None) -> ProfileSemanticEvidence:
    profile_id = "authorization.fastapi.ast_v1"
    base = (
        "from fastapi import Depends, FastAPI\n"
        "def require_admin():\n"
        "    return 'admin'\n"
        "app = FastAPI()\n"
        "@app.get('/admin/users', dependencies=[Depends(require_admin)])\n"
        "def users():\n"
        "    return []\n"
    )
    materials = materials_from_pair(path="app.py", base_source=base, head_source=base)
    ir = FastApiAstAuthorizationCompiler().compile(materials)
    profile_ok = any(profile_id in note for note in ir.warnings)
    coverage_complete = bool(ir.routes) and all(route.support == "supported" for route in ir.routes)
    notes = [
        f"routes={len(ir.routes)}",
        f"profile_marker={'yes' if profile_ok else 'no'}",
    ]
    return ProfileSemanticEvidence(
        profile_id=profile_id,
        materials_trusted=True,  # fixture materials authored for this proof
        coverage_complete=coverage_complete and profile_ok and not ir.unsupported_constructs,
        enforcement_test_present=_enforcement_present(repo_root, enforcement_test),
        notes=tuple(notes),
    )


def prove_terraform_recursive_profile(repo_root: Path, *, enforcement_test: str | None) -> ProfileSemanticEvidence:
    profile_id = "infrastructure.terraform.plan_recursive_v1"
    plan = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [],
                "child_modules": [
                    {
                        "address": "module.exports",
                        "resources": [
                            {
                                "address": "module.exports.aws_s3_bucket.data",
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
    profile_ok = any(profile_id in note for note in ir.warnings)
    coverage_complete = bool(ir.resources) and profile_ok
    return ProfileSemanticEvidence(
        profile_id=profile_id,
        materials_trusted=True,
        coverage_complete=coverage_complete,
        enforcement_test_present=_enforcement_present(repo_root, enforcement_test),
        notes=(f"resources={len(ir.resources)}", f"eligibility={ir.eligibility}"),
    )


def prove_k8s_controller_profile(repo_root: Path, *, enforcement_test: str | None) -> ProfileSemanticEvidence:
    profile_id = "infrastructure.kubernetes.controller_reachability_v1"
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
            "metadata": {
                "name": "api",
                "namespace": "default",
                "annotations": {"ovk.io/sensitivity": "confidential"},
            },
            "spec": {
                "template": {
                    "metadata": {"labels": {"app": "api"}},
                    "spec": {"containers": [{"name": "api", "image": "api:1"}]},
                }
            },
        },
    ]
    ir = compile_kubernetes_objects(objects)
    profile_ok = any(profile_id in note for note in ir.warnings)
    has_selector_edge = any(edge.kind == "service_selector" for edge in ir.edges)
    return ProfileSemanticEvidence(
        profile_id=profile_id,
        materials_trusted=True,
        coverage_complete=profile_ok and has_selector_edge,
        enforcement_test_present=_enforcement_present(repo_root, enforcement_test),
        notes=(f"edges={len(ir.edges)}", f"selector_edge={'yes' if has_selector_edge else 'no'}"),
    )


def prove_actions_permissions_flow(repo_root: Path, *, enforcement_test: str | None) -> ProfileSemanticEvidence:
    profile_id = "ci_secrets.actions.permissions_flow_v1"
    workflow = {
        "_ovk_path": "ci.yml",
        "on": {"pull_request_target": {}},
        "permissions": {"contents": "write"},
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "use secret",
                        "run": "echo ${{ secrets.DEPLOY_TOKEN }}",
                        "env": {"TOKEN": "${{ secrets.DEPLOY_TOKEN }}"},
                    }
                ],
            }
        },
    }
    ir = compile_workflow_trust(workflow)
    grants = extract_permissions(workflow)
    secrets = extract_secrets(workflow)
    write = has_write_token(grants)
    findings = list(ir.findings) if hasattr(ir, "findings") else []
    coverage_complete = bool(secrets) and write and (bool(findings) or bool(ir.edges))
    return ProfileSemanticEvidence(
        profile_id=profile_id,
        materials_trusted=True,
        coverage_complete=coverage_complete,
        enforcement_test_present=_enforcement_present(repo_root, enforcement_test),
        notes=(
            f"secrets={len(secrets)}",
            f"write_token={write}",
            f"findings={len(findings)}",
            f"compiled_with_source_profile:{profile_id}",
        ),
    )


def prove_deployment_trusted_profile(repo_root: Path, *, enforcement_test: str | None) -> ProfileSemanticEvidence:
    """Deployment strictness only when an explicit trusted profile marker is present."""
    profile_id = "deployment.trusted_profile_v1"
    # Without an explicit trusted profile material, coverage is incomplete by design.
    trusted_marker = repo_root / "examples" / "deployment_state" / "trusted_profile.v1.json"
    materials_trusted = trusted_marker.is_file()
    coverage_complete = False
    notes = ["requires explicit trusted_profile material for strictness"]
    if materials_trusted:
        try:
            from ovk.core.json_io import read_json_file

            payload = read_json_file(trusted_marker)
            coverage_complete = (
                isinstance(payload, dict)
                and payload.get("source_profile") == profile_id
                and payload.get("trusted") is True
            )
            notes = [f"trusted_marker={trusted_marker.as_posix()}"]
        except (OSError, ValueError) as exc:
            notes = [f"trusted_marker_unreadable:{exc}"]
            materials_trusted = False
    return ProfileSemanticEvidence(
        profile_id=profile_id,
        materials_trusted=materials_trusted,
        coverage_complete=coverage_complete,
        enforcement_test_present=_enforcement_present(repo_root, enforcement_test),
        notes=tuple(notes),
    )


_PROVERS = {
    "authorization.fastapi.ast_v1": prove_fastapi_ast_profile,
    "infrastructure.terraform.plan_recursive_v1": prove_terraform_recursive_profile,
    "infrastructure.kubernetes.controller_reachability_v1": prove_k8s_controller_profile,
    "ci_secrets.actions.permissions_flow_v1": prove_actions_permissions_flow,
    "deployment.trusted_profile_v1": prove_deployment_trusted_profile,
}


def collect_source_profile_evidence(
    repo_root: Path,
    *,
    catalog_by_intent: dict[str, dict[str, Any]],
) -> dict[str, ProfileSemanticEvidence]:
    """Run profile proofs for intents that declare a source_profile_id."""
    evidence: dict[str, ProfileSemanticEvidence] = {}
    for intent_id, entry in catalog_by_intent.items():
        profile_id = entry.get("source_profile_id")
        if not is_known_source_profile(str(profile_id) if profile_id else None):
            continue
        prover = _PROVERS.get(str(profile_id))
        if prover is None:
            evidence[intent_id] = ProfileSemanticEvidence(
                profile_id=str(profile_id),
                materials_trusted=False,
                coverage_complete=False,
                enforcement_test_present=False,
                notes=("no prover registered for profile",),
            )
            continue
        links = entry.get("links") or {}
        evidence[intent_id] = prover(
            repo_root,
            enforcement_test=str(links.get("enforcement_test") or "") or None,
        )
    return evidence


def evidence_payload(evidence: dict[str, ProfileSemanticEvidence]) -> dict[str, Any]:
    return {
        "schema_version": "ovk.source_profile_evidence.v1",
        "known_profiles": sorted(KNOWN_SOURCE_PROFILES),
        "intents": {intent: item.as_dict() for intent, item in sorted(evidence.items())},
    }
