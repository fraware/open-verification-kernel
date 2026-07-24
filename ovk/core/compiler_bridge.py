"""Bridge source-grounded compilers into neutral obligation compilation.

Compilers in ``ovk.compilers.*`` produce typed IRs. This module detects when
base/head (or plan/manifest/workflow) materials are present and routes through
those compilers. Legacy pre-normalized abstractions remain supported when no
source materials are supplied — they are not silently upgraded to claim
source-grounded coverage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ovk.compilers.authorization import (
    CoveragePolicy,
    ExpressAuthorizationCompiler,
    FastApiAuthorizationCompiler,
    assess_coverage,
    materials_from_pair,
)
from ovk.compilers.authorization.ir import AuthorizationIR
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.cbmc import CbmcProject, guarantee_implies_project_code
from ovk.compilers.deployment import (
    compile_argo_rollouts,
    compile_explicit_schema,
    compile_github_environments,
)
from ovk.compilers.deployment.ir import DeploymentIR
from ovk.compilers.github_actions import compile_workflow_trust, load_workflow_text
from ovk.compilers.github_actions.ir import GitHubActionsIR
from ovk.compilers.infrastructure import compile_kubernetes_objects, compile_terraform_plan
from ovk.compilers.infrastructure.ir import InfrastructureIR
from ovk.core.execution_models import AbstractionCoverage, MaterialReference
from ovk.core.materials import material_reference_from_payload


def coverage_policy_from_dict(policy: dict[str, Any] | None) -> CoveragePolicy:
    """Build authorization coverage policy from repository policy."""
    policy = policy or {}
    section = policy.get("coverage") if isinstance(policy.get("coverage"), dict) else {}
    routing = policy.get("routing") if isinstance(policy.get("routing"), dict) else {}
    accept = bool(
        section.get(
            "accept_partial_coverage",
            routing.get("accept_partial_coverage", routing.get("accept_partial_primary", False)),
        )
    )
    return CoveragePolicy(accept_partial_coverage=accept)


def extract_auth_materials(
    data: dict[str, Any],
    *,
    repo: str | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> AuthMaterials | None:
    """Extract base/head authorization materials when explicitly provided.

    Supported shapes:
    * ``materials``: ``{path, base_source, head_source}``
    * ``source_files``: ``{base: {path: text}, head: {path: text}}``
    * ``base_dir`` / ``head_dir`` filesystem roots
    """
    materials = data.get("materials")
    if isinstance(materials, dict) and (
        materials.get("base_source") is not None or materials.get("head_source") is not None
    ):
        path = str(materials.get("path") or "app.py")
        return materials_from_pair(
            path=path,
            base_source=materials.get("base_source"),
            head_source=materials.get("head_source"),
            repo=repo,
            base_revision=base_sha,
            head_revision=head_sha,
        )

    source_files = data.get("source_files")
    if isinstance(source_files, dict):
        base = source_files.get("base") if isinstance(source_files.get("base"), dict) else {}
        head = source_files.get("head") if isinstance(source_files.get("head"), dict) else {}
        if base or head:
            return AuthMaterials(
                base_files={str(k): str(v) for k, v in base.items()},
                head_files={str(k): str(v) for k, v in head.items()},
                repo=repo,
                base_revision=base_sha,
                head_revision=head_sha,
            )

    base_dir = data.get("base_dir")
    head_dir = data.get("head_dir")
    if base_dir or head_dir:
        from ovk.compilers.authorization.material_loader import load_materials_from_dirs

        return load_materials_from_dirs(
            base_dir=Path(str(base_dir)) if base_dir else None,
            head_dir=Path(str(head_dir)) if head_dir else None,
            repo=repo,
            base_revision=base_sha,
            head_revision=head_sha,
        )
    return None


def compile_authorization_ir(
    data: dict[str, Any],
    *,
    repo: str | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
    coverage_policy: CoveragePolicy | None = None,
) -> tuple[AuthorizationIR, AbstractionCoverage, str, AuthMaterials] | None:
    """Compile FastAPI/Express sources when materials are present."""
    materials = extract_auth_materials(data, repo=repo, base_sha=base_sha, head_sha=head_sha)
    if materials is None:
        return None

    framework = str(data.get("framework") or "").lower()
    if not framework:
        sample = " ".join(list(materials.head_files.values())[:1] + list(materials.base_files.values())[:1])
        if "fastapi" in sample.lower() or "APIRouter" in sample:
            framework = "fastapi"
        elif "express" in sample.lower() or "require(" in sample:
            framework = "express"
        else:
            # Prefer fastapi for .py, express for .js/.ts
            paths = materials.paths
            if any(p.endswith((".js", ".ts", ".mjs", ".cjs")) for p in paths):
                framework = "express"
            else:
                framework = "fastapi"

    if framework == "express":
        ir = ExpressAuthorizationCompiler().compile(materials)
        compiler_id = "ovk.authorization.express.v1"
    else:
        ir = FastApiAuthorizationCompiler().compile(materials)
        compiler_id = "ovk.authorization.fastapi.v1"

    coverage = assess_coverage(ir, materials, policy=coverage_policy)
    return ir, coverage, compiler_id, materials


def compile_infrastructure_ir(data: dict[str, Any]) -> tuple[InfrastructureIR, str] | None:
    """Compile terraform plan or kubernetes objects when present."""
    if isinstance(data.get("terraform_plan"), dict):
        return compile_terraform_plan(data["terraform_plan"]), "ovk.infrastructure.terraform_plan.v1"
    if isinstance(data.get("kubernetes"), (list, dict)):
        return compile_kubernetes_objects(data["kubernetes"]), "ovk.infrastructure.kubernetes.v1"
    if isinstance(data.get("k8s_objects"), (list, dict)):
        return compile_kubernetes_objects(data["k8s_objects"]), "ovk.infrastructure.kubernetes.v1"
    return None


def infrastructure_coverage(ir: InfrastructureIR) -> AbstractionCoverage:
    """Documented coverage from infrastructure IR eligibility."""
    extracted = len(ir.resources)
    if ir.unsupported_constructs and extracted == 0:
        return AbstractionCoverage(
            status="unknown",
            confidence=0.0,
            extracted_elements=0,
            expected_elements=None,
            unsupported_constructs=list(ir.unsupported_constructs),
            warnings=list(ir.warnings),
        )
    if ir.eligibility != "strict" or ir.unsupported_constructs or ir.warnings:
        return AbstractionCoverage(
            status="partial",
            confidence=0.5 if ir.resources else 0.2,
            extracted_elements=extracted,
            expected_elements=extracted or None,
            unsupported_constructs=list(ir.unsupported_constructs),
            warnings=list(ir.warnings) + list(ir.eligibility_reasons),
        )
    return AbstractionCoverage(
        status="complete" if extracted else "unknown",
        confidence=1.0 if extracted else 0.0,
        extracted_elements=extracted,
        expected_elements=extracted,
        unsupported_constructs=[],
        warnings=list(ir.warnings),
    )


def compile_deployment_ir(data: dict[str, Any]) -> tuple[DeploymentIR, str] | None:
    """Select deployment source compiler from materials present."""
    if isinstance(data.get("environments"), list):
        return compile_github_environments(data), "ovk.deployment.github_environments.v1"
    if isinstance(data.get("argo_rollouts"), dict) or data.get("kind") == "Rollout":
        payload = data.get("argo_rollouts") if isinstance(data.get("argo_rollouts"), dict) else data
        return compile_argo_rollouts(payload), "ovk.deployment.argo_rollouts.v1"
    if isinstance(data.get("states"), list) or isinstance(data.get("transitions"), list):
        return compile_explicit_schema(data), "ovk.deployment.explicit_schema.v1"
    return None


def deployment_coverage(ir: DeploymentIR) -> AbstractionCoverage:
    has_states = bool(ir.states)
    has_transitions = bool(ir.transitions)
    warnings = list(ir.warnings)
    unsupported = list(ir.unsupported_constructs)
    extracted = len(ir.states) + len(ir.transitions)
    if has_states and has_transitions and not unsupported:
        return AbstractionCoverage(
            status="complete",
            confidence=1.0,
            extracted_elements=extracted,
            expected_elements=extracted,
            warnings=warnings,
        )
    if has_states or has_transitions:
        return AbstractionCoverage(
            status="partial",
            confidence=0.4,
            extracted_elements=extracted,
            expected_elements=None,
            unsupported_constructs=unsupported,
            warnings=warnings,
        )
    return AbstractionCoverage(
        status="unknown",
        confidence=0.0,
        extracted_elements=0,
        expected_elements=None,
        unsupported_constructs=unsupported,
        warnings=warnings or ["state machine abstraction missing"],
    )


def compile_github_actions_irs(
    data: dict[str, Any],
    *,
    repo_root: Path | None = None,
) -> list[GitHubActionsIR]:
    """Compile workflow YAML documents or structured workflow entries."""
    irs: list[GitHubActionsIR] = []
    workflows = data.get("workflows")
    if not isinstance(workflows, list):
        return irs
    for item in workflows:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("yaml"), str):
            document = load_workflow_text(item["yaml"], path=str(item.get("path") or "workflow.yml"))
            irs.append(compile_workflow_trust(document, repo_root=repo_root))
        elif isinstance(item.get("document"), dict):
            document = dict(item["document"])
            document.setdefault("_ovk_path", str(item.get("path") or "workflow.yml"))
            irs.append(compile_workflow_trust(document, repo_root=repo_root))
        elif "on" in item or "jobs" in item:
            document = dict(item)
            document.setdefault("_ovk_path", str(item.get("_ovk_path") or item.get("path") or "workflow.yml"))
            irs.append(compile_workflow_trust(document, repo_root=repo_root))
    return irs


def github_actions_to_lane_input(
    irs: list[GitHubActionsIR],
    *,
    trust_context: str,
    legacy_workflows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Project trust-flow IRs into the CI-secrets lane abstraction."""
    workflows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    unsupported: list[str] = []
    warnings: list[str] = []
    for ir in irs:
        unsupported.extend(ir.unsupported_constructs)
        warnings.extend(ir.warnings)
        for finding in ir.findings:
            findings.append(finding.model_dump(mode="json"))
        for ref in ir.workflows or []:
            path = ref.path if hasattr(ref, "path") else str(ref)
            secret_finding = any(
                f.kind
                in {
                    "untrusted_code_with_secret",
                    "untrusted_code_with_write_token",
                    "untrusted_code_with_protected_env",
                    "untrusted_code_with_privileged_capability",
                    "secrets_inherit",
                }
                for f in ir.findings
            )
            triggers = []
            for node in ir.nodes:
                if node.kind == "workflow":
                    triggers.extend(node.labels)
            workflows.append(
                {
                    "workflow_id": path,
                    "triggers": sorted(set(triggers)) or ["pull_request"],
                    "uses_secrets": secret_finding or bool(ir.secrets),
                    "trust_findings": [f.model_dump(mode="json") for f in ir.findings],
                }
            )
    if not workflows and legacy_workflows:
        workflows = list(legacy_workflows)
    return {
        "trust_context": trust_context,
        "workflows": workflows,
        "trust_findings": findings,
        "unsupported_constructs": sorted(set(unsupported)),
        "warnings": warnings,
        "compiler": "ovk.github_actions.trust_flow.v1",
    }


def github_actions_coverage(irs: list[GitHubActionsIR], *, workflow_count: int) -> AbstractionCoverage:
    if not irs and workflow_count == 0:
        return AbstractionCoverage(
            status="unknown",
            confidence=0.0,
            extracted_elements=0,
            expected_elements=None,
            warnings=["workflow abstraction missing or empty"],
        )
    unsupported = [item for ir in irs for item in ir.unsupported_constructs]
    warnings = [item for ir in irs for item in ir.warnings]
    extracted = max(workflow_count, len(irs))
    if unsupported:
        return AbstractionCoverage(
            status="partial",
            confidence=0.5,
            extracted_elements=extracted,
            expected_elements=extracted,
            unsupported_constructs=sorted(set(unsupported)),
            warnings=warnings,
        )
    return AbstractionCoverage(
        status="complete" if extracted else "unknown",
        confidence=1.0 if extracted else 0.0,
        extracted_elements=extracted,
        expected_elements=extracted,
        warnings=warnings,
    )


def material_refs_from_digest(
    *,
    material_id: str,
    kind: str,
    uri: str,
    payload: Any,
    source_revision: str | None,
    trusted: bool = False,
) -> MaterialReference:
    return material_reference_from_payload(
        material_id=material_id[:32],
        kind=kind,
        uri=uri,
        payload=payload,
        source_revision=source_revision,
        trusted=trusted,
    )


def register_cbmc_project(data: dict[str, Any]) -> tuple[CbmcProject, AbstractionCoverage, str]:
    """Register CBMC materials honestly without claiming project-grounded eligibility.

    When compile database / harnesses that include project code are present,
    coverage may be complete for bounded project checking. Otherwise the
    compiler id is registered with non-project guarantees only.
    """
    project_payload = data.get("cbmc_project") if isinstance(data.get("cbmc_project"), dict) else data
    project = CbmcProject.model_validate(
        {
            "compile_commands_path": project_payload.get("compile_commands_path"),
            "source_roots": project_payload.get("source_roots") or [],
            "functions": project_payload.get("functions") or [],
            "harnesses": project_payload.get("harnesses") or [],
            "environment_models": project_payload.get("environment_models") or [],
            "warnings": project_payload.get("warnings") or [],
        }
    )
    guarantee = project.declare_guarantee()
    project = project.model_copy(update={"guarantee_type": guarantee})
    project_grounded = guarantee_implies_project_code(guarantee)
    extracted = len(project.functions) + len(project.harnesses)
    if project_grounded:
        coverage = AbstractionCoverage(
            status="complete",
            confidence=1.0,
            extracted_elements=extracted,
            expected_elements=extracted,
            warnings=list(project.warnings),
        )
        compiler_id = "ovk.cbmc.project_grounded.v1"
    elif project.harnesses or project.compile_commands_path:
        coverage = AbstractionCoverage(
            status="partial",
            confidence=0.4,
            extracted_elements=extracted,
            expected_elements=None,
            warnings=list(project.warnings)
            + ["CBMC materials registered without project-grounded strict eligibility"],
        )
        compiler_id = "ovk.cbmc.harness_or_cdb.v1"
    else:
        coverage = AbstractionCoverage(
            status="unknown",
            confidence=0.0,
            extracted_elements=0,
            expected_elements=None,
            warnings=["no CBMC project materials; compiler registered without strict eligibility"],
        )
        compiler_id = "ovk.cbmc.registry.v1"
    return project, coverage, compiler_id
