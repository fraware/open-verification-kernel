from __future__ import annotations

from pathlib import Path

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.core.automatic_pr_assurance import (
    build_automatic_pull_request_assurance,
)
from ovk.core.guarantee_graph import GuaranteeSelector, GuaranteeSpec
from ovk.core.guarantee_manifest import (
    GuaranteeManifest,
    GovernedGuaranteeContext,
    diff_guarantee_manifests,
)
from ovk.core.protected_effect_evidence import (
    ProtectedEffectRuntimeFingerprint,
)
from ovk.core.protected_effect_profile import (
    GovernedProtectedEffectProfileContext,
    ProtectedEffectProfileConfig,
)


TEST_KEY = b"automatic-pr-assurance-test-key"


SECURE = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id, workspace_id=workspace_id)
    return agent
""".strip()


VULNERABLE = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    agent = await svc.get(agent_id)
    return agent
""".strip()


def _spec() -> GuaranteeSpec:
    return GuaranteeSpec(
        guarantee_id="G-WORKSPACE-AGENT-READ",
        statement="Agent reads are authorized for the acted workspace.",
        selector=GuaranteeSelector(
            effect_name="workspace.agent.read",
            entrypoint="GET /workspaces/{workspace_id}/agents/{agent_id}",
        ),
    )


def _manifest_context(
    *,
    proposed: GuaranteeManifest | None = None,
) -> GovernedGuaranteeContext:
    active = GuaranteeManifest(guarantees=[_spec()])
    head = proposed if proposed is not None else active
    diff = diff_guarantee_manifests(active, head)
    return GovernedGuaranteeContext(
        base_sha="base-a",
        active_source="base_revision",
        active_manifest=active,
        active_revision="base-a",
        assurance_target_available=True,
        proposed_manifest=head,
        proposal_valid=True,
        manifest_path_touched=diff.semantic_change,
        semantic_manifest_changed=diff.semantic_change,
        governance_review_required=diff.semantic_change,
        diff=diff,
    )


def _profile(
    *,
    effect_name: str = "workspace.agent.read",
) -> ProtectedEffectProfileConfig:
    return ProtectedEffectProfileConfig(
        source_paths=["routes.py"],
        sink_effects={"svc.get": effect_name},
        sink_identity_args={"svc.get": 0},
        sink_scope_keywords={"svc.get": "workspace_id"},
        sink_missing_scope_unconstrained=["svc.get"],
        dependency_guard_resources={
            "require_workspace_member": "workspace_id",
        },
        dependency_guard_effects={
            "require_workspace_member": [effect_name],
        },
        principal_parameter="user",
    )


def _profile_context(
    *,
    proposed: ProtectedEffectProfileConfig | None = None,
) -> GovernedProtectedEffectProfileContext:
    active = _profile()
    head = proposed if proposed is not None else active
    changed = head.profile_digest != active.profile_digest
    return GovernedProtectedEffectProfileContext(
        base_sha="base-a",
        active_source="base_revision",
        active_profile=active,
        active_revision="base-a",
        profile_available=True,
        proposed_profile=head,
        proposal_valid=True,
        profile_path_touched=changed,
        semantic_profile_changed=changed,
        governance_review_required=changed,
    )


def _materials(head_source: str) -> AuthMaterials:
    return AuthMaterials(
        base_files={"routes.py": SECURE},
        head_files={"routes.py": head_source},
        repo="example/review",
        base_revision="base-a",
        head_revision="head-b",
    )


def _runtime(_effect_id: str) -> ProtectedEffectRuntimeFingerprint:
    return ProtectedEffectRuntimeFingerprint(
        environment_digest="env:test",
        tool_digest="tool:test",
        worker_image_digest="sha256:test-worker",
        native_execution=True,
    )


def _patch_contexts(
    monkeypatch,
    *,
    materials: AuthMaterials,
    governance: GovernedGuaranteeContext | None = None,
    profile_context: GovernedProtectedEffectProfileContext | None = None,
) -> None:
    monkeypatch.setattr(
        "ovk.core.automatic_pr_assurance.load_governed_guarantee_context",
        lambda **kwargs: governance or _manifest_context(),
    )
    monkeypatch.setattr(
        "ovk.core.automatic_pr_assurance."
        "load_governed_protected_effect_profile_context",
        lambda **kwargs: profile_context or _profile_context(),
    )
    monkeypatch.setattr(
        "ovk.core.automatic_pr_assurance._load_exact_source_materials",
        lambda **kwargs: (materials, []),
    )


def test_automatic_review_reuses_unchanged_secure_head(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _patch_contexts(monkeypatch, materials=_materials(SECURE))

    result = build_automatic_pull_request_assurance(
        repo="example/review",
        base_sha="base-a",
        head_sha="head-b",
        changed_files=["routes.py"],
        verification_policy={"mode": "advisory"},
        cache_dir=tmp_path / "cache",
        signing_key=TEST_KEY,
        runtime_fingerprint_provider=_runtime,
    )

    assert result.status == "complete"
    assert result.review is not None
    assert result.base_fresh_effects
    assert result.head_fresh_effects == []
    assert result.head_reused_effects
    assert result.review.assurance_diff.available is True
    assert result.base_effective_coverage_statuses
    assert result.head_effective_coverage_statuses
    assert set(result.base_effective_coverage_statuses.values()) == {"complete"}
    assert set(result.head_effective_coverage_statuses.values()) == {"complete"}
    delta = result.review.assurance_diff.deltas[0]
    assert delta.guarantee_id == "G-WORKSPACE-AGENT-READ"
    assert delta.head_status == "established"
    assert delta.head_evidence_origin == "reused"
    assert "### Code Diff" in result.markdown
    assert "### Guarantee Diff" in result.markdown
    assert "### Assurance Diff" in result.markdown
    assert "### Protected Effect Source Profile" in result.markdown


def test_vulnerable_head_loses_trusted_base_guarantee_assurance(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _patch_contexts(monkeypatch, materials=_materials(VULNERABLE))

    result = build_automatic_pull_request_assurance(
        repo="example/review",
        base_sha="base-a",
        head_sha="head-b",
        changed_files=["routes.py"],
        verification_policy={"mode": "advisory"},
        cache_dir=tmp_path / "cache",
        signing_key=TEST_KEY,
        runtime_fingerprint_provider=_runtime,
    )

    assert result.status == "complete"
    assert result.review is not None
    delta = result.review.assurance_diff.deltas[0]
    assert delta.base_status == "established"
    assert delta.head_status in {"violated", "unknown", "invalid_evidence"}
    assert "G-WORKSPACE-AGENT-READ" in (
        result.review.assurance_diff.open_guarantee_ids
    )
    assert result.head_fresh_effects


def test_missing_signing_identity_fails_closed_before_assurance_snapshot(
    monkeypatch,
    tmp_path: Path,
) -> None:
    _patch_contexts(monkeypatch, materials=_materials(SECURE))
    monkeypatch.setattr(
        "ovk.core.automatic_pr_assurance.signing_key_from_environment",
        lambda: None,
    )

    result = build_automatic_pull_request_assurance(
        repo="example/review",
        base_sha="base-a",
        head_sha="head-b",
        changed_files=["routes.py"],
        cache_dir=tmp_path / "cache",
    )

    assert result.status == "unavailable"
    assert result.reason_codes == ["evidence_signing_key_unavailable"]
    assert result.review is not None
    assert result.review.assurance_diff.available is False


def test_proposed_profile_change_does_not_govern_current_pr(
    monkeypatch,
    tmp_path: Path,
) -> None:
    proposed = _profile(effect_name="workspace.agent.delete")
    profile_context = _profile_context(proposed=proposed)
    _patch_contexts(
        monkeypatch,
        materials=_materials(SECURE),
        profile_context=profile_context,
    )

    result = build_automatic_pull_request_assurance(
        repo="example/review",
        base_sha="base-a",
        head_sha="head-b",
        changed_files=[
            ".verification/protected-effects.fastapi.json",
            "routes.py",
        ],
        cache_dir=tmp_path / "cache",
        signing_key=TEST_KEY,
        runtime_fingerprint_provider=_runtime,
    )

    assert result.status == "complete"
    assert result.source_profile_digest == _profile().profile_digest
    assert result.profile_semantic_changed is True
    assert result.profile_governance_review_required is True
    assert result.review is not None
    assert result.review.assurance_diff.deltas[0].head_status == "established"


def test_no_active_guarantees_is_explicitly_not_applicable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    active = GuaranteeManifest()
    governance = GovernedGuaranteeContext(
        base_sha="base-a",
        active_source="base_absent",
        active_manifest=active,
        active_revision="base-a",
        assurance_target_available=True,
        proposed_manifest=active,
        proposal_valid=True,
        semantic_manifest_changed=False,
        governance_review_required=False,
        diff=diff_guarantee_manifests(active, active),
    )
    _patch_contexts(
        monkeypatch,
        materials=_materials(SECURE),
        governance=governance,
    )

    result = build_automatic_pull_request_assurance(
        repo="example/review",
        base_sha="base-a",
        head_sha="head-b",
        changed_files=["routes.py"],
        cache_dir=tmp_path / "cache",
        signing_key=TEST_KEY,
    )

    assert result.status == "not_applicable"
    assert result.reason_codes == ["no_active_guarantees"]
