from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ovk.core.external_assurance_replay import (
    ExternalAssuranceReplayCase,
    ExternalAssuranceReplaySuite,
    replay_external_assurance_case,
    run_external_assurance_replay_suite,
    validate_external_assurance_replay_report,
)


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


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def _manifest() -> dict:
    return {
        "schema_version": "ovk.guarantee_manifest.v1",
        "guarantees": [
            {
                "guarantee_id": "G-WORKSPACE-AGENT-READ",
                "spec_version": "1",
                "guarantee_type": "protected_effect_integrity_v1",
                "statement": (
                    "Agent reads are authorized for the acted workspace."
                ),
                "selector": {
                    "effect_name": "workspace.agent.read",
                },
                "assumptions": [],
                "dependencies": [],
                "origin_intent": {"owner": "security"},
            }
        ],
    }


def _profile() -> dict:
    return {
        "schema_version": "ovk.protected_effect_profile.v1",
        "profile_type": "fastapi_dependency_effects_v1",
        "source_paths": ["routes.py"],
        "sink_effects": {"svc.get": "workspace.agent.read"},
        "sink_identity_args": {"svc.get": 0},
        "sink_scope_keywords": {"svc.get": "workspace_id"},
        "sink_missing_scope_unconstrained": ["svc.get"],
        "dependency_guard_resources": {
            "require_workspace_member": "workspace_id",
        },
        "dependency_guard_effects": {
            "require_workspace_member": ["workspace.agent.read"],
        },
        "principal_parameter": "user",
    }


def _upstream(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "external@example.invalid")
    _git(repo, "config", "user.name", "External Fixture")

    (repo / "routes.py").write_text(SECURE + "\n", encoding="utf-8")
    (repo / "unrelated.txt").write_text("base\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "secure base")
    base_sha = _git(repo, "rev-parse", "HEAD")

    (repo / "routes.py").write_text(VULNERABLE + "\n", encoding="utf-8")
    (repo / "unrelated.txt").write_text("head\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "scope regression")
    head_sha = _git(repo, "rev-parse", "HEAD")
    return repo, base_sha, head_sha


def _case(tmp_path: Path) -> ExternalAssuranceReplayCase:
    repo, base_sha, head_sha = _upstream(tmp_path)
    return ExternalAssuranceReplayCase(
        case_id="local-external-regression",
        repository="external/fixture",
        repository_url=repo.resolve().as_uri(),
        base_sha=base_sha,
        head_sha=head_sha,
        safety_label="unsafe",
        expected_head_assurance="not_established",
        guarantee_manifest=_manifest(),
        protected_effect_profile=_profile(),
        provenance={
            "adjudication_kind": "public_security_advisory",
            "references": ["https://example.invalid/advisory"],
        },
        qualification_human_adjudicated=False,
        human_review_minutes=None,
    )


def test_external_replay_fetches_pinned_materials_and_uses_common_scorer(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    result = replay_external_assurance_case(
        case,
        allow_local_file_urls=True,
    )

    assert result.base_sha == case.base_sha
    assert result.head_sha == case.head_sha
    assert result.selected_paths == ["routes.py"]
    assert result.upstream_base_material_digest
    assert result.upstream_head_material_digest
    assert (
        result.upstream_base_material_digest
        != result.upstream_head_material_digest
    )

    qualification = result.qualification_result
    assert qualification.validation_class == "independent_external"
    assert qualification.safety_label == "unsafe"
    assert qualification.assurance_available is True
    assert qualification.head_established is False
    assert qualification.unsafe_false_assurance is False
    assert qualification.expectation_met is True
    assert qualification.human_adjudicated is False


def test_external_replay_report_is_schema_valid(tmp_path: Path) -> None:
    suite = ExternalAssuranceReplaySuite(
        suite_id="local-external-suite",
        cases=[_case(tmp_path)],
    )
    report = run_external_assurance_replay_suite(
        suite,
        allow_local_file_urls=True,
    )

    validate_external_assurance_replay_report(report)
    assert report.cases_total == 1
    assert report.results[0].qualification_result.expectation_met is True


def test_public_provenance_cannot_claim_measured_human_minutes() -> None:
    with pytest.raises(
        ValueError,
        match="human_review_minutes require",
    ):
        ExternalAssuranceReplayCase(
            case_id="invalid-human-time",
            repository="owner/repo",
            repository_url="https://github.com/owner/repo.git",
            base_sha="a" * 40,
            head_sha="b" * 40,
            safety_label="safe",
            expected_head_assurance="established",
            guarantee_manifest=_manifest(),
            protected_effect_profile=_profile(),
            provenance={
                "adjudication_kind": "public_merged_fix",
                "references": ["https://github.com/owner/repo/pull/1"],
            },
            qualification_human_adjudicated=False,
            human_review_minutes=2.5,
        )


def test_qualification_human_review_requires_explicit_human_flag() -> None:
    with pytest.raises(
        ValueError,
        match="qualification_human_review provenance requires",
    ):
        ExternalAssuranceReplayCase(
            case_id="invalid-human-label",
            repository="owner/repo",
            repository_url="https://github.com/owner/repo.git",
            base_sha="a" * 40,
            head_sha="b" * 40,
            safety_label="safe",
            expected_head_assurance="established",
            guarantee_manifest=_manifest(),
            protected_effect_profile=_profile(),
            provenance={
                "adjudication_kind": "qualification_human_review",
                "references": ["review-ledger:1"],
            },
            qualification_human_adjudicated=False,
        )


def test_production_url_must_match_declared_repository(tmp_path: Path) -> None:
    case = ExternalAssuranceReplayCase(
        case_id="url-mismatch",
        repository="owner/repo",
        repository_url="https://github.com/other/repo.git",
        base_sha="a" * 40,
        head_sha="b" * 40,
        safety_label="unsafe",
        expected_head_assurance="not_established",
        guarantee_manifest=_manifest(),
        protected_effect_profile=_profile(),
        provenance={
            "adjudication_kind": "public_issue",
            "references": ["https://github.com/other/repo/issues/1"],
        },
    )

    with pytest.raises(ValueError, match="does not match"):
        replay_external_assurance_case(case)
