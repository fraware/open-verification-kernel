from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ovk.core.check import run_check


SECURE_ROUTE = """
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


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_run_check_builds_assurance_diff_from_exact_git_revisions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "consumer"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "ovk-test@example.invalid")
    _git(repo, "config", "user.name", "OVK Test")

    (repo / "routes.py").write_text(SECURE_ROUTE + "\n", encoding="utf-8")

    _write_json(
        repo / ".verification" / "guarantees.json",
        {
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
                        "entrypoint": (
                            "GET /workspaces/{workspace_id}/agents/{agent_id}"
                        ),
                    },
                    "assumptions": [],
                    "dependencies": [],
                    "origin_intent": {"owner": "security"},
                }
            ],
        },
    )
    _write_json(
        repo / ".verification" / "protected-effects.fastapi.json",
        {
            "schema_version": "ovk.protected_effect_profile.v1",
            "profile_type": "fastapi_dependency_effects_v1",
            "source_paths": ["routes.py"],
            "sink_effects": {
                "svc.get": "workspace.agent.read",
            },
            "sink_identity_args": {"svc.get": 0},
            "sink_scope_keywords": {
                "svc.get": "workspace_id",
            },
            "sink_missing_scope_unconstrained": ["svc.get"],
            "dependency_guard_resources": {
                "require_workspace_member": "workspace_id",
            },
            "dependency_guard_effects": {
                "require_workspace_member": ["workspace.agent.read"],
            },
            "principal_parameter": "user",
        },
    )

    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base assurance state")
    base_sha = _git(repo, "rev-parse", "HEAD")

    (repo / "README.md").write_text(
        "unrelated documentation change\n",
        encoding="utf-8",
    )
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "unrelated change")
    head_sha = _git(repo, "rev-parse", "HEAD")

    monkeypatch.chdir(repo)
    monkeypatch.setenv(
        "OVK_SIGNING_KEY",
        "automatic-git-integration-test-key",
    )
    monkeypatch.setenv(
        "OVK_WORKER_IMAGE_DIGEST",
        "sha256:automatic-git-integration-worker",
    )

    result = run_check(
        changed_files=["README.md"],
        repo="example/consumer",
        base_sha=base_sha,
        head_sha=head_sha,
        cache_dir=repo / ".verification" / "cache",
        use_cache=True,
        parallel=False,
    )

    automatic = result.plan["pr_assurance_review"]
    assert automatic["status"] == "complete"
    assert automatic["reason_codes"] == []
    assert automatic["base_fresh_effects"]
    assert automatic["head_fresh_effects"] == []
    assert automatic["head_reused_effects"]

    review = automatic["review"]
    assert review["code_diff"]["changed_files"] == ["README.md"]
    assert review["guarantee_diff"]["governance_review_required"] is False
    assert review["assurance_diff"]["available"] is True
    assert review["assurance_diff"]["freshly_established_guarantee_ids"] == []
    assert review["assurance_diff"]["reused_established_guarantee_ids"] == [
        "G-WORKSPACE-AGENT-READ"
    ]
    assert review["assurance_diff"]["deltas"][0]["head_status"] == "established"
    assert review["assurance_diff"]["deltas"][0]["head_evidence_origin"] == "reused"

    assert "### Code Diff" in result.markdown
    assert "### Guarantee Diff" in result.markdown
    assert "### Assurance Diff" in result.markdown
    assert "current_established_reused" in result.markdown
