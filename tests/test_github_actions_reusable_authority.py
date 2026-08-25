"""Reusable-workflow authority and trust-lineage regressions."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from ovk.compilers.github_actions.trust_flow import compile_workflow_trust


def _write_workflow(root: Path, name: str, text: str) -> None:
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    (workflow_dir / name).write_text(dedent(text).strip() + "\n", encoding="utf-8")


def _parent(*, permissions: dict[str, str] | None, job: dict) -> dict:
    workflow = {
        "_ovk_path": ".github/workflows/a.yml",
        "on": {"pull_request_target": {}},
        "jobs": {"call": job},
    }
    if permissions is not None:
        workflow["permissions"] = permissions
    return workflow


def _write_findings(ir):
    return [finding for finding in ir.findings if finding.kind == "untrusted_code_with_write_token"]


def _secret_findings(ir):
    return [finding for finding in ir.findings if finding.kind == "untrusted_code_with_secret"]


def test_reusable_workflow_cannot_escalate_caller_read_to_write(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "b.yml",
        """
        on:
          workflow_call:
        permissions:
          contents: write
        jobs:
          risky:
            runs-on: ubuntu-latest
            steps:
              - name: consume
                run: 'echo "${{ github.event.pull_request.title }}"'
        """,
    )
    ir = compile_workflow_trust(
        _parent(
            permissions={"contents": "read"},
            job={"uses": "./.github/workflows/b.yml"},
        ),
        repo_root=tmp_path,
    )
    assert _write_findings(ir) == []
    child = next(node for node in ir.nodes if node.node_id.endswith("job:risky"))
    assert "write_token" not in child.labels
    assert any(label.startswith("permissions_source:reusable:") for label in child.labels)


def test_reusable_workflow_preserves_caller_write_when_child_requests_write(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "b.yml",
        """
        on:
          workflow_call:
        permissions:
          contents: write
        jobs:
          risky:
            runs-on: ubuntu-latest
            steps:
              - name: consume
                run: 'echo "${{ github.event.pull_request.title }}"'
        """,
    )
    ir = compile_workflow_trust(
        _parent(
            permissions={"contents": "write"},
            job={"uses": "./.github/workflows/b.yml"},
        ),
        repo_root=tmp_path,
    )
    findings = _write_findings(ir)
    assert len(findings) == 1
    assert findings[0].node_ids[0].endswith("job:risky:step:consume")


def test_nested_reusable_workflows_cannot_restore_permission_removed_upstream(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "b.yml",
        """
        on:
          workflow_call:
        permissions:
          contents: write
        jobs:
          call-c:
            uses: ./.github/workflows/c.yml
        """,
    )
    _write_workflow(
        tmp_path,
        "c.yml",
        """
        on:
          workflow_call:
        permissions:
          contents: write
        jobs:
          risky:
            runs-on: ubuntu-latest
            steps:
              - name: consume
                run: 'echo "${{ github.event.pull_request.title }}"'
        """,
    )
    ir = compile_workflow_trust(
        _parent(
            permissions={"contents": "read"},
            job={"uses": "./.github/workflows/b.yml"},
        ),
        repo_root=tmp_path,
    )
    assert _write_findings(ir) == []


def test_inherited_secrets_are_available_only_to_directly_called_workflow(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "b.yml",
        """
        on:
          workflow_call:
        jobs:
          direct:
            permissions: {}
            runs-on: ubuntu-latest
            steps:
              - name: direct-use
                run: 'echo "${{ github.event.pull_request.title }} ${{ secrets.TOP_SECRET }}"'
          call-c:
            permissions: {}
            uses: ./.github/workflows/c.yml
        """,
    )
    _write_workflow(
        tmp_path,
        "c.yml",
        """
        on:
          workflow_call:
        jobs:
          nested:
            permissions: {}
            runs-on: ubuntu-latest
            steps:
              - name: nested-use
                run: 'echo "${{ github.event.pull_request.title }} ${{ secrets.TOP_SECRET }}"'
        """,
    )
    ir = compile_workflow_trust(
        _parent(
            permissions={},
            job={
                "uses": "./.github/workflows/b.yml",
                "secrets": "inherit",
            },
        ),
        repo_root=tmp_path,
    )
    findings = _secret_findings(ir)
    assert len(findings) == 1
    assert findings[0].node_ids[0].endswith("job:direct:step:direct-use")


def test_named_secret_forwarding_reaches_only_the_named_child_secret(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "b.yml",
        """
        on:
          workflow_call:
        jobs:
          call-c:
            permissions: {}
            uses: ./.github/workflows/c.yml
            secrets:
              forwarded: '${{ secrets.TOP_SECRET }}'
        """,
    )
    _write_workflow(
        tmp_path,
        "c.yml",
        """
        on:
          workflow_call:
        jobs:
          nested:
            permissions: {}
            runs-on: ubuntu-latest
            steps:
              - name: forwarded-use
                run: 'echo "${{ github.event.pull_request.title }} ${{ secrets.forwarded }}"'
              - name: unavailable-use
                run: 'echo "${{ github.event.pull_request.title }} ${{ secrets.NOT_FORWARDED }}"'
        """,
    )
    ir = compile_workflow_trust(
        _parent(
            permissions={},
            job={
                "uses": "./.github/workflows/b.yml",
                "secrets": "inherit",
            },
        ),
        repo_root=tmp_path,
    )
    findings = _secret_findings(ir)
    assert len(findings) == 1
    assert findings[0].node_ids[0].endswith("job:nested:step:forwarded-use")
    assert findings[0].evidence["secrets"] == ["forwarded"]


def test_untrusted_reusable_input_taint_propagates_into_called_step(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "b.yml",
        """
        on:
          workflow_call:
            inputs:
              message:
                required: true
                type: string
        permissions:
          contents: write
        jobs:
          risky:
            runs-on: ubuntu-latest
            steps:
              - name: consume
                run: 'echo "${{ inputs.message }}"'
        """,
    )
    ir = compile_workflow_trust(
        _parent(
            permissions={"contents": "write"},
            job={
                "uses": "./.github/workflows/b.yml",
                "with": {"message": "${{ github.event.pull_request.title }}"},
            },
        ),
        repo_root=tmp_path,
    )
    findings = _write_findings(ir)
    assert len(findings) == 1
    assert findings[0].node_ids[0].endswith("job:risky:step:consume")
    step = next(node for node in ir.nodes if node.node_id == findings[0].node_ids[0])
    assert "untrusted_reusable_input" in step.labels


def test_unresolved_nested_token_authority_is_not_strictly_classified(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "b.yml",
        """
        on:
          workflow_call:
        permissions:
          contents: write
        jobs:
          risky:
            runs-on: ubuntu-latest
            steps:
              - run: 'echo "${{ github.event.pull_request.title }}"'
        """,
    )
    parent = {
        "_ovk_path": ".github/workflows/a.yml",
        "on": {"workflow_dispatch": {}},
        "jobs": {"call": {"uses": "./.github/workflows/b.yml"}},
    }
    ir = compile_workflow_trust(parent, repo_root=tmp_path)
    assert _write_findings(ir) == []
    assert "job:risky:reusable_token_permissions_unresolved" in ir.unsupported_constructs


def test_local_reusable_workflow_outside_required_directory_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "workflows"
    outside.mkdir()
    (outside / "b.yml").write_text(
        "on:\n  workflow_call:\njobs: {}\n",
        encoding="utf-8",
    )
    ir = compile_workflow_trust(
        _parent(
            permissions={},
            job={"uses": "./workflows/b.yml"},
        ),
        repo_root=tmp_path,
    )
    assert any(item.endswith(":invalid_location") for item in ir.unsupported_constructs)
    assert any(
        finding.kind == "review" and "outside .github/workflows" in finding.summary
        for finding in ir.findings
    )
