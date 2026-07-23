"""GitHub Actions trust-flow compiler tests (synthetic incident reproductions)."""

from __future__ import annotations

from pathlib import Path

from ovk.compilers.github_actions import compile_workflow_trust, load_workflow_text
from ovk.compilers.github_actions.reusable_workflows import parse_uses


def test_untrusted_pr_with_secret_is_finding() -> None:
    workflow = load_workflow_text(
        """
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: run-pr
        run: echo "${{ secrets.DEPLOY_KEY }}"
""".strip(),
        path="evil.yml",
    )
    ir = compile_workflow_trust(workflow)
    kinds = {item.kind for item in ir.findings}
    assert "untrusted_code_with_secret" in kinds
    assert "untrusted_code_with_write_token" in kinds


def test_mutable_remote_reusable_ref_is_review() -> None:
    ref = parse_uses("actions/checkout@main")
    assert ref.remote is True
    assert ref.mutable_ref is True
    pinned = parse_uses("actions/checkout@" + ("a" * 40))
    assert pinned.mutable_ref is False
    assert pinned.digest == "a" * 40


def test_secrets_inherit_on_reusable(tmp_path: Path) -> None:
    reusable = tmp_path / ".github" / "workflows" / "reusable.yml"
    reusable.parent.mkdir(parents=True)
    reusable.write_text(
        """
on: workflow_call
jobs:
  inner:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
""".strip(),
        encoding="utf-8",
    )
    workflow = load_workflow_text(
        """
on: push
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
""".strip(),
        path="caller.yml",
    )
    ir = compile_workflow_trust(workflow, repo_root=tmp_path)
    assert any(item.kind == "secrets_inherit" for item in ir.findings)


def test_cycle_prevention(tmp_path: Path) -> None:
    a = tmp_path / "a.yml"
    b = tmp_path / "b.yml"
    a.write_text(
        """
on: workflow_call
jobs:
  call:
    uses: ./b.yml
""".strip(),
        encoding="utf-8",
    )
    b.write_text(
        """
on: workflow_call
jobs:
  call:
    uses: ./a.yml
""".strip(),
        encoding="utf-8",
    )
    workflow = load_workflow_text(a.read_text(encoding="utf-8"), path=str(a))
    # Force path identity used by cycle detection.
    workflow["_ovk_path"] = str(a.resolve())
    ir = compile_workflow_trust(workflow, repo_root=tmp_path)
    assert any(item.kind == "cycle" for item in ir.findings)


def test_composite_action_propagates_env(tmp_path: Path) -> None:
    action = tmp_path / "composite" / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_text(
        """
name: composite
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "${{ secrets.TOKEN }}"
      env:
        X: "${{ inputs.value }}"
""".strip(),
        encoding="utf-8",
    )
    workflow = load_workflow_text(
        """
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: use
        uses: ./composite
""".strip(),
        path="wf.yml",
    )
    ir = compile_workflow_trust(workflow, repo_root=tmp_path)
    assert any(node.kind == "composite_action" for node in ir.nodes)
    assert any(item.name == "TOKEN" for item in ir.secrets)
