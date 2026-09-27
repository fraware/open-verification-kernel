from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from ovk.core.guarantee_manifest import (
    GuaranteeManifest,
    diff_guarantee_manifests,
    load_governed_guarantee_context,
    parse_guarantee_manifest_text,
)


def _guarantee(
    guarantee_id: str = "G-REFUND",
    *,
    effect_name: str = "billing.invoice.refund",
    statement: str = "Refund authorization for the acted invoice.",
    dependencies: list[str] | None = None,
) -> dict:
    return {
        "guarantee_id": guarantee_id,
        "spec_version": "1",
        "guarantee_type": "protected_effect_integrity_v1",
        "statement": statement,
        "selector": {
            "effect_name": effect_name,
            "resource_type": "Invoice",
        },
        "assumptions": [],
        "dependencies": dependencies or [],
        "origin_intent": {"owner": "security"},
    }


def _manifest(*guarantees: dict) -> str:
    return json.dumps(
        {
            "schema_version": "ovk.guarantee_manifest.v1",
            "guarantees": list(guarantees),
        }
    )


def _write_manifest(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _mock_git_base(monkeypatch, base_text: str | None, *, commit_available: bool = True) -> None:
    def fake_run(args, **kwargs):
        if args[:3] == ["git", "cat-file", "-e"]:
            target = args[3]
            if target.endswith("^{commit}"):
                return CompletedProcess(
                    args=args,
                    returncode=0 if commit_available else 128,
                    stdout="",
                    stderr="",
                )
            return CompletedProcess(
                args=args,
                returncode=0 if base_text is not None else 128,
                stdout="",
                stderr="",
            )
        if args[:2] == ["git", "show"]:
            return CompletedProcess(
                args=args,
                returncode=0 if base_text is not None else 128,
                stdout=base_text or "",
                stderr="",
            )
        raise AssertionError(f"unexpected git command: {args}")

    monkeypatch.setattr("ovk.core.guarantee_manifest.subprocess.run", fake_run)


def test_manifest_rejects_duplicate_ids_unknown_dependencies_and_cycles() -> None:
    duplicate = _manifest(_guarantee(), _guarantee())
    with pytest.raises(ValueError, match="duplicate guarantee_id"):
        parse_guarantee_manifest_text(duplicate, source="test")

    missing_dependency = _manifest(
        _guarantee(dependencies=["G-MISSING"])
    )
    with pytest.raises(ValueError, match="unknown dependencies"):
        parse_guarantee_manifest_text(missing_dependency, source="test")

    cycle = _manifest(
        _guarantee("G-A", dependencies=["G-B"]),
        _guarantee("G-B", dependencies=["G-A"]),
    )
    with pytest.raises(ValueError, match="dependency cycle"):
        parse_guarantee_manifest_text(cycle, source="test")


def test_manifest_digest_is_stable_under_guarantee_and_set_order() -> None:
    a = _guarantee("G-A", dependencies=["G-B"])
    a["assumptions"] = ["z", "a"]
    b = _guarantee("G-B")

    first = parse_guarantee_manifest_text(
        _manifest(a, b),
        source="first",
    )

    reordered_a = dict(a)
    reordered_a["assumptions"] = ["a", "z"]
    second = parse_guarantee_manifest_text(
        _manifest(b, reordered_a),
        source="second",
    )

    assert first.manifest_digest == second.manifest_digest


def test_diff_distinguishes_machine_claim_from_statement_change() -> None:
    base = parse_guarantee_manifest_text(
        _manifest(_guarantee()),
        source="base",
    )
    statement_head = parse_guarantee_manifest_text(
        _manifest(_guarantee(statement="Edited display statement.")),
        source="statement",
    )
    selector_head = parse_guarantee_manifest_text(
        _manifest(_guarantee(effect_name="billing.invoice.void")),
        source="selector",
    )

    statement_diff = diff_guarantee_manifests(base, statement_head)
    statement_change = statement_diff.modified_guarantees[0]
    assert statement_change.statement_changed is True
    assert statement_change.machine_claim_changed is False

    selector_diff = diff_guarantee_manifests(base, selector_head)
    selector_change = selector_diff.modified_guarantees[0]
    assert selector_change.machine_claim_changed is True
    assert "machine_claim" in selector_change.changed_fields


def test_pr_evaluation_always_uses_base_manifest_as_active_authority(
    monkeypatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / ".verification" / "guarantees.json"
    base_text = _manifest(_guarantee(effect_name="billing.invoice.refund"))
    head_text = _manifest(_guarantee(effect_name="billing.invoice.void"))
    _write_manifest(path, head_text)
    _mock_git_base(monkeypatch, base_text)

    context = load_governed_guarantee_context(
        changed_files=[".verification/guarantees.json"],
        base_sha="base123",
        manifest_path=path,
    )

    assert context.active_source == "base_revision"
    assert context.require_assurance_specs()[0].selector.effect_name == (
        "billing.invoice.refund"
    )
    assert context.proposed_specs()[0].selector.effect_name == (
        "billing.invoice.void"
    )
    assert context.semantic_manifest_changed is True
    assert context.governance_review_required is True
    assert context.diff is not None
    assert context.diff.modified_guarantees[0].machine_claim_changed is True


def test_content_diff_is_detected_even_if_changed_files_omits_manifest(
    monkeypatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / ".verification" / "guarantees.json"
    base_text = _manifest(_guarantee())
    head_text = _manifest(_guarantee(statement="Changed statement."))
    _write_manifest(path, head_text)
    _mock_git_base(monkeypatch, base_text)

    context = load_governed_guarantee_context(
        changed_files=["src/app.py"],
        base_sha="base123",
        manifest_path=path,
    )

    assert context.semantic_manifest_changed is True
    assert context.change_detection_mismatch is True
    assert context.governance_review_required is True
    assert "does not list" in str(context.warning)


def test_manifest_deletion_is_a_proposal_and_base_guarantees_remain_active(
    monkeypatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / ".verification" / "guarantees.json"
    base_text = _manifest(_guarantee())
    _mock_git_base(monkeypatch, base_text)

    context = load_governed_guarantee_context(
        changed_files=[".verification/guarantees.json"],
        base_sha="base123",
        manifest_path=path,
    )

    assert len(context.require_assurance_specs()) == 1
    assert context.proposed_specs() == []
    assert context.diff is not None
    assert context.diff.removed_guarantee_ids == ["G-REFUND"]


def test_invalid_head_proposal_does_not_replace_valid_base_authority(
    monkeypatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / ".verification" / "guarantees.json"
    _write_manifest(path, "{invalid")
    _mock_git_base(monkeypatch, _manifest(_guarantee()))

    context = load_governed_guarantee_context(
        changed_files=[".verification/guarantees.json"],
        base_sha="base123",
        manifest_path=path,
    )

    assert context.assurance_target_available is True
    assert len(context.require_assurance_specs()) == 1
    assert context.proposal_valid is False
    assert context.proposed_specs() is None
    assert context.governance_review_required is True


def test_unavailable_base_fails_closed_instead_of_using_empty_manifest(
    monkeypatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / ".verification" / "guarantees.json"
    _write_manifest(path, _manifest(_guarantee()))
    _mock_git_base(monkeypatch, None, commit_available=False)

    context = load_governed_guarantee_context(
        changed_files=["src/app.py"],
        base_sha="missing",
        manifest_path=path,
    )

    assert context.active_source == "unavailable"
    assert context.assurance_target_available is False
    with pytest.raises(ValueError, match="trusted guarantee assurance target"):
        context.require_assurance_specs()


def test_absent_base_manifest_is_valid_bootstrap_with_empty_active_set(
    monkeypatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / ".verification" / "guarantees.json"
    _write_manifest(path, _manifest(_guarantee()))
    _mock_git_base(monkeypatch, None, commit_available=True)

    context = load_governed_guarantee_context(
        changed_files=[".verification/guarantees.json"],
        base_sha="base123",
        manifest_path=path,
    )

    assert context.active_source == "base_absent"
    assert context.require_assurance_specs() == []
    assert context.diff is not None
    assert context.diff.added_guarantee_ids == ["G-REFUND"]
    assert context.governance_review_required is True


def test_local_mode_uses_workspace_manifest_as_active_target(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".verification" / "guarantees.json"
    _write_manifest(path, _manifest(_guarantee()))

    context = load_governed_guarantee_context(
        changed_files=[],
        base_sha=None,
        manifest_path=path,
    )

    assert context.active_source == "workspace_local"
    assert context.assurance_target_available is True
    assert [item.guarantee_id for item in context.require_assurance_specs()] == [
        "G-REFUND"
    ]
