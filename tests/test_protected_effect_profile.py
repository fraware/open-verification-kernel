from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from ovk.core.protected_effect_profile import (
    ProtectedEffectProfileConfig,
    load_governed_protected_effect_profile_context,
    parse_protected_effect_profile_text,
)


def _payload(*, effect_name: str = "workspace.agent.read") -> dict:
    return {
        "schema_version": "ovk.protected_effect_profile.v1",
        "profile_type": "fastapi_dependency_effects_v1",
        "source_paths": ["routes/**/*.py", "services/**/*.py"],
        "sink_effects": {"svc.get": effect_name},
        "sink_identity_args": {"svc.get": 0},
        "sink_scope_keywords": {"svc.get": "workspace_id"},
        "sink_missing_scope_unconstrained": ["svc.get"],
        "dependency_guard_resources": {
            "require_workspace_member": "workspace_id"
        },
        "dependency_guard_effects": {
            "require_workspace_member": [effect_name]
        },
        "principal_parameter": "user"
    }


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _mock_git_base(
    monkeypatch,
    base_text: str | None,
    *,
    commit_available: bool = True,
) -> None:
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

    monkeypatch.setattr(
        "ovk.core.protected_effect_profile.subprocess.run",
        fake_run,
    )


def test_profile_rejects_unknown_sink_semantics() -> None:
    payload = _payload()
    payload["sink_contracts"] = {"other.get": "Other.get"}

    with pytest.raises(ValueError, match="unknown sink keys"):
        parse_protected_effect_profile_text(
            json.dumps(payload),
            source="test",
        )


def test_profile_rejects_dependency_effect_absent_from_sinks() -> None:
    payload = _payload()
    payload["dependency_guard_effects"] = {
        "require_workspace_member": ["workspace.agent.delete"]
    }

    with pytest.raises(ValueError, match="effects absent from sink_effects"):
        parse_protected_effect_profile_text(
            json.dumps(payload),
            source="test",
        )


def test_profile_digest_is_stable_under_set_like_order() -> None:
    first = ProtectedEffectProfileConfig.model_validate(_payload())
    second_payload = _payload()
    second_payload["source_paths"] = list(
        reversed(second_payload["source_paths"])
    )
    second = ProtectedEffectProfileConfig.model_validate(second_payload)

    assert first.profile_digest == second.profile_digest


def test_pr_uses_base_profile_as_semantic_authority(
    monkeypatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / ".verification" / "protected-effects.fastapi.json"
    base = _payload(effect_name="workspace.agent.read")
    head = _payload(effect_name="workspace.agent.delete")
    _write(path, head)
    _mock_git_base(monkeypatch, json.dumps(base))

    context = load_governed_protected_effect_profile_context(
        changed_files=[
            ".verification/protected-effects.fastapi.json"
        ],
        base_sha="base123",
        profile_path=path,
    )

    assert context.active_source == "base_revision"
    assert context.require_active_profile().sink_effects == {
        "svc.get": "workspace.agent.read"
    }
    assert context.proposed_profile is not None
    assert context.proposed_profile.sink_effects == {
        "svc.get": "workspace.agent.delete"
    }
    assert context.semantic_profile_changed is True
    assert context.governance_review_required is True


def test_profile_content_change_detected_without_changed_file_metadata(
    monkeypatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / ".verification" / "protected-effects.fastapi.json"
    _write(path, _payload(effect_name="workspace.agent.delete"))
    _mock_git_base(
        monkeypatch,
        json.dumps(_payload(effect_name="workspace.agent.read")),
    )

    context = load_governed_protected_effect_profile_context(
        changed_files=["src/app.py"],
        base_sha="base123",
        profile_path=path,
    )

    assert context.semantic_profile_changed is True
    assert context.change_detection_mismatch is True
    assert context.governance_review_required is True


def test_unavailable_base_profile_fails_closed(
    monkeypatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / ".verification" / "protected-effects.fastapi.json"
    _write(path, _payload())
    _mock_git_base(monkeypatch, None, commit_available=False)

    context = load_governed_protected_effect_profile_context(
        changed_files=[],
        base_sha="missing",
        profile_path=path,
    )

    assert context.active_source == "unavailable"
    assert context.profile_available is False
    with pytest.raises(ValueError, match="trusted Protected Effect profile"):
        context.require_active_profile()
