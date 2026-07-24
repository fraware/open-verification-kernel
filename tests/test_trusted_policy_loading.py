from pathlib import Path
from subprocess import CompletedProcess

from ovk.core.context import SAFE_UNTRUSTED_POLICY, load_trusted_verification_policy


BASE_POLICY = """schema_version: ovk.config.v1
mode: strict
default_on_unknown: require_human_review
routing:
  mode: shadow
  enforced_lanes: []
"""


def test_workspace_policy_is_used_when_policy_file_is_unchanged(tmp_path: Path) -> None:
    config = tmp_path / ".verification" / "config.yml"
    config.parent.mkdir(parents=True)
    config.write_text(BASE_POLICY, encoding="utf-8")
    policy, metadata = load_trusted_verification_policy(
        changed_files=["src/app.py"],
        base_sha="base",
        config_path=config,
    )
    assert policy["mode"] == "strict"
    assert metadata["policy_source"] == "workspace"


def test_changed_policy_is_loaded_from_base_revision(monkeypatch, tmp_path: Path) -> None:
    config = tmp_path / ".verification" / "config.yml"
    config.parent.mkdir(parents=True)
    config.write_text(
        BASE_POLICY.replace("require_human_review", "allow_with_warning"),
        encoding="utf-8",
    )

    def fake_run(*args, **kwargs):
        return CompletedProcess(args=args[0], returncode=0, stdout=BASE_POLICY, stderr="")

    monkeypatch.setattr("ovk.core.context.subprocess.run", fake_run)
    policy, metadata = load_trusted_verification_policy(
        changed_files=[".verification/config.yml"],
        base_sha="base123",
        config_path=config,
    )
    assert policy["default_on_unknown"] == "require_human_review"
    assert metadata["policy_source"] == "base_revision"
    assert metadata["policy_revision"] == "base123"


def test_changed_policy_without_base_material_uses_safe_builtin(monkeypatch, tmp_path: Path) -> None:
    config = tmp_path / ".verification" / "config.yml"
    config.parent.mkdir(parents=True)
    config.write_text(BASE_POLICY, encoding="utf-8")

    def fake_run(*args, **kwargs):
        return CompletedProcess(args=args[0], returncode=128, stdout="", stderr="missing")

    monkeypatch.setattr("ovk.core.context.subprocess.run", fake_run)
    policy, metadata = load_trusted_verification_policy(
        changed_files=[".verification/config.yml"],
        base_sha="base123",
        config_path=config,
    )
    assert policy == SAFE_UNTRUSTED_POLICY
    assert policy["default_on_unknown"] == "block"
    assert policy["routing"]["allow_fallback"] is False
    assert metadata["policy_source"] == "safe_builtin"
