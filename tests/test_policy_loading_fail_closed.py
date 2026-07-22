from pathlib import Path

import pytest

from ovk.core.context import load_verification_policy


def test_malformed_policy_yaml_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "config.yml"
    config.write_text("schema_version: [\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid OVK verification policy YAML"):
        load_verification_policy(config)


def test_schema_invalid_policy_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "config.yml"
    config.write_text(
        "schema_version: ovk.config.v1\n"
        "mode: strict\n"
        "default_on_unknown: allow\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="failed schema validation"):
        load_verification_policy(config)


def test_missing_policy_uses_explicit_safe_default(tmp_path: Path) -> None:
    policy = load_verification_policy(tmp_path / "missing.yml")
    assert policy == {
        "schema_version": "ovk.config.v1",
        "mode": "advisory",
        "default_on_unknown": "require_human_review",
    }
