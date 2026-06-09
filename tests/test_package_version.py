from pathlib import Path

from ovk.core.release_metadata import OVK_RELEASE_CANDIDATE


def test_pyproject_version_matches_release_candidate() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{OVK_RELEASE_CANDIDATE}"' in pyproject
