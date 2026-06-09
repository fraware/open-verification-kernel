from pathlib import Path

import ovk
from ovk.core.release_metadata import OVK_RELEASE_CANDIDATE


def test_pyproject_version_matches_release_candidate() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{OVK_RELEASE_CANDIDATE}"' in pyproject


def test_package_version_matches_release_candidate() -> None:
    assert ovk.__version__ == OVK_RELEASE_CANDIDATE
