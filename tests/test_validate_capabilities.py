from scripts.validate_capabilities import validate_capabilities


def test_validate_capabilities_passes_for_repo_manifests() -> None:
    assert validate_capabilities() == []
