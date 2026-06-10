from ovk.core.release_metadata import release_metadata


def test_release_metadata_contains_release_candidate() -> None:
    metadata = release_metadata()
    assert metadata["version"] == "1.1.0"
    assert metadata["release_candidate"] == "1.1.0"


def test_release_metadata_lists_core_commands() -> None:
    metadata = release_metadata()
    assert "ovk ci" in metadata["supported_commands"]
    assert "ovk auth-obligation" in metadata["supported_commands"]
    assert "ovk infra-exposure" in metadata["supported_commands"]
    assert "ovk pilot" in metadata["supported_commands"]


def test_release_metadata_lists_optional_backends() -> None:
    metadata = release_metadata()
    assert "opa" in metadata["optional_backends"]
    assert "z3" in metadata["optional_backends"]
