from scripts.check_release_metadata import main as check_release_metadata


def test_check_release_metadata_passes() -> None:
    assert check_release_metadata() == 0
