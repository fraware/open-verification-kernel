from scripts.release_preflight import main as release_preflight


def test_release_preflight_passes() -> None:
    assert release_preflight() == 0
