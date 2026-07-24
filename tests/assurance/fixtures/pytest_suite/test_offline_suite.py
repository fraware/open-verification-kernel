"""Offline pytest suite fixture for VA-07 assurance adapter."""


def test_fixture_passes() -> None:
    assert 1 + 1 == 2


def test_fixture_also_passes() -> None:
    assert "ovk".upper() == "OVK"
