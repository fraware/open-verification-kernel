from scripts.smoke_release_local import run_local_release_smoke


def test_local_release_smoke_has_no_failures() -> None:
    assert run_local_release_smoke() == []
