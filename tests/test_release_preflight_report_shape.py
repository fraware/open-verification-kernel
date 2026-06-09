from scripts.release_preflight_report import build_release_preflight_report


def test_release_preflight_report_is_serializable() -> None:
    report = build_release_preflight_report()
    payload = report.to_dict()
    assert payload["passed"] is True
    assert {check["name"] for check in payload["checks"]} == {
        "release_metadata",
        "command_surface",
        "local_release_smoke",
    }
