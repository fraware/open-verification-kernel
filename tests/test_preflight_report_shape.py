from ovk.core.preflight import PreflightCheck, PreflightReport


def test_preflight_report_to_dict_shape() -> None:
    report = PreflightReport((PreflightCheck("metadata", True),))
    payload = report.to_dict()
    assert payload["passed"] is True
    assert payload["checks"][0]["name"] == "metadata"
