from ovk.core.preflight import PreflightCheck, PreflightReport, check_from_exit_code, check_from_failures


def test_preflight_report_passes_when_all_checks_pass() -> None:
    report = PreflightReport((PreflightCheck("metadata", True), PreflightCheck("commands", True)))
    assert report.passed is True
    assert report.failures == ()


def test_preflight_report_collects_failure_messages() -> None:
    report = PreflightReport((PreflightCheck("metadata", False, ("metadata drift",)),))
    assert report.passed is False
    assert report.failures == ("metadata drift",)


def test_check_from_exit_code() -> None:
    assert check_from_exit_code("metadata", 0, "failed").passed is True
    failed = check_from_exit_code("metadata", 1, "failed")
    assert failed.passed is False
    assert failed.messages == ("failed",)


def test_check_from_failures() -> None:
    assert check_from_failures("smoke", []).passed is True
    failed = check_from_failures("smoke", ["missing output"])
    assert failed.passed is False
    assert failed.messages == ("missing output",)
