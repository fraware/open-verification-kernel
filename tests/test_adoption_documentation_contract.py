"""Public onboarding must not advertise an unpublished or unauthenticated release.

The Git tag, Action source and Python distribution are distinct objects;
these tests guard copyable guidance, not the live publication authority.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_SOURCE = "a27d5720f4350c00bca34f71d991c31f5a2f38c7"
UNPUBLISHED_TAG = "fraware/open-verification-kernel@v1.3.0-rc.1"
EXAMPLES = [
    ROOT / "examples/github_workflows/pilot_fork_adopter.yml",
    ROOT / "examples/github_workflows/pilot_advisory_with_comment.yml",
    ROOT / "examples/github_workflows/external_consumer.yml",
]


def test_public_readme_marks_published_source_and_legacy_fallback() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert HISTORICAL_SOURCE in readme
    assert 'OVK_PACKAGE_VERSION: "1.2.1"' in readme
    assert "v1.3.0-rc.1" in readme
    assert "not published or tagged" in readme
    assert "Action falls back to its checkout" in readme
    assert "fail-closed installer" in readme
    assert UNPUBLISHED_TAG not in readme


def test_active_pilot_workflows_do_not_install_nonexistent_candidate() -> None:
    for path in EXAMPLES:
        text = path.read_text(encoding="utf-8")
        assert UNPUBLISHED_TAG not in text, path
        assert 'OVK_PACKAGE_VERSION: "1.2.1"' in text, path
        assert f"fraware/open-verification-kernel@{HISTORICAL_SOURCE}" in text, path
        assert (
            "fallback to checkout" in text or "fall back to the Action checkout" in text
        ), path


def test_fork_example_does_not_request_write_permissions_or_comment() -> None:
    text = EXAMPLES[0].read_text(encoding="utf-8")
    assert "pull-requests: write" not in text
    assert "checks: write" not in text
    assert 'post-comment: "true"' not in text


def test_integration_guide_separates_legacy_action_and_future_release() -> None:
    text = (ROOT / "docs/INTEGRATION.md").read_text(encoding="utf-8")
    assert "historical Action" in text
    assert "not currently available" in text
    assert HISTORICAL_SOURCE in text
    assert UNPUBLISHED_TAG not in text


def test_full_license_and_notice_are_included_in_sdist() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in license_text
    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in license_text
    assert "END OF TERMS AND CONDITIONS" in license_text
    assert "Copyright 2026 fraware" in (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "include NOTICE" in (ROOT / "MANIFEST.in").read_text(encoding="utf-8")


def test_preview_checklist_and_current_status_do_not_grant_release_authority() -> None:
    checklist = (ROOT / "docs/DEVELOPER_PREVIEW_READINESS.md").read_text(encoding="utf-8")
    status = (ROOT / "docs/CURRENT_RELEASE_STATUS.md").read_text(encoding="utf-8")
    assert "NOT LAUNCH-AUTHORIZED" in checklist
    assert "not exist as a public tag" in checklist
    assert "unsigned" in status
    assert "immutable=false" in status
    assert "protected=false" in status
    assert "issue #25" in status


def test_no_error_swallowing_for_requested_action_package_version() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    requested = 'pip install "open-verification-kernel==$' + '{OVK_PACKAGE_VERSION}"'
    assert requested in action
    assert requested + " ||" not in action
    assert 'echo "OVK install: requested distribution version' in action


def test_copyable_external_consumer_is_advisory_and_least_privilege() -> None:
    text = (ROOT / "examples/github_workflows/external_consumer.yml").read_text(
        encoding="utf-8"
    )
    assert "mode: advisory" in text
    assert "mode: strict" not in text
    assert "contents: read" in text
    assert "checks: write" not in text
    assert "pull-requests: write" not in text
    assert 'emit-check: "false"' in text
    assert 'post-comment: "false"' in text
    assert "changed-files:" not in text


def test_strict_required_check_reference_not_copyable_as_unpublished_rc() -> None:
    text = (
        ROOT / "examples/github_workflows/branch_protection_required_check.yml"
    ).read_text(encoding="utf-8")
    assert UNPUBLISHED_TAG not in text
    assert "REPLACE_WITH_AUTHORIZED_VERSION" in text
    assert "REPLACE_WITH_VERIFIED_SHA" in text
    assert "NOT INSTALLABLE UNTIL REPLACED" in text
