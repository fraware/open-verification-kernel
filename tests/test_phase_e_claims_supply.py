"""WP-15/16 claims, badges, Trusted Publishing, toolchain lock."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _publish_workflow_text() -> str:
    return (REPO / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")


def test_publish_uses_trusted_publishing_without_token() -> None:
    text = _publish_workflow_text()
    assert "password:" not in text
    assert "secrets.PYPI_API_TOKEN" not in text
    assert "id-token: write" in text
    assert "environment: pypi" in text
    assert "gh-action-pypi-publish" in text
    assert re.search(r"^\s*skip-existing\s*:", text, re.MULTILINE) is None


def test_publish_requires_authorization_before_any_public_release() -> None:
    text = _publish_workflow_text()
    assert "release:\n    types: [published]" not in text
    assert "workflow_dispatch:" in text
    assert "verify_release_tag_github.py" in text
    assert "collect_workflow_evidence.py" in text
    assert "--required-event workflow_dispatch" in text
    assert "verify_release_ledger_github.py" in text
    assert "verify_authorized_release_inputs.py" in text
    assert "check_pypi_distribution_state.py" in text
    assert "--draft" in text
    assert "Refusing to mutate an already-public GitHub Release" in text
    assert "Make GitHub Release public only after exact PyPI verification" in text

    ledger_index = text.index("verify_release_ledger_github.py")
    draft_index = text.index("--draft", ledger_index)
    pypi_index = text.index("gh-action-pypi-publish", draft_index)
    public_index = text.index("-F draft=false", pypi_index)
    assert ledger_index < draft_index < pypi_index < public_index


def test_publish_is_tag_ref_bound_and_signs_authorized_ledger() -> None:
    text = _publish_workflow_text()
    assert 'if [ "$GITHUB_REF" != "refs/tags/$TAG" ]' in text
    assert "workflow identity is not tag-bound" in text
    assert "--require-immutable-tag" in text
    assert "--extra .verification/release-ledger.authorized.json" in text
    assert "release-ledger.authorized.json" in text
    assert "published=false tag=null" not in text  # workflow consumes verifier output, never hand-mints it


def test_backend_tools_lock_has_required_digests() -> None:
    lock = json.loads((REPO / "toolchains" / "backend-tools.lock.json").read_text(encoding="utf-8"))
    tools = {t["id"]: t for t in lock["tools"]}
    for required in ("opa", "z3", "cedar", "cbmc"):
        assert required in tools
        assert tools[required].get("required_for_native_matrix") is True
    assert len(tools["opa"]["sha256"]) == 64
    assert len(tools["cbmc"]["sha256"]) == 64
    assert tools["cbmc"].get("allow_distro_fallback") is False
    assert tools["kani"].get("allow_silent_skip") is False


def test_install_backend_is_lock_driven() -> None:
    text = (REPO / "scripts" / "ci" / "install_backend.sh").read_text(encoding="utf-8")
    assert "backend-tools.lock.json" in text
    assert "allow_distro_fallback" in text
    assert "silent kani skip is disabled" in text


def test_badge_does_not_auto_mint_verified_source_sha(monkeypatch) -> None:
    from scripts.render_bench_badge import render_badge

    monkeypatch.setenv("OVK_VERIFIED_SOURCE_SHA", "deadbeef" * 5)
    badge = render_badge(
        {"summary": {"cases_total": 1, "cases_passed": 1}},
        benchmark_source_sha="a" * 40,
        verified_source_sha=None,
    )
    assert badge["benchmark_source_sha"] == "a" * 40
    assert "verified_source_sha" not in badge


def test_project_status_and_claim_registry(tmp_path: Path) -> None:
    """Generation must be testable without mutating release surfaces in the checkout."""
    from ovk.core.project_status import build_claim_registry, write_project_status_and_claims

    fixture = tmp_path / "repo"
    shutil.copytree(REPO / "profiles", fixture / "profiles")
    (fixture / "docs").mkdir(parents=True)

    real_status = REPO / "docs" / "STATUS.md"
    real_status_before = real_status.read_bytes()

    claims = build_claim_registry(fixture)
    assert claims["schema_version"] == "ovk.claim_registry.v1"
    assert claims["normative_maturity_field"] == "conformance_status_v3"
    assert any(c["claim_id"].startswith("profile:") for c in claims["claims"])

    _claims, status = write_project_status_and_claims(fixture, candidate_sha="b" * 40)
    assert status["candidate_sha"] == "b" * 40
    assert status["maturity_contract"]["badge_may_set_verified_source_sha"] is False
    assert (fixture / ".verification" / "project-status.json").is_file()
    assert (fixture / ".verification" / "claim-registry.json").is_file()
    status_md = (fixture / "docs" / "STATUS.md").read_text(encoding="utf-8")
    assert "conformance_status_v3" in status_md
    assert "v1.2.0" not in status_md.split("Generated")[0] or "Generated from" in status_md

    assert real_status.read_bytes() == real_status_before, "tests must not mutate committed release status"


def test_required_workflows_sha_pin_third_party_actions() -> None:
    required = [
        "ci.yml",
        "native-backends-tier1.yml",
        "native-backends-tier1b.yml",
        "holdout-eval.yml",
        "holdout-predict.yml",
        "consumer-pin-verification.yml",
        "bench-badge.yml",
        "publish.yml",
    ]
    for name in required:
        text = (REPO / ".github" / "workflows" / name).read_text(encoding="utf-8")
        # Tag-only pins for first-party actions/checkout etc. should be gone.
        assert "actions/checkout@v4\n" not in text and "actions/checkout@v4\r" not in text
        assert "actions/setup-python@v5\n" not in text and "actions/setup-python@v5\r" not in text
        if "actions/checkout@" in text:
            assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in text
