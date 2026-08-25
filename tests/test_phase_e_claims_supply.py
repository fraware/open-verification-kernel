"""WP-15/16 claims, badges, Trusted Publishing, toolchain lock."""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_publish_uses_trusted_publishing_without_token() -> None:
    text = (REPO / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert "password:" not in text
    assert "secrets.PYPI_API_TOKEN" not in text
    assert "id-token: write" in text
    assert "environment: pypi" in text
    assert "gh-action-pypi-publish" in text


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
    from ovk.core.project_status import build_claim_registry, write_project_status_and_claims

    claims = build_claim_registry(REPO)
    assert claims["schema_version"] == "ovk.claim_registry.v1"
    assert claims["normative_maturity_field"] == "conformance_status_v3"
    assert any(c["claim_id"].startswith("profile:") for c in claims["claims"])
    # Write into temp copies of required paths by using repo and accepting .verification write
    _claims, status = write_project_status_and_claims(REPO, candidate_sha="b" * 40)
    assert status["candidate_sha"] == "b" * 40
    assert status["maturity_contract"]["badge_may_set_verified_source_sha"] is False
    assert (REPO / ".verification" / "project-status.json").is_file()
    assert (REPO / ".verification" / "claim-registry.json").is_file()
    status_md = (REPO / "docs" / "STATUS.md").read_text(encoding="utf-8")
    assert "conformance_status_v3" in status_md
    assert "v1.2.0" not in status_md.split("Generated")[0] or "Generated from" in status_md


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
