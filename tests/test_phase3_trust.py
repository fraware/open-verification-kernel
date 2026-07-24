import json
from pathlib import Path

from ovk.core.attestation import bundle_to_statement
from ovk.core.attestation_binding import verify_bundle_statement_binding
from ovk.core.evidence_quality import build_evidence_quality_report
from ovk.core.github_check import build_check_run_payload, check_conclusion_for_recommendation
from ovk.core.json_io import read_json_file
from ovk.core.kernel import execute_kernel
from ovk.core.models import EvidenceBundle
from ovk.core.sigstore_signing import sigstore_signing_enabled


def test_adversarial_sha_mismatch_fails_quality_gate() -> None:
    bundle = EvidenceBundle.model_validate(
        read_json_file(Path("examples/evidence_quality/adversarial_sha_mismatch.json"))
    )
    report = build_evidence_quality_report(bundle)
    assert report.passed is False
    messages = {issue.message for issue in report.issues}
    assert any("OVK-INV-008" in message for message in messages)


def test_adversarial_missing_claim_metadata_fails_quality_gate() -> None:
    bundle = EvidenceBundle.model_validate(
        read_json_file(Path("examples/evidence_quality/adversarial_missing_claim_metadata.json"))
    )
    report = build_evidence_quality_report(bundle)
    assert report.passed is False


def test_valid_kernel_bundle_binds_to_attestation_statement() -> None:
    diff_text = Path("examples/ci_secrets/workflow_secrets_on_pr.diff").read_text(encoding="utf-8")
    result = execute_kernel(diff_text=diff_text, use_cache=False, repo="trust/repo", head_sha="abc123")
    statement = bundle_to_statement(result.bundle)
    assert not verify_bundle_statement_binding(result.bundle, statement)


def test_tampered_attestation_digest_is_detected() -> None:
    diff_text = Path("examples/ci_secrets/workflow_secrets_on_pr.diff").read_text(encoding="utf-8")
    result = execute_kernel(diff_text=diff_text, use_cache=False, repo="trust/repo", head_sha="abc123")
    statement = bundle_to_statement(result.bundle)
    tampered = json.loads(json.dumps(statement))
    tampered["predicate"]["verification"]["bundle_digest"] = "forged"
    issues = verify_bundle_statement_binding(result.bundle, tampered)
    assert issues


def test_github_check_maps_block_to_failure() -> None:
    assert check_conclusion_for_recommendation("block") == "failure"
    assert check_conclusion_for_recommendation("allow") == "success"


def test_build_github_check_payload_from_kernel_result() -> None:
    diff_text = Path("examples/ci_secrets/workflow_secrets_on_pr.diff").read_text(encoding="utf-8")
    result = execute_kernel(diff_text=diff_text, use_cache=False, repo="trust/repo", head_sha="abc123")
    payload = build_check_run_payload(result.bundle, head_sha="abc123")
    assert payload["conclusion"] == "failure"
    assert payload["head_sha"] == "abc123"


def test_sigstore_signing_disabled_by_default() -> None:
    assert sigstore_signing_enabled() is False


def test_external_smoke_checklist_passes() -> None:
    from scripts.external_smoke_checklist import run_external_smoke_checklist

    assert run_external_smoke_checklist() == []
