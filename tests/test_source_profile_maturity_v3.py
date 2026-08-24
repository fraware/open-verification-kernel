"""Template Conformance v3 source-profile maturity rules."""

from ovk.core.source_profile_maturity import (
    SourceProfileQualification,
    VerifiedExternalCalibration,
    classify_source_profile_maturity,
    qualification_from_local_profile_evidence,
)

PROFILE = "authorization.fastapi.ast_v1"


def _candidate() -> SourceProfileQualification:
    return SourceProfileQualification(
        profile_id=PROFILE,
        executable_path_complete=True,
        compiler_binding_present=True,
        enforcement_test_present=True,
        materials_trusted=True,
        measured_coverage_complete=True,
    )


def _strict() -> SourceProfileQualification:
    return SourceProfileQualification(
        profile_id=PROFILE,
        executable_path_complete=True,
        compiler_binding_present=True,
        enforcement_test_present=True,
        materials_trusted=True,
        measured_coverage_complete=True,
        support_contract_version="1.0.0",
        positive_cases=3,
        negative_cases=3,
        unsupported_cases=1,
        malformed_cases=1,
        unknown_cases=1,
        timeout_cases=1,
        source_range_cases=1,
        evidence_invariant_cases=1,
        end_to_end_bundle_cases=1,
        installed_package_cases=1,
        action_cases=1,
    )


def test_existing_synthetic_local_proof_can_only_be_candidate() -> None:
    qualification = qualification_from_local_profile_evidence(
        profile_id=PROFILE,
        materials_trusted=True,
        coverage_complete=True,
        enforcement_test_present=True,
        executable_path_complete=True,
        compiler_binding_present=True,
    )
    assert qualification.candidate_ready() is True
    assert qualification.strict_ready() is False
    assert classify_source_profile_maturity(qualification, executable=True) == "source_profile_candidate"


def test_single_positive_and_negative_fixture_are_not_a_strict_corpus() -> None:
    qualification = _candidate()
    qualification = SourceProfileQualification(
        **{
            **qualification.__dict__,
            "support_contract_version": "1.0.0",
            "positive_cases": 1,
            "negative_cases": 1,
            "unsupported_cases": 1,
            "malformed_cases": 1,
            "unknown_cases": 1,
            "timeout_cases": 1,
            "source_range_cases": 1,
            "evidence_invariant_cases": 1,
            "end_to_end_bundle_cases": 1,
            "installed_package_cases": 1,
            "action_cases": 1,
        }
    )
    assert qualification.strict_ready() is False
    assert "positive_corpus" in qualification.unmet_strict_obligations()
    assert "negative_corpus" in qualification.unmet_strict_obligations()


def test_every_strict_obligation_is_required() -> None:
    baseline = _strict()
    fields = [
        "support_contract_version",
        "unsupported_cases",
        "malformed_cases",
        "unknown_cases",
        "timeout_cases",
        "source_range_cases",
        "evidence_invariant_cases",
        "end_to_end_bundle_cases",
        "installed_package_cases",
        "action_cases",
    ]
    for field in fields:
        values = dict(baseline.__dict__)
        values[field] = None if field == "support_contract_version" else 0
        degraded = SourceProfileQualification(**values)
        assert degraded.strict_ready() is False, field


def test_complete_machine_evidence_reaches_strict_eligible() -> None:
    qualification = _strict()
    assert qualification.strict_ready() is True
    assert classify_source_profile_maturity(qualification, executable=True) == "source_profile_strict_eligible"


def test_external_calibration_requires_strict_qualification_first() -> None:
    external = VerifiedExternalCalibration(
        profile_id=PROFILE,
        artifact_sha256="a" * 64,
        producer="independent-lab",
        verification_method="sigstore-bundle-v1",
        verified=True,
    )
    assert classify_source_profile_maturity(
        _candidate(), executable=True, external_calibration=external
    ) == "source_profile_candidate"
    assert classify_source_profile_maturity(
        _strict(), executable=True, external_calibration=external
    ) == "externally_calibrated_strict"


def test_wrong_profile_or_unverified_external_artifact_cannot_promote() -> None:
    wrong_profile = VerifiedExternalCalibration(
        profile_id="ci_secrets.actions.permissions_flow_v1",
        artifact_sha256="b" * 64,
        producer="independent-lab",
        verification_method="sigstore-bundle-v1",
        verified=True,
    )
    unverified = VerifiedExternalCalibration(
        profile_id=PROFILE,
        artifact_sha256="c" * 64,
        producer="independent-lab",
        verification_method="sigstore-bundle-v1",
        verified=False,
    )
    assert classify_source_profile_maturity(
        _strict(), executable=True, external_calibration=wrong_profile
    ) == "source_profile_strict_eligible"
    assert classify_source_profile_maturity(
        _strict(), executable=True, external_calibration=unverified
    ) == "source_profile_strict_eligible"


def test_no_profile_remains_advisory_or_catalog_only() -> None:
    assert classify_source_profile_maturity(None, executable=True) == "executable_advisory"
    assert classify_source_profile_maturity(None, executable=False) == "catalog_only"
