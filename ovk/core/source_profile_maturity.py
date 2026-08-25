"""Source-profile maturity contract for Template Conformance v3.

Local synthetic compiler demonstrations are useful development evidence, but
they are not calibration and cannot establish strict enforcement maturity. This
module separates five states:

* catalog_only
* executable_advisory
* source_profile_candidate
* source_profile_strict_eligible
* externally_calibrated_strict

``externally_calibrated_strict`` is intentionally impossible to derive from an
intent/template boolean. It requires a separately verified immutable external
calibration artifact supplied by a verifier boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from ovk.core.source_profiles import is_known_source_profile

SourceProfileMaturity = Literal[
    "catalog_only",
    "executable_advisory",
    "source_profile_candidate",
    "source_profile_strict_eligible",
    "externally_calibrated_strict",
    "deprecated",
]


@dataclass(frozen=True)
class SourceProfileQualification:
    """Evidence obligations required to promote a source profile.

    Counts are explicit so a single positive/negative fixture cannot masquerade
    as a corpus. The initial threshold is intentionally small but non-trivial;
    profile-specific policy may raise it later.
    """

    profile_id: str | None
    executable_path_complete: bool = False
    compiler_binding_present: bool = False
    enforcement_test_present: bool = False
    materials_trusted: bool = False
    measured_coverage_complete: bool = False

    support_contract_version: str | None = None
    positive_cases: int = 0
    negative_cases: int = 0
    unsupported_cases: int = 0
    malformed_cases: int = 0
    unknown_cases: int = 0
    timeout_cases: int = 0
    source_range_cases: int = 0
    evidence_invariant_cases: int = 0
    end_to_end_bundle_cases: int = 0
    installed_package_cases: int = 0
    action_cases: int = 0

    # A minimum of three positive and three negative cases prevents the current
    # one-fixture proof from qualifying as a strict corpus while remaining
    # achievable for an initial bounded profile.
    min_positive_cases: int = 3
    min_negative_cases: int = 3

    def candidate_ready(self) -> bool:
        return bool(
            is_known_source_profile(self.profile_id)
            and self.executable_path_complete
            and self.compiler_binding_present
            and self.enforcement_test_present
            and self.materials_trusted
            and self.measured_coverage_complete
        )

    def strict_ready(self) -> bool:
        """Return True only when every strict evidence obligation is satisfied."""
        if not self.candidate_ready():
            return False
        if not self.support_contract_version or not self.support_contract_version.strip():
            return False
        return all(
            (
                self.positive_cases >= self.min_positive_cases,
                self.negative_cases >= self.min_negative_cases,
                self.unsupported_cases >= 1,
                self.malformed_cases >= 1,
                self.unknown_cases >= 1,
                self.timeout_cases >= 1,
                self.source_range_cases >= 1,
                self.evidence_invariant_cases >= 1,
                self.end_to_end_bundle_cases >= 1,
                self.installed_package_cases >= 1,
                self.action_cases >= 1,
            )
        )

    def unmet_strict_obligations(self) -> tuple[str, ...]:
        missing: list[str] = []
        if not self.candidate_ready():
            missing.append("candidate_requirements")
        if not self.support_contract_version:
            missing.append("versioned_support_contract")
        if self.positive_cases < self.min_positive_cases:
            missing.append("positive_corpus")
        if self.negative_cases < self.min_negative_cases:
            missing.append("negative_corpus")
        checks = {
            "unsupported_case": self.unsupported_cases,
            "malformed_case": self.malformed_cases,
            "unknown_case": self.unknown_cases,
            "timeout_case": self.timeout_cases,
            "source_range_case": self.source_range_cases,
            "evidence_invariant_case": self.evidence_invariant_cases,
            "end_to_end_bundle_case": self.end_to_end_bundle_cases,
            "installed_package_case": self.installed_package_cases,
            "action_case": self.action_cases,
        }
        missing.extend(name for name, count in checks.items() if count < 1)
        return tuple(missing)


@dataclass(frozen=True)
class VerifiedExternalCalibration:
    """Result of a separate external-calibration verifier.

    Callers must not construct this from template metadata. ``verified`` means
    the calibration artifact's immutable digest, producer identity and expected
    profile binding were checked by the external-calibration verification path.
    """

    profile_id: str
    artifact_sha256: str
    producer: str
    verification_method: str
    verified: bool

    def valid_for(self, profile_id: str | None) -> bool:
        return bool(
            self.verified
            and profile_id
            and self.profile_id == profile_id
            and len(self.artifact_sha256) == 64
            and all(char in "0123456789abcdefABCDEF" for char in self.artifact_sha256)
            and self.producer.strip()
            and self.verification_method.strip()
        )


def classify_source_profile_maturity(
    qualification: SourceProfileQualification | None,
    *,
    executable: bool,
    deprecated: bool = False,
    external_calibration: VerifiedExternalCalibration | None = None,
) -> SourceProfileMaturity:
    """Classify a profile without accepting self-declared maturity assertions."""
    if deprecated:
        return "deprecated"
    if qualification is None:
        return "executable_advisory" if executable else "catalog_only"
    if qualification.strict_ready():
        if external_calibration is not None and external_calibration.valid_for(qualification.profile_id):
            return "externally_calibrated_strict"
        return "source_profile_strict_eligible"
    if qualification.candidate_ready():
        return "source_profile_candidate"
    return "executable_advisory" if executable else "catalog_only"


def qualification_from_local_profile_evidence(
    *,
    profile_id: str | None,
    materials_trusted: bool,
    coverage_complete: bool,
    enforcement_test_present: bool,
    executable_path_complete: bool,
    compiler_binding_present: bool,
) -> SourceProfileQualification:
    """Convert existing local proof evidence into v3 maturity evidence.

    Critically, this function populates *only* candidate-level fields. It never
    invents corpus, timeout, package, Action or external-calibration evidence.
    Thus the current synthetic source-profile prover can at most produce
    ``source_profile_candidate``.
    """
    return SourceProfileQualification(
        profile_id=profile_id,
        executable_path_complete=executable_path_complete,
        compiler_binding_present=compiler_binding_present,
        enforcement_test_present=enforcement_test_present,
        materials_trusted=materials_trusted,
        measured_coverage_complete=coverage_complete,
    )


def qualification_from_dict(payload: dict[str, Any]) -> SourceProfileQualification:
    """Parse machine-produced qualification evidence; unknown keys are ignored."""
    allowed = SourceProfileQualification.__dataclass_fields__
    return SourceProfileQualification(
        **{key: value for key, value in payload.items() if key in allowed}
    )
