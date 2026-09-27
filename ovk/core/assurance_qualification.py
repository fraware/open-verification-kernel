"""Product-qualification harness for durable pull-request assurance.

The harness evaluates the ordinary run_check path inside ephemeral Git
repositories. It keeps benchmark evidence classes explicit so synthetic and
production-shaped internal cases cannot be presented as independent external
validation.

Core product metrics:
- unsafe false assurance: unsafe head reported ESTABLISHED;
- unsafe detection: unsafe head evaluated and left non-established;
- benign open: safe head left non-established or unavailable;
- semantic coverage: complete head source-to-IR coverage;
- fresh/reused proof work;
- end-to-end latency; and
- observed human assurance minutes, when actually measured.

The production gate is deliberately conservative and cannot be satisfied by
internal or public-development fixtures alone.
"""

from __future__ import annotations

import json
import math
import os
import statistics
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal

from pydantic import BaseModel, Field

from ovk import __version__ as OVK_VERSION
from ovk.core.check import run_check
from ovk.core.schema_validation import load_json, require_schema_valid
from ovk.paths import schema_path


ValidationClass = Literal[
    "synthetic",
    "production_shaped_internal",
    "public_upstream_reduction",
    "independent_external",
]
SafetyLabel = Literal["safe", "unsafe"]
ExpectedHeadAssurance = Literal["established", "not_established", "any"]


class AssuranceQualificationCase(BaseModel):
    case_id: str
    repository: str
    description: str = ""
    validation_class: ValidationClass
    safety_label: SafetyLabel
    expected_head_assurance: ExpectedHeadAssurance
    provenance: dict[str, Any] = Field(default_factory=dict)
    base_files: dict[str, str]
    head_files: dict[str, str]
    guarantee_manifest: dict[str, Any]
    head_guarantee_manifest: dict[str, Any] | None = None
    protected_effect_profile: dict[str, Any]
    head_protected_effect_profile: dict[str, Any] | None = None
    human_adjudicated: bool = False
    human_review_minutes: float | None = Field(default=None, ge=0)


class AssuranceQualificationSuite(BaseModel):
    schema_version: Literal["ovk.assurance_qualification_suite.v1"] = (
        "ovk.assurance_qualification_suite.v1"
    )
    suite_id: str
    description: str = ""
    cases: list[AssuranceQualificationCase]


class AssuranceQualificationCaseResult(BaseModel):
    case_id: str
    repository: str
    validation_class: ValidationClass
    safety_label: SafetyLabel
    expected_head_assurance: ExpectedHeadAssurance

    automatic_status: str
    assurance_available: bool
    head_established: bool
    semantic_coverage_complete: bool
    expectation_met: bool
    unsafe_false_assurance: bool
    benign_open: bool

    fresh_effect_count: int = Field(ge=0)
    reused_effect_count: int = Field(ge=0)
    elapsed_ms: float = Field(ge=0)

    changed_files: list[str] = Field(default_factory=list)
    head_statuses: dict[str, str | None] = Field(default_factory=dict)
    reason_codes: list[str] = Field(default_factory=list)
    governance_review_required: bool = False

    human_adjudicated: bool = False
    human_review_minutes: float | None = Field(default=None, ge=0)


class AssuranceQualificationMetrics(BaseModel):
    unsafe_cases: int = Field(ge=0)
    safe_cases: int = Field(ge=0)
    unsafe_false_assurance_count: int = Field(ge=0)
    unsafe_false_assurance_rate: float | None = Field(
        default=None, ge=0, le=1
    )
    unsafe_detection_rate: float | None = Field(default=None, ge=0, le=1)
    benign_open_count: int = Field(ge=0)
    benign_open_rate: float | None = Field(default=None, ge=0, le=1)
    safe_establishment_rate: float | None = Field(default=None, ge=0, le=1)
    semantic_coverage_rate: float | None = Field(default=None, ge=0, le=1)
    automatic_completion_rate: float | None = Field(
        default=None, ge=0, le=1
    )
    fresh_verification_fraction: float | None = Field(
        default=None, ge=0, le=1
    )
    reuse_rate: float | None = Field(default=None, ge=0, le=1)
    p50_latency_ms: float | None = Field(default=None, ge=0)
    p95_latency_ms: float | None = Field(default=None, ge=0)
    human_review_minutes_total: float | None = Field(default=None, ge=0)
    human_review_minutes_per_pr: float | None = Field(default=None, ge=0)
    human_minutes_observed_cases: int = Field(ge=0)


class AssuranceEvidenceClasses(BaseModel):
    synthetic_cases: int = Field(ge=0)
    production_shaped_internal_cases: int = Field(ge=0)
    public_upstream_reduction_cases: int = Field(ge=0)
    independent_external_cases: int = Field(ge=0)
    independent_external_repositories: int = Field(ge=0)


class AssuranceQualificationStatus(BaseModel):
    status: Literal[
        "internal_signal_only",
        "external_evidence_incomplete",
        "production_gate_eligible",
    ]
    reason_codes: list[str] = Field(default_factory=list)
    production_gate_met: bool
    minimum_external_repositories: int = 2
    minimum_human_adjudicated_prs_per_repository: int = 30


class AssuranceQualificationReport(BaseModel):
    schema_version: Literal["ovk.assurance_qualification_report.v1"] = (
        "ovk.assurance_qualification_report.v1"
    )
    suite_id: str
    ovk_version: str
    cases_total: int = Field(ge=1)
    results: list[AssuranceQualificationCaseResult]
    metrics: AssuranceQualificationMetrics
    evidence_classes: AssuranceEvidenceClasses
    qualification: AssuranceQualificationStatus


def load_assurance_qualification_suite(
    path: Path,
) -> AssuranceQualificationSuite:
    payload = json.loads(path.read_text(encoding="utf-8"))
    suite_schema_path = schema_path(
        "assurance.qualification.suite.schema.json"
    )
    require_schema_valid(
        payload,
        load_json(suite_schema_path),
        context="assurance qualification suite",
    )
    return AssuranceQualificationSuite.model_validate(payload)


def validate_assurance_qualification_report(
    report: AssuranceQualificationReport | dict[str, Any],
) -> None:
    payload = (
        report.model_dump(mode="json")
        if isinstance(report, AssuranceQualificationReport)
        else dict(report)
    )
    report_schema_path = schema_path(
        "assurance.qualification.report.schema.json"
    )
    require_schema_valid(
        payload,
        load_json(report_schema_path),
        context="assurance qualification report",
    )


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "git command failed: "
            + " ".join(args)
            + ": "
            + completed.stderr.strip()
        )
    return completed.stdout.strip()


def _write_text_files(repo: Path, files: dict[str, str]) -> None:
    for relative, content in sorted(files.items()):
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _remove_files(repo: Path, paths: set[str]) -> None:
    for relative in sorted(paths):
        path = repo / relative
        if path.is_file():
            path.unlink()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _install_case_base(
    repo: Path,
    case: AssuranceQualificationCase,
) -> None:
    _write_text_files(repo, case.base_files)
    _write_json(
        repo / ".verification" / "guarantees.json",
        case.guarantee_manifest,
    )
    _write_json(
        repo / ".verification" / "protected-effects.fastapi.json",
        case.protected_effect_profile,
    )


def _install_case_head(
    repo: Path,
    case: AssuranceQualificationCase,
) -> None:
    _remove_files(repo, set(case.base_files) - set(case.head_files))
    _write_text_files(repo, case.head_files)

    if case.head_guarantee_manifest is not None:
        _write_json(
            repo / ".verification" / "guarantees.json",
            case.head_guarantee_manifest,
        )
    if case.head_protected_effect_profile is not None:
        _write_json(
            repo / ".verification" / "protected-effects.fastapi.json",
            case.head_protected_effect_profile,
        )


def _head_statuses(automatic: dict[str, Any]) -> dict[str, str | None]:
    review = automatic.get("review") or {}
    assurance = review.get("assurance_diff") or {}
    deltas = assurance.get("deltas") or []
    return {
        str(item.get("guarantee_id")): item.get("head_status")
        for item in deltas
        if item.get("guarantee_id")
    }


def _expectation_met(
    expected: ExpectedHeadAssurance,
    *,
    assurance_available: bool,
    head_established: bool,
) -> bool:
    if expected == "any":
        return True
    if expected == "established":
        return assurance_available and head_established
    return assurance_available and not head_established


def run_assurance_qualification_case(
    case: AssuranceQualificationCase,
    *,
    signing_key: str = "qualification-signing-key",
    worker_image_digest: str = "sha256:qualification-worker",
) -> AssuranceQualificationCaseResult:
    """Execute one case through the ordinary run_check entrypoint."""

    with TemporaryDirectory(prefix="ovk-assurance-qualification-") as tmp:
        repo = Path(tmp)
        _git(repo, "init")
        _git(repo, "config", "user.email", "qualification@example.invalid")
        _git(repo, "config", "user.name", "OVK Qualification")

        _install_case_base(repo, case)
        _git(repo, "add", ".")
        _git(repo, "commit", "-m", "qualification base")
        base_sha = _git(repo, "rev-parse", "HEAD")

        _install_case_head(repo, case)
        _git(repo, "add", "-A")
        _git(repo, "commit", "--allow-empty", "-m", "qualification head")
        head_sha = _git(repo, "rev-parse", "HEAD")
        changed_files = [
            path
            for path in _git(
                repo,
                "diff",
                "--name-only",
                base_sha,
                head_sha,
            ).splitlines()
            if path.strip()
        ]

        previous_cwd = Path.cwd()
        old_signing = os.environ.get("OVK_SIGNING_KEY")
        old_worker = os.environ.get("OVK_WORKER_IMAGE_DIGEST")
        try:
            os.chdir(repo)
            os.environ["OVK_SIGNING_KEY"] = signing_key
            os.environ["OVK_WORKER_IMAGE_DIGEST"] = worker_image_digest

            started = time.perf_counter()
            result = run_check(
                changed_files=changed_files,
                repo=case.repository,
                base_sha=base_sha,
                head_sha=head_sha,
                cache_dir=repo / ".verification" / "cache",
                use_cache=True,
                parallel=False,
            )
            elapsed_ms = (time.perf_counter() - started) * 1000
        finally:
            os.chdir(previous_cwd)
            if old_signing is None:
                os.environ.pop("OVK_SIGNING_KEY", None)
            else:
                os.environ["OVK_SIGNING_KEY"] = old_signing
            if old_worker is None:
                os.environ.pop("OVK_WORKER_IMAGE_DIGEST", None)
            else:
                os.environ["OVK_WORKER_IMAGE_DIGEST"] = old_worker

        automatic = dict(result.plan.get("pr_assurance_review") or {})
        review = dict(automatic.get("review") or {})
        assurance = dict(review.get("assurance_diff") or {})
        guarantee_diff = dict(review.get("guarantee_diff") or {})

        statuses = _head_statuses(automatic)
        assurance_available = bool(assurance.get("available"))
        head_established = (
            assurance_available
            and bool(statuses)
            and all(status == "established" for status in statuses.values())
        )
        semantic_complete = (
            automatic.get("status") == "complete"
            and automatic.get("head_coverage_status") == "complete"
        )
        unsafe_false_assurance = (
            case.safety_label == "unsafe" and head_established
        )
        benign_open = (
            case.safety_label == "safe" and not head_established
        )
        governance_review_required = bool(
            guarantee_diff.get("governance_review_required")
            or automatic.get("profile_governance_review_required")
        )

        return AssuranceQualificationCaseResult(
            case_id=case.case_id,
            repository=case.repository,
            validation_class=case.validation_class,
            safety_label=case.safety_label,
            expected_head_assurance=case.expected_head_assurance,
            automatic_status=str(automatic.get("status") or "missing"),
            assurance_available=assurance_available,
            head_established=head_established,
            semantic_coverage_complete=semantic_complete,
            expectation_met=_expectation_met(
                case.expected_head_assurance,
                assurance_available=assurance_available,
                head_established=head_established,
            ),
            unsafe_false_assurance=unsafe_false_assurance,
            benign_open=benign_open,
            fresh_effect_count=len(
                automatic.get("head_fresh_effects") or []
            ),
            reused_effect_count=len(
                automatic.get("head_reused_effects") or []
            ),
            elapsed_ms=elapsed_ms,
            changed_files=changed_files,
            head_statuses=statuses,
            reason_codes=[
                str(item)
                for item in (automatic.get("reason_codes") or [])
            ],
            governance_review_required=governance_review_required,
            human_adjudicated=case.human_adjudicated,
            human_review_minutes=case.human_review_minutes,
        )


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return float(ordered[index])


def _qualification_status(
    results: list[AssuranceQualificationCaseResult],
    *,
    minimum_external_repositories: int = 2,
    minimum_human_adjudicated_prs_per_repository: int = 30,
) -> AssuranceQualificationStatus:
    external = [
        result
        for result in results
        if result.validation_class == "independent_external"
    ]
    if not external:
        return AssuranceQualificationStatus(
            status="internal_signal_only",
            production_gate_met=False,
            reason_codes=["no_independent_external_cases"],
            minimum_external_repositories=minimum_external_repositories,
            minimum_human_adjudicated_prs_per_repository=(
                minimum_human_adjudicated_prs_per_repository
            ),
        )

    by_repo: dict[str, list[AssuranceQualificationCaseResult]] = {}
    for result in external:
        by_repo.setdefault(result.repository, []).append(result)

    reasons: list[str] = []
    if len(by_repo) < minimum_external_repositories:
        reasons.append("insufficient_independent_external_repositories")

    qualifying_repos = 0
    for repository, items in sorted(by_repo.items()):
        adjudicated = sum(1 for item in items if item.human_adjudicated)
        if adjudicated >= minimum_human_adjudicated_prs_per_repository:
            qualifying_repos += 1
        else:
            reasons.append(
                "insufficient_human_adjudicated_prs:"
                + repository
                + ":"
                + str(adjudicated)
            )

    if any(result.unsafe_false_assurance for result in external):
        reasons.append("unsafe_false_assurance_observed_external")

    gate = (
        len(by_repo) >= minimum_external_repositories
        and qualifying_repos >= minimum_external_repositories
        and not any(
            result.unsafe_false_assurance
            for result in external
        )
    )
    return AssuranceQualificationStatus(
        status=(
            "production_gate_eligible"
            if gate
            else "external_evidence_incomplete"
        ),
        production_gate_met=gate,
        reason_codes=sorted(set(reasons)),
        minimum_external_repositories=minimum_external_repositories,
        minimum_human_adjudicated_prs_per_repository=(
            minimum_human_adjudicated_prs_per_repository
        ),
    )


def build_assurance_qualification_report(
    suite: AssuranceQualificationSuite,
    results: list[AssuranceQualificationCaseResult],
) -> AssuranceQualificationReport:
    if len(results) != len(suite.cases):
        raise ValueError(
            "qualification result count does not match suite case count"
        )

    unsafe = [item for item in results if item.safety_label == "unsafe"]
    safe = [item for item in results if item.safety_label == "safe"]
    false_assurance = [
        item for item in unsafe if item.unsafe_false_assurance
    ]
    detected_unsafe = [
        item
        for item in unsafe
        if item.assurance_available and not item.head_established
    ]
    benign_open = [item for item in safe if item.benign_open]
    safe_established = [item for item in safe if item.head_established]
    semantic_complete = [
        item for item in results if item.semantic_coverage_complete
    ]
    completed = [
        item for item in results if item.automatic_status == "complete"
    ]

    fresh = sum(item.fresh_effect_count for item in results)
    reused = sum(item.reused_effect_count for item in results)
    proof_total = fresh + reused

    measured_minutes = [
        float(item.human_review_minutes)
        for item in results
        if item.human_review_minutes is not None
    ]
    human_total = (
        float(sum(measured_minutes))
        if measured_minutes
        else None
    )
    human_per_pr = (
        human_total / len(measured_minutes)
        if human_total is not None and measured_minutes
        else None
    )

    metrics = AssuranceQualificationMetrics(
        unsafe_cases=len(unsafe),
        safe_cases=len(safe),
        unsafe_false_assurance_count=len(false_assurance),
        unsafe_false_assurance_rate=_rate(
            len(false_assurance),
            len(unsafe),
        ),
        unsafe_detection_rate=_rate(
            len(detected_unsafe),
            len(unsafe),
        ),
        benign_open_count=len(benign_open),
        benign_open_rate=_rate(len(benign_open), len(safe)),
        safe_establishment_rate=_rate(
            len(safe_established),
            len(safe),
        ),
        semantic_coverage_rate=_rate(
            len(semantic_complete),
            len(results),
        ),
        automatic_completion_rate=_rate(
            len(completed),
            len(results),
        ),
        fresh_verification_fraction=_rate(fresh, proof_total),
        reuse_rate=_rate(reused, proof_total),
        p50_latency_ms=(
            float(statistics.median([item.elapsed_ms for item in results]))
            if results
            else None
        ),
        p95_latency_ms=_percentile(
            [item.elapsed_ms for item in results],
            0.95,
        ),
        human_review_minutes_total=human_total,
        human_review_minutes_per_pr=human_per_pr,
        human_minutes_observed_cases=len(measured_minutes),
    )

    counts = {
        value: sum(
            1 for item in results if item.validation_class == value
        )
        for value in (
            "synthetic",
            "production_shaped_internal",
            "public_upstream_reduction",
            "independent_external",
        )
    }
    external_repositories = {
        item.repository
        for item in results
        if item.validation_class == "independent_external"
    }
    evidence_classes = AssuranceEvidenceClasses(
        synthetic_cases=counts["synthetic"],
        production_shaped_internal_cases=counts[
            "production_shaped_internal"
        ],
        public_upstream_reduction_cases=counts[
            "public_upstream_reduction"
        ],
        independent_external_cases=counts["independent_external"],
        independent_external_repositories=len(external_repositories),
    )

    report = AssuranceQualificationReport(
        suite_id=suite.suite_id,
        ovk_version=OVK_VERSION,
        cases_total=len(results),
        results=results,
        metrics=metrics,
        evidence_classes=evidence_classes,
        qualification=_qualification_status(results),
    )
    validate_assurance_qualification_report(report)
    return report


def run_assurance_qualification_suite(
    suite: AssuranceQualificationSuite,
) -> AssuranceQualificationReport:
    results = [
        run_assurance_qualification_case(case)
        for case in suite.cases
    ]
    return build_assurance_qualification_report(suite, results)
