"""Pinned external-repository replay for durable assurance qualification.

External replay deliberately separates acquisition from scoring:

1. fetch immutable upstream base/head commits;
2. materialize only source paths selected by the supplied, typed Protected
   Effect profile;
3. content-address those exact upstream materials;
4. build an ordinary AssuranceQualificationCase using those materials; and
5. execute the existing qualification runner, which itself exercises run_check.

Upstream source is parsed as data and is never imported or executed.

A public advisory or merged fix is useful label provenance, but it does not
count as a qualification human adjudication. Only cases explicitly marked
qualification_human_adjudicated=True contribute to the human sample depth used
by the production qualification gate.
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

from ovk.core.assurance_qualification import (
    AssuranceQualificationCase,
    AssuranceQualificationCaseResult,
    ExpectedHeadAssurance,
    SafetyLabel,
    run_assurance_qualification_case,
)
from ovk.core.bundle import content_digest
from ovk.core.protected_effect_profile import ProtectedEffectProfileConfig
from ovk.core.schema_validation import load_json, require_schema_valid
from ovk.paths import schema_path


ExternalReplayValidationClass = Literal[
    "public_upstream_reduction",
    "independent_external",
]
ExternalReplayContaminationStatus = Literal[
    "public_development_case",
    "held_out_independent",
]


ExternalAdjudicationKind = Literal[
    "public_security_advisory",
    "public_merged_fix",
    "public_issue",
    "qualification_human_review",
]

_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


class ExternalReplayProvenance(BaseModel):
    contamination_status: ExternalReplayContaminationStatus
    adjudication_kind: ExternalAdjudicationKind
    references: list[str]
    notes: str | None = None

    @field_validator("references")
    @classmethod
    def _references_non_empty(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value.strip()]
        if not normalized:
            raise ValueError("external replay provenance requires references")
        return normalized


class ExternalAssuranceReplayCase(BaseModel):
    case_id: str
    repository: str
    repository_url: str
    validation_class: ExternalReplayValidationClass
    base_sha: str
    head_sha: str
    description: str = ""
    safety_label: SafetyLabel
    expected_head_assurance: ExpectedHeadAssurance
    guarantee_manifest: dict[str, Any]
    protected_effect_profile: dict[str, Any]
    provenance: ExternalReplayProvenance
    qualification_human_adjudicated: bool = False
    human_review_minutes: float | None = Field(default=None, ge=0)

    @field_validator("case_id", "repository", "repository_url")
    @classmethod
    def _required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("external replay identity fields must be non-empty")
        return value

    @field_validator("base_sha", "head_sha")
    @classmethod
    def _full_commit_sha(cls, value: str) -> str:
        value = value.strip().lower()
        if not _FULL_SHA.fullmatch(value):
            raise ValueError("external replay revisions must be full 40-hex SHAs")
        return value

    @model_validator(mode="after")
    def _human_measurement_consistency(self) -> "ExternalAssuranceReplayCase":
        if (
            self.validation_class == "independent_external"
            and self.provenance.contamination_status != "held_out_independent"
        ):
            raise ValueError(
                "independent_external replay requires held_out_independent contamination status"
            )
        if (
            self.validation_class == "public_upstream_reduction"
            and self.provenance.contamination_status == "held_out_independent"
        ):
            raise ValueError(
                "held_out_independent replay must use independent_external validation class"
            )
        if (
            self.human_review_minutes is not None
            and not self.qualification_human_adjudicated
        ):
            raise ValueError(
                "human_review_minutes require qualification_human_adjudicated=true"
            )
        if (
            self.provenance.adjudication_kind == "qualification_human_review"
            and not self.qualification_human_adjudicated
        ):
            raise ValueError(
                "qualification_human_review provenance requires "
                "qualification_human_adjudicated=true"
            )
        return self


class ExternalAssuranceReplaySuite(BaseModel):
    schema_version: Literal["ovk.assurance_external_replay_suite.v1"] = (
        "ovk.assurance_external_replay_suite.v1"
    )
    suite_id: str
    description: str = ""
    cases: list[ExternalAssuranceReplayCase]


class ExternalAssuranceReplayCaseResult(BaseModel):
    case_id: str
    repository: str
    repository_url: str
    base_sha: str
    head_sha: str
    upstream_base_material_digest: str
    upstream_head_material_digest: str
    selected_paths: list[str] = Field(default_factory=list)
    qualification_result: AssuranceQualificationCaseResult


class ExternalAssuranceReplayReport(BaseModel):
    schema_version: Literal["ovk.assurance_external_replay_report.v1"] = (
        "ovk.assurance_external_replay_report.v1"
    )
    suite_id: str
    collected_at: str
    cases_total: int = Field(ge=1)
    results: list[ExternalAssuranceReplayCaseResult]


def load_external_assurance_replay_suite(
    path: Path,
) -> ExternalAssuranceReplaySuite:
    payload = json.loads(path.read_text(encoding="utf-8"))
    require_schema_valid(
        payload,
        load_json(schema_path("assurance.external_replay.suite.schema.json")),
        context="external assurance replay suite",
    )
    return ExternalAssuranceReplaySuite.model_validate(payload)


def validate_external_assurance_replay_report(
    report: ExternalAssuranceReplayReport | dict[str, Any],
) -> None:
    payload = (
        report.model_dump(mode="json")
        if isinstance(report, ExternalAssuranceReplayReport)
        else dict(report)
    )
    require_schema_valid(
        payload,
        load_json(schema_path("assurance.external_replay.report.schema.json")),
        context="external assurance replay report",
    )


def _git(cwd: Path, *args: str, timeout: int = 120) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "git command failed: "
            + " ".join(args)
            + ": "
            + completed.stderr.strip()
        )
    return completed.stdout


def _validate_repository_url(
    case: ExternalAssuranceReplayCase,
    *,
    allow_local_file_urls: bool,
) -> None:
    parsed = urlparse(case.repository_url)

    if allow_local_file_urls and parsed.scheme == "file":
        return

    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise ValueError(
            "external replay repository_url must be an https://github.com URL"
        )

    expected = "/" + case.repository.strip("/") + ".git"
    accepted = {
        "/" + case.repository.strip("/"),
        expected,
    }
    if parsed.path.rstrip("/") not in {item.rstrip("/") for item in accepted}:
        raise ValueError(
            "repository_url path does not match declared repository identity"
        )


def _clone_repository(
    case: ExternalAssuranceReplayCase,
    destination: Path,
    *,
    allow_local_file_urls: bool,
) -> None:
    _validate_repository_url(
        case,
        allow_local_file_urls=allow_local_file_urls,
    )
    completed = subprocess.run(
        [
            "git",
            "clone",
            "--no-checkout",
            "--filter=blob:none",
            case.repository_url,
            str(destination),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
        timeout=180,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "external repository clone failed: " + completed.stderr.strip()
        )

    for revision in (case.base_sha, case.head_sha):
        probe = subprocess.run(
            ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
            cwd=destination,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        if probe.returncode == 0:
            continue
        fetch = subprocess.run(
            ["git", "fetch", "--no-tags", "origin", revision],
            cwd=destination,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        if fetch.returncode != 0:
            raise RuntimeError(
                f"unable to fetch pinned external revision {revision}: "
                + fetch.stderr.strip()
            )
        verify = subprocess.run(
            ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
            cwd=destination,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        if verify.returncode != 0:
            raise RuntimeError(
                f"pinned external revision unavailable after fetch: {revision}"
            )


def _paths_at_revision(repo: Path, revision: str) -> list[str]:
    return sorted(
        line.strip()
        for line in _git(
            repo,
            "ls-tree",
            "-r",
            "--name-only",
            revision,
        ).splitlines()
        if line.strip()
    )


def _matches(path: str, patterns: list[str]) -> bool:
    candidate = PurePosixPath(path)
    return any(candidate.match(pattern) for pattern in patterns)


def _selected_paths(
    repo: Path,
    case: ExternalAssuranceReplayCase,
    profile: ProtectedEffectProfileConfig,
) -> list[str]:
    base_paths = _paths_at_revision(repo, case.base_sha)
    head_paths = _paths_at_revision(repo, case.head_sha)
    selected = sorted(
        {
            path
            for path in base_paths + head_paths
            if _matches(path, profile.source_paths)
        }
    )
    if not selected:
        raise ValueError(
            "trusted Protected Effect profile matched no files in pinned "
            "external revisions"
        )
    if len(selected) > profile.max_files:
        raise ValueError("external replay source_file_limit_exceeded")
    return selected


def _revision_files(
    repo: Path,
    revision: str,
    selected_paths: list[str],
    *,
    max_total_bytes: int,
) -> dict[str, str]:
    available = set(_paths_at_revision(repo, revision))
    files: dict[str, str] = {}
    total = 0
    for path in selected_paths:
        if path not in available:
            continue
        content = _git(repo, "show", f"{revision}:{path}")
        total += len(content.encode("utf-8"))
        if total > max_total_bytes:
            raise ValueError("external replay source_byte_limit_exceeded")
        files[path] = content
    return files


def _material_digest(files: dict[str, str]) -> str:
    return content_digest(
        {
            path: content_digest(content)
            for path, content in sorted(files.items())
        }
    )


def replay_external_assurance_case(
    case: ExternalAssuranceReplayCase,
    *,
    allow_local_file_urls: bool = False,
    signing_key: str = "external-replay-signing-key",
    worker_image_digest: str = "sha256:external-replay-worker",
) -> ExternalAssuranceReplayCaseResult:
    """Replay one pinned upstream transition through the qualification runner."""

    profile = ProtectedEffectProfileConfig.model_validate(
        case.protected_effect_profile
    )

    with TemporaryDirectory(prefix="ovk-external-assurance-") as tmp:
        upstream = Path(tmp) / "upstream"
        _clone_repository(
            case,
            upstream,
            allow_local_file_urls=allow_local_file_urls,
        )
        selected = _selected_paths(upstream, case, profile)
        base_files = _revision_files(
            upstream,
            case.base_sha,
            selected,
            max_total_bytes=profile.max_total_bytes,
        )
        head_files = _revision_files(
            upstream,
            case.head_sha,
            selected,
            max_total_bytes=profile.max_total_bytes,
        )

        base_digest = _material_digest(base_files)
        head_digest = _material_digest(head_files)

        qualification_case = AssuranceQualificationCase(
            case_id=case.case_id,
            repository=case.repository,
            description=case.description,
            validation_class=case.validation_class,
            safety_label=case.safety_label,
            expected_head_assurance=case.expected_head_assurance,
            provenance={
                "kind": "pinned_external_replay",
                "repository_url": case.repository_url,
                "base_sha": case.base_sha,
                "head_sha": case.head_sha,
                "upstream_base_material_digest": base_digest,
                "upstream_head_material_digest": head_digest,
                "contamination_status": case.provenance.contamination_status,
                "adjudication_kind": case.provenance.adjudication_kind,
                "references": case.provenance.references,
                "notes": case.provenance.notes,
            },
            base_files=base_files,
            head_files=head_files,
            guarantee_manifest=case.guarantee_manifest,
            protected_effect_profile=case.protected_effect_profile,
            human_adjudicated=case.qualification_human_adjudicated,
            human_review_minutes=case.human_review_minutes,
        )
        result = run_assurance_qualification_case(
            qualification_case,
            signing_key=signing_key,
            worker_image_digest=worker_image_digest,
        )

        return ExternalAssuranceReplayCaseResult(
            case_id=case.case_id,
            repository=case.repository,
            repository_url=case.repository_url,
            base_sha=case.base_sha,
            head_sha=case.head_sha,
            upstream_base_material_digest=base_digest,
            upstream_head_material_digest=head_digest,
            selected_paths=selected,
            qualification_result=result,
        )


def run_external_assurance_replay_suite(
    suite: ExternalAssuranceReplaySuite,
    *,
    allow_local_file_urls: bool = False,
) -> ExternalAssuranceReplayReport:
    results = [
        replay_external_assurance_case(
            case,
            allow_local_file_urls=allow_local_file_urls,
        )
        for case in suite.cases
    ]
    return ExternalAssuranceReplayReport(
        suite_id=suite.suite_id,
        collected_at=(
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        cases_total=len(results),
        results=results,
    )


def qualification_results_from_external_report(
    report: ExternalAssuranceReplayReport,
) -> list[AssuranceQualificationCaseResult]:
    """Project replay results into the common product-qualification metric type."""

    return [item.qualification_result for item in report.results]
