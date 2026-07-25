"""Adapter conformance matrix (OVK-05 / OVK-PR4).

Every advertised adapter (10 formal backends + 5 lane adapters) must provide:

1. pass fixture
2. fail fixture
3. malformed-output fixture
4. timeout fixture
5. unavailable-binary fixture
6. documentation of what a pass establishes
7. documentation of what remains outside the claim

``release_status=stable`` requires all seven. Non-conformant adapters that claim
stable are auto-downgraded when capability tables are rendered.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ovk.adapters.wave2_oracle import classify_conformance_flags
from ovk.core.evidence_integrity import seal_evidence, verify_evidence_digest
from ovk.core.json_io import read_json_file
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus
from ovk.paths import ovk_data_root

FORMAL_BACKEND_IDS: tuple[str, ...] = (
    "opa",
    "z3",
    "cbmc",
    "cedar",
    "tla+",
    "kani",
    "dafny",
    "verus",
    "lean",
    "alloy",
)

LANE_ADAPTER_IDS: tuple[str, ...] = (
    "lane-self-protection",
    "lane-authorization",
    "lane-infrastructure",
    "lane-ci-secrets",
    "lane-deployment",
)

ADVERTISED_ADAPTER_IDS: tuple[str, ...] = FORMAL_BACKEND_IDS + LANE_ADAPTER_IDS

REQUIRED_FIXTURE_CASES: tuple[str, ...] = (
    "pass",
    "fail",
    "malformed",
    "timeout",
    "unavailable",
)

REQUIRED_DOC_KEYS: tuple[str, ...] = (
    "pass_establishes",
    "outside_claim",
)

# Directory name under adapters/ for checker_id values that differ from folder names.
ADAPTER_DIR_ALIASES: dict[str, str] = {
    "tla+": "tla",
}

EXPECTED_STATUS_BY_CASE: dict[str, frozenset[str]] = {
    "pass": frozenset({"pass"}),
    "fail": frozenset({"fail"}),
    "malformed": frozenset({"unknown", "error"}),
    "timeout": frozenset({"unknown", "error"}),
    "unavailable": frozenset({"unknown", "error", "skipped"}),
}

LANE_ID_TO_LANE: dict[str, str] = {
    "lane-self-protection": "self_protection",
    "lane-authorization": "authorization",
    "lane-infrastructure": "infrastructure",
    "lane-ci-secrets": "ci_secrets",
    "lane-deployment": "deployment",
}

_PASS_SECTION = re.compile(
    r"(?im)^#{1,3}\s*pass\s+establishes\s*$",
)
_OUTSIDE_SECTION = re.compile(
    r"(?im)^#{1,3}\s*(?:outside\s+(?:the\s+)?claim|outside\s+the\s+claim)\s*$",
)


def adapter_directory_name(adapter_id: str) -> str:
    """Return the filesystem directory name for an advertised adapter id."""
    return ADAPTER_DIR_ALIASES.get(adapter_id, adapter_id)


def conformance_dir(adapter_id: str, *, root: Path | None = None) -> Path:
    """Return ``adapters/<id>/conformance`` for an advertised adapter."""
    base = root or ovk_data_root()
    return base / "adapters" / adapter_directory_name(adapter_id) / "conformance"


def manifest_path(adapter_id: str, *, root: Path | None = None) -> Path:
    return conformance_dir(adapter_id, root=root) / "manifest.json"


def claims_path(adapter_id: str, *, root: Path | None = None) -> Path:
    return conformance_dir(adapter_id, root=root) / "CLAIMS.md"


def load_conformance_manifest(adapter_id: str, *, root: Path | None = None) -> dict[str, Any]:
    path = manifest_path(adapter_id, root=root)
    if not path.is_file():
        raise FileNotFoundError(f"missing conformance manifest: {path}")
    payload = read_json_file(path)
    if not isinstance(payload, dict):
        raise ValueError(f"conformance manifest must be an object: {path}")
    return payload


def resolve_fixture_path(
    adapter_id: str,
    relative: str,
    *,
    root: Path | None = None,
) -> Path:
    """Resolve a fixture path relative to the repo root or the conformance dir."""
    base = root or ovk_data_root()
    candidate = Path(relative)
    if candidate.is_absolute():
        return candidate
    from_root = base / candidate
    if from_root.exists():
        return from_root
    from_conformance = conformance_dir(adapter_id, root=base) / candidate
    return from_conformance


def _claim_status(evidence: VerificationEvidence) -> str:
    if evidence.backend_claims:
        return evidence.backend_claims[0].status.value
    decision = evidence.decision or {}
    recommendation = str(decision.get("merge_recommendation") or decision.get("decision_state") or "")
    mapping = {
        "allow": "pass",
        "block": "fail",
        "require_human_review": "unknown",
        "needs_review": "unknown",
        "unknown": "unknown",
        "error": "error",
        "skipped": "skipped",
    }
    return mapping.get(recommendation, "unknown")


def _synthetic_evidence(
    *,
    adapter_id: str,
    status: str,
    summary: str,
    failure_mode: str,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    adapter_version: str = "0.1.0",
) -> VerificationEvidence:
    verification_status = VerificationStatus(status)
    merge_by_status = {
        VerificationStatus.PASS: "allow",
        VerificationStatus.FAIL: "block",
        VerificationStatus.UNKNOWN: "require_human_review",
        VerificationStatus.ERROR: "require_human_review",
        VerificationStatus.SKIPPED: "require_human_review",
    }
    recommendation = merge_by_status[verification_status]
    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha
    counterexamples: list[dict[str, Any]] = []
    if verification_status != VerificationStatus.PASS:
        counterexamples = [{"summary": summary, "failure_mode": failure_mode}]
    return VerificationEvidence(
        evidence_id=f"conformance-{adapter_id}-{head_sha[:8]}",
        schema_version="ovk.evidence.v3",
        subject=subject,
        intent={
            "intent_id": f"{adapter_id}-conformance",
            "title": f"{adapter_id} conformance",
            "risk": {"severity": "medium"},
        },
        backend_claims=[
            BackendClaim(
                backend=adapter_id,
                guarantee_type="adapter_conformance",
                status=verification_status,
                assumptions=["Conformance fixture evaluation."],
                limits=["Synthetic conformance fixture; not a production claim."],
                adapter_version=adapter_version,
            )
        ],
        counterexamples=counterexamples,
        decision={
            "merge_recommendation": recommendation,
            "human_review_required": recommendation != "allow",
            "override_allowed": recommendation != "allow",
            "override_requires": ["maintainer"] if recommendation != "allow" else [],
        },
    )


def _evaluate_opa_fixture(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
) -> VerificationEvidence:
    from ovk.adapters.opa.evidence import opa_raw_to_evidence

    early = classify_conformance_flags(data)
    if early is not None:
        status, counterexamples = early
        reason = counterexamples[0]["summary"] if counterexamples else status
        return opa_raw_to_evidence(
            {"status": status, "reason": reason, "violations": []},
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
        )
    raw = {
        "status": str(data.get("status", "pass" if not data.get("violations") else "fail")),
        "violations": list(data.get("violations") or []),
        "reason": data.get("reason"),
    }
    return opa_raw_to_evidence(raw, repo=repo, head_sha=head_sha, base_sha=base_sha)


def _evaluate_z3_fixture(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
) -> VerificationEvidence:
    early = classify_conformance_flags(data)
    if early is not None:
        status, counterexamples = early
        return _synthetic_evidence(
            adapter_id="z3",
            status=status,
            summary=counterexamples[0]["summary"],
            failure_mode=str(counterexamples[0]["failure_mode"]),
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
        )
    from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path

    return evaluate_validated_authorization_path(
        data, repo=repo, head_sha=head_sha, base_sha=base_sha
    )


def _evaluate_lane_fixture(
    adapter_id: str,
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
) -> VerificationEvidence:
    early = classify_conformance_flags(data)
    if early is not None:
        status, counterexamples = early
        return _synthetic_evidence(
            adapter_id=adapter_id,
            status=status,
            summary=counterexamples[0]["summary"],
            failure_mode=str(counterexamples[0]["failure_mode"]),
            repo=repo,
            head_sha=head_sha,
            base_sha=base_sha,
        )
    from ovk.core.multi_lane import evaluate_lane

    lane = LANE_ID_TO_LANE[adapter_id]
    return evaluate_lane(lane, data, repo=repo, head_sha=head_sha, base_sha=base_sha)


def _evaluate_formal_backend_fixture(
    adapter_id: str,
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
) -> VerificationEvidence:
    if adapter_id == "opa":
        return _evaluate_opa_fixture(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    if adapter_id == "z3":
        return _evaluate_z3_fixture(data, repo=repo, head_sha=head_sha, base_sha=base_sha)
    from ovk.core.backend_fixture import evaluate_backend_fixture

    # Ensure intent_id is present for backends that rely on it.
    payload = dict(data)
    if "intent_id" not in payload:
        intent_defaults = {
            "cbmc": "cbmc-harness-check",
            "cedar": "cedar-policy-check",
            "tla+": "tla-state-check",
            "kani": "kani-harness-check",
            "dafny": "dafny-obligation-check",
            "verus": "verus-harness-check",
            "lean": "lean-proof-check",
            "alloy": "alloy-model-check",
        }
        if adapter_id in intent_defaults:
            payload["intent_id"] = intent_defaults[adapter_id]
    return evaluate_backend_fixture(payload, repo=repo, head_sha=head_sha, base_sha=base_sha)


def evaluate_conformance_fixture(
    adapter_id: str,
    data: dict[str, Any],
    *,
    repo: str = "ovk/conformance",
    head_sha: str = "conformance-head",
    base_sha: str | None = "conformance-base",
) -> VerificationEvidence:
    """Evaluate one conformance fixture payload for an advertised adapter."""
    if adapter_id in LANE_ADAPTER_IDS:
        return _evaluate_lane_fixture(
            adapter_id, data, repo=repo, head_sha=head_sha, base_sha=base_sha
        )
    if adapter_id in FORMAL_BACKEND_IDS:
        return _evaluate_formal_backend_fixture(
            adapter_id, data, repo=repo, head_sha=head_sha, base_sha=base_sha
        )
    raise ValueError(f"unknown advertised adapter id: {adapter_id!r}")


def _doc_sections_present(claims_text: str) -> tuple[bool, bool]:
    has_pass = bool(_PASS_SECTION.search(claims_text))
    has_outside = bool(_OUTSIDE_SECTION.search(claims_text))
    return has_pass, has_outside


def structural_conformance_failures(
    adapter_id: str,
    *,
    root: Path | None = None,
) -> list[str]:
    """Return structural failures for the seven-item conformance matrix."""
    base = root or ovk_data_root()
    failures: list[str] = []
    conf = conformance_dir(adapter_id, root=base)
    if not conf.is_dir():
        return [f"{adapter_id}: missing conformance directory {conf}"]

    try:
        manifest = load_conformance_manifest(adapter_id, root=base)
    except (OSError, ValueError, FileNotFoundError) as error:
        return [f"{adapter_id}: {error}"]

    if str(manifest.get("adapter_id", "")) not in {adapter_id, adapter_directory_name(adapter_id)}:
        failures.append(
            f"{adapter_id}: manifest adapter_id {manifest.get('adapter_id')!r} "
            f"does not match advertised id"
        )

    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, dict):
        failures.append(f"{adapter_id}: manifest.fixtures must be an object")
        fixtures = {}

    for case in REQUIRED_FIXTURE_CASES:
        entry = fixtures.get(case)
        if not isinstance(entry, dict):
            failures.append(f"{adapter_id}: missing fixtures.{case}")
            continue
        rel = entry.get("path")
        if not isinstance(rel, str) or not rel.strip():
            failures.append(f"{adapter_id}: fixtures.{case}.path must be a non-empty string")
            continue
        path = resolve_fixture_path(adapter_id, rel, root=base)
        if not path.is_file():
            failures.append(f"{adapter_id}: fixtures.{case} path not found: {path}")

    docs = manifest.get("docs")
    if not isinstance(docs, dict):
        failures.append(f"{adapter_id}: manifest.docs must be an object")
        docs = {}

    claims = claims_path(adapter_id, root=base)
    if not claims.is_file():
        failures.append(f"{adapter_id}: missing CLAIMS.md ({claims})")
    else:
        text = claims.read_text(encoding="utf-8")
        has_pass, has_outside = _doc_sections_present(text)
        if not has_pass and "pass_establishes" not in docs:
            failures.append(f"{adapter_id}: CLAIMS.md missing 'Pass establishes' section")
        if not has_outside and "outside_claim" not in docs:
            failures.append(f"{adapter_id}: CLAIMS.md missing 'Outside the claim' section")
        for key in REQUIRED_DOC_KEYS:
            if key not in docs and not (has_pass if key == "pass_establishes" else has_outside):
                failures.append(f"{adapter_id}: docs.{key} missing from manifest and CLAIMS.md")

    return failures


def behavioral_conformance_failures(
    adapter_id: str,
    *,
    root: Path | None = None,
    seal: bool = True,
) -> list[str]:
    """Evaluate fixtures, check expected statuses, and require integrity-valid evidence."""
    base = root or ovk_data_root()
    structural = structural_conformance_failures(adapter_id, root=base)
    if structural:
        return structural

    manifest = load_conformance_manifest(adapter_id, root=base)
    fixtures = manifest["fixtures"]
    failures: list[str] = []

    for case in REQUIRED_FIXTURE_CASES:
        entry = fixtures[case]
        path = resolve_fixture_path(adapter_id, str(entry["path"]), root=base)
        try:
            data = read_json_file(path)
        except (OSError, ValueError) as error:
            failures.append(f"{adapter_id}/{case}: could not read fixture ({error})")
            continue
        if not isinstance(data, dict):
            failures.append(f"{adapter_id}/{case}: fixture must be a JSON object")
            continue
        try:
            evidence = evaluate_conformance_fixture(adapter_id, data)
        except Exception as error:  # noqa: BLE001 - conformance boundary
            failures.append(f"{adapter_id}/{case}: evaluation raised {type(error).__name__}: {error}")
            continue

        status = _claim_status(evidence)
        expected = EXPECTED_STATUS_BY_CASE[case]
        override = entry.get("expected_status")
        if isinstance(override, str) and override.strip():
            expected = frozenset({override.strip()})
        if status not in expected:
            failures.append(
                f"{adapter_id}/{case}: expected status in {sorted(expected)}, got {status!r}"
            )
            continue

        if seal:
            try:
                sealed = seal_evidence(evidence)
            except Exception as error:  # noqa: BLE001
                failures.append(
                    f"{adapter_id}/{case}: seal_evidence failed ({type(error).__name__}: {error})"
                )
                continue
            if not verify_evidence_digest(sealed):
                failures.append(f"{adapter_id}/{case}: evidence_digest verification failed")

    return failures


def is_fully_conformant(adapter_id: str, *, root: Path | None = None, seal: bool = True) -> bool:
    """Return True when the adapter satisfies all seven conformance items."""
    return not behavioral_conformance_failures(adapter_id, root=root, seal=seal)


def effective_release_status(
    manifest: dict[str, Any],
    *,
    root: Path | None = None,
    conformant: bool | None = None,
) -> str:
    """Return the honesty-adjusted release_status for rendering.

    Non-conformant adapters that declare ``stable`` are auto-downgraded to
    ``preview`` (native candidates) or ``experimental`` (everyone else).
    """
    declared = str(manifest.get("release_status") or "experimental")
    if declared != "stable":
        return declared
    checker = str(manifest.get("checker_id") or manifest.get("tool", {}).get("name") or "")
    ok = is_fully_conformant(checker, root=root) if conformant is None else conformant
    if ok:
        return "stable"
    native = manifest.get("native_execution")
    if native is True or checker in {"opa", "z3", "cbmc"}:
        return "preview"
    return "experimental"


def apply_release_status_honesty(
    manifest: dict[str, Any],
    *,
    root: Path | None = None,
    conformant: bool | None = None,
) -> dict[str, Any]:
    """Return a shallow copy with auto-downgraded ``release_status`` when needed."""
    adjusted = dict(manifest)
    effective = effective_release_status(manifest, root=root, conformant=conformant)
    if effective != str(manifest.get("release_status")):
        adjusted["release_status"] = effective
        adjusted["_release_status_auto_downgraded"] = True
    return adjusted


def validate_all_adapter_conformance(
    *,
    root: Path | None = None,
    seal: bool = True,
    adapters: tuple[str, ...] | None = None,
) -> list[str]:
    """Validate structural + behavioral conformance for all advertised adapters."""
    base = root or ovk_data_root()
    failures: list[str] = []
    for adapter_id in adapters or ADVERTISED_ADAPTER_IDS:
        failures.extend(behavioral_conformance_failures(adapter_id, root=base, seal=seal))
    return failures


def stable_requires_conformance_failures(
    manifests: list[dict[str, Any]],
    *,
    root: Path | None = None,
) -> list[str]:
    """Fail when any manifest claims stable without full conformance."""
    base = root or ovk_data_root()
    failures: list[str] = []
    for manifest in manifests:
        if str(manifest.get("release_status")) != "stable":
            continue
        checker = str(manifest.get("checker_id") or manifest.get("tool", {}).get("name") or "")
        if not checker:
            failures.append("stable capability missing checker_id")
            continue
        if not is_fully_conformant(checker, root=base):
            failures.append(
                f"{checker}: release_status 'stable' requires full seven-item "
                "adapter conformance (OVK-PR4)"
            )
    return failures
