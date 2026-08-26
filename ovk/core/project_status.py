"""Machine claim registry and project-status generation (WP-15).

Project status is a public claim surface. It therefore recomputes source-profile
maturity from the current normative qualification contract and never trusts
serialized summary labels such as ``maturity`` or ``strict_ready``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ovk.core.source_profile_maturity import qualification_from_dict
from ovk.core.source_profiles import KNOWN_SOURCE_PROFILES
from ovk.core.support_contracts import load_all_support_contracts

CLAIM_REGISTRY_SCHEMA = "ovk.claim_registry.v1"
PROJECT_STATUS_SCHEMA = "ovk.project_status.v1"
QUALIFICATION_V1_SCHEMA = "ovk.source_profile_qualification.v1"


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_claim_registry(repo_root: Path) -> dict[str, Any]:
    """Map advertised claims to proposition/profile/guarantee/trust boundary."""
    contracts = load_all_support_contracts(repo_root=repo_root)
    claims: list[dict[str, Any]] = []
    for profile_id, contract in sorted(contracts.items()):
        claims.append(
            {
                "claim_id": f"profile:{profile_id}",
                "proposition": contract.proposition,
                "profile_id": profile_id,
                "guarantee_type": contract.guarantee_type,
                "schema": "ovk.support_contract.v1",
                "materials": list(contract.required_materials),
                "trust_boundary": "strict_only_inside_support_contract; unsupported_forces_review",
                "maturity_field": "conformance_status_v3",
                "maturity_note": "externally_calibrated_strict is not locally derivable",
                "compiler_binding": contract.compiler_binding,
            }
        )
    claims.extend(
        [
            {
                "claim_id": "bench:formalpr_bench_regression",
                "proposition": "FormalPR-Bench measures regression against a frozen corpus/generator/scorer.",
                "profile_id": None,
                "guarantee_type": "regression_benchmark",
                "schema": "formal_pr_bench.leaderboard.v1",
                "materials": ["benchmarks/formal_pr_bench"],
                "trust_boundary": "not_external_calibration",
                "maturity_field": "benchmark_source_sha",
                "maturity_note": "Must not mint verified_source_sha",
            },
            {
                "claim_id": "release:verified_source_sha",
                "proposition": "verified_source_sha is populated only after release-ledger offline verification.",
                "profile_id": None,
                "guarantee_type": "release_ledger_authorization",
                "schema": "ovk.release_ledger.v1",
                "materials": [".verification/release-ledger.json"],
                "trust_boundary": "WP-17 only",
                "maturity_field": "verified_source_sha",
                "maturity_note": "Ordinary holdout/badge/CI must not set this field",
            },
        ]
    )
    return {
        "schema_version": CLAIM_REGISTRY_SCHEMA,
        "normative_maturity_field": "conformance_status_v3",
        "claims": claims,
        "claim_count": len(claims),
    }


def _load_qualification_payload(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _normalized_profile_status(
    *,
    profile_id: str,
    contract_version: str,
    qualification_payload: dict[str, Any],
    candidate_sha: str,
) -> dict[str, Any]:
    """Recompute one public maturity row from normative fields.

    Qualification v1 is declaration-derived and has no candidate-bound execution
    attestation contract. It may inform diagnostics, but it cannot authorize a
    candidate-specific maturity promotion. In particular, stale or forged
    serialized ``maturity``/``strict_ready`` values are ignored.
    """
    schema = qualification_payload.get("schema_version")
    profiles = qualification_payload.get("profiles")
    row = profiles.get(profile_id) if isinstance(profiles, dict) else None
    qualification_dict = row.get("qualification") if isinstance(row, dict) else None

    qualification_valid = False
    candidate_ready = False
    normative_strict_ready = False
    reasons: list[str] = []

    if isinstance(qualification_dict, dict):
        try:
            qualification = qualification_from_dict(qualification_dict)
        except (TypeError, ValueError):
            reasons.append("qualification_payload_invalid")
        else:
            if qualification.profile_id != profile_id:
                reasons.append("qualification_profile_mismatch")
            elif qualification.support_contract_version != contract_version:
                reasons.append("qualification_support_contract_mismatch")
            else:
                qualification_valid = True
                candidate_ready = qualification.candidate_ready()
                normative_strict_ready = qualification.strict_ready()
    else:
        reasons.append("qualification_missing")

    # v1 has no candidate identity or independently verified execution-attestation
    # binding. Refuse all candidate-specific promotion from this schema even when
    # its serialized qualification happens to satisfy today's numeric thresholds.
    candidate_bound = False
    if schema == QUALIFICATION_V1_SCHEMA:
        reasons.append("qualification_v1_not_candidate_bound")
    elif schema is None:
        reasons.append("qualification_schema_missing")
    else:
        reasons.append(f"qualification_schema_not_authoritative:{schema}")

    if candidate_sha == "unknown":
        reasons.append("candidate_sha_unknown")

    strict_ready = bool(
        qualification_valid
        and candidate_bound
        and candidate_sha != "unknown"
        and normative_strict_ready
    )

    # Candidate maturity is also candidate-specific. Until qualification has a
    # verified candidate binding, the strongest public status is advisory.
    maturity = "source_profile_strict_eligible" if strict_ready else "executable_advisory"

    return {
        "support_contract_version": contract_version,
        "maturity": maturity,
        "strict_ready": strict_ready,
        "qualification_valid": qualification_valid,
        "qualification_schema": schema,
        "candidate_bound": candidate_bound,
        "candidate_ready_unbound": candidate_ready,
        "normative_strict_ready_unbound": normative_strict_ready,
        "status_reasons": sorted(set(reasons)),
    }


def build_project_status(repo_root: Path, *, candidate_sha: str | None = None) -> dict[str, Any]:
    """Generate the machine status source for docs and badges.

    The result is conservative by construction: source-profile maturity is
    recomputed from the current dataclass contract, and unbound qualification
    artifacts cannot promote a specific candidate.
    """
    if candidate_sha is None:
        candidate_sha = "unknown"
    contracts = load_all_support_contracts(repo_root=repo_root)
    qualification_path = repo_root / ".verification" / "source-profile-qualification.json"
    qualification_payload = _load_qualification_payload(qualification_path)

    profile_statuses = {
        profile_id: _normalized_profile_status(
            profile_id=profile_id,
            contract_version=contracts[profile_id].contract_version,
            qualification_payload=qualification_payload,
            candidate_sha=candidate_sha,
        )
        for profile_id in sorted(KNOWN_SOURCE_PROFILES)
    }

    conformance = repo_root / "docs" / "benchmarks" / "template-conformance.json"
    badge = repo_root / "docs" / "benchmarks" / "leaderboard-badge.json"
    return {
        "schema_version": PROJECT_STATUS_SCHEMA,
        "candidate_sha": candidate_sha,
        "required_runs": [
            "ci",
            "native-backends-tier1",
            "native-backends-tier1b",
            "holdout-predict",
            "holdout-eval",
            "consumer-pin-verification",
            "dogfood-regression",
        ],
        "profile_statuses": profile_statuses,
        "artifacts": {
            "template_conformance_sha256": _sha256_file(conformance),
            "leaderboard_badge_sha256": _sha256_file(badge),
            "qualification_sha256": _sha256_file(qualification_path),
            "qualification_schema": qualification_payload.get("schema_version"),
            "claim_registry_path": ".verification/claim-registry.json",
        },
        "open_blockers": [
            item
            for item in [
                "verified_source_sha deferred to WP-17 release ledger",
                "externally_calibrated_strict not claimed",
                *(
                    f"{pid}: not strict_ready"
                    for pid, status in profile_statuses.items()
                    if not status.get("strict_ready")
                ),
            ]
        ],
        "maturity_contract": {
            "normative_status_field": "conformance_status_v3",
            "production_status_is_maturity_synonym": False,
            "badge_may_set_verified_source_sha": False,
            "serialized_maturity_is_authoritative": False,
            "qualification_v1_can_authorize_candidate_promotion": False,
        },
    }


def render_project_status_markdown(status: dict[str, Any]) -> str:
    """Render a project-status payload into the committed Markdown surface."""
    lines = [
        "# OVK Status",
        "",
        f"Generated from `.verification/project-status.json` (candidate `{status['candidate_sha']}`).",
        "",
        "Do not hand-edit this file. Regenerate with `python scripts/build_project_status.py`.",
        "Adoption and pin guidance: [CURRENT_RELEASE_STATUS.md](CURRENT_RELEASE_STATUS.md).",
        "",
        "## Maturity",
        "",
        "Normative field: `conformance_status_v3`. `production_status` is legacy catalog metadata only.",
        "Local `source_profile_strict_eligible` is not `externally_calibrated_strict`.",
        "FormalPR-Bench is regression-only; `verified_source_sha` requires the release ledger.",
        "Qualification v1 is declaration-derived and cannot authorize candidate-specific maturity.",
        "",
        "## Profile statuses",
        "",
    ]
    for profile_id, row in status["profile_statuses"].items():
        lines.append(
            f"- `{profile_id}`: {row['maturity']} (contract {row['support_contract_version']}, "
            f"strict_ready={row['strict_ready']}, candidate_bound={row['candidate_bound']})"
        )
    lines.extend(["", "## Open blockers", ""])
    for blocker in status["open_blockers"][:20]:
        lines.append(f"- {blocker}")
    lines.append("")
    return "\n".join(lines)


def check_committed_status_truthfulness(repo_root: Path) -> list[str]:
    """Reject stale or stronger-than-supported claims in ``docs/STATUS.md``.

    A Git commit cannot contain its own final SHA without changing that SHA.
    Consequently the committed status page is intentionally an unbound static
    snapshot (candidate ``unknown``). Exact-candidate authorization is delegated
    to release-ledger / external verification artifacts rather than this file.
    """
    path = repo_root / "docs" / "STATUS.md"
    if not path.is_file():
        return ["docs/STATUS.md is missing"]
    actual = path.read_text(encoding="utf-8")

    # Build the strongest status that the committed, unbound page is allowed to
    # publish. Qualification artifacts in .verification are deliberately ignored
    # by using an isolated projection with no qualification payload semantics:
    # v1 cannot authorize promotion and current code therefore yields advisory.
    contracts = load_all_support_contracts(repo_root=repo_root)
    expected_lines = {
        profile_id: (
            f"- `{profile_id}`: executable_advisory "
            f"(contract {contracts[profile_id].contract_version}, strict_ready=False, candidate_bound=False)"
        )
        for profile_id in sorted(KNOWN_SOURCE_PROFILES)
    }

    failures: list[str] = []
    if "(candidate `unknown`)." not in actual:
        failures.append("docs/STATUS.md must use candidate `unknown`; exact SHA belongs in release evidence")
    for profile_id, expected in expected_lines.items():
        matching = [line for line in actual.splitlines() if line.startswith(f"- `{profile_id}`:")]
        if matching != [expected]:
            failures.append(
                f"docs/STATUS.md profile claim drift for {profile_id}: expected {expected!r}, got {matching!r}"
            )
    return failures


def write_project_status_and_claims(
    repo_root: Path,
    *,
    candidate_sha: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    claims = build_claim_registry(repo_root)
    status = build_project_status(repo_root, candidate_sha=candidate_sha)
    out_dir = repo_root / ".verification"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "claim-registry.json").write_text(
        json.dumps(claims, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "project-status.json").write_text(
        json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (repo_root / "docs" / "STATUS.md").write_text(
        render_project_status_markdown(status), encoding="utf-8"
    )
    return claims, status
