"""Machine claim registry and project-status generation (WP-15)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ovk.core.source_profiles import KNOWN_SOURCE_PROFILES
from ovk.core.support_contracts import load_all_support_contracts

CLAIM_REGISTRY_SCHEMA = "ovk.claim_registry.v1"
PROJECT_STATUS_SCHEMA = "ovk.project_status.v1"


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


def build_project_status(repo_root: Path, *, candidate_sha: str | None = None) -> dict[str, Any]:
    """Generate machine status source for docs/badges."""
    if candidate_sha is None:
        head = repo_root / ".git" / "HEAD"
        candidate_sha = "unknown"
        # Prefer explicit env-less placeholder; callers should pass GITHUB_SHA.
    contracts = load_all_support_contracts(repo_root=repo_root)
    qualification_path = repo_root / ".verification" / "source-profile-qualification.json"
    qualification = {}
    if qualification_path.is_file():
        qualification = json.loads(qualification_path.read_text(encoding="utf-8")).get("profiles") or {}

    profile_statuses = {}
    for profile_id in sorted(KNOWN_SOURCE_PROFILES):
        row = qualification.get(profile_id) if isinstance(qualification, dict) else None
        profile_statuses[profile_id] = {
            "support_contract_version": contracts[profile_id].contract_version,
            "maturity": (row or {}).get("maturity", "unknown"),
            "strict_ready": bool(((row or {}).get("qualification") or {}).get("strict_ready")),
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
        },
    }


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
    # Human status page generated from machine status (do not hand-author maturity).
    status_md = repo_root / "docs" / "STATUS.md"
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
        "",
        "## Profile statuses",
        "",
    ]
    for profile_id, row in status["profile_statuses"].items():
        lines.append(
            f"- `{profile_id}`: {row['maturity']} (contract {row['support_contract_version']}, "
            f"strict_ready={row['strict_ready']})"
        )
    lines.extend(["", "## Open blockers", ""])
    for blocker in status["open_blockers"][:20]:
        lines.append(f"- {blocker}")
    lines.append("")
    status_md.write_text("\n".join(lines), encoding="utf-8")
    return claims, status
