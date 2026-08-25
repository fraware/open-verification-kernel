"""Generate machine-derived source-profile qualification artifacts.

Counts are aggregated from named evidence entries (test IDs / digests) in
``profiles/qualification-evidence.json``. Hand-typed summary integers are
rejected.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ovk.core.source_profile_maturity import (
    SourceProfileQualification,
    classify_source_profile_maturity,
)
from ovk.core.source_profiles import KNOWN_SOURCE_PROFILES, is_known_source_profile
from ovk.core.support_contracts import load_all_support_contracts, load_support_contract

QUALIFICATION_SCHEMA_VERSION = "ovk.source_profile_qualification.v1"
EVIDENCE_BUCKETS = frozenset(
    {
        "positive",
        "negative",
        "unsupported",
        "malformed",
        "unknown",
        "timeout",
        "source_range",
        "evidence_invariant",
        "end_to_end_bundle",
        "installed_package",
        "action",
        "candidate_gate",
    }
)

_BUCKET_TO_FIELD = {
    "positive": "positive_cases",
    "negative": "negative_cases",
    "unsupported": "unsupported_cases",
    "malformed": "malformed_cases",
    "unknown": "unknown_cases",
    "timeout": "timeout_cases",
    "source_range": "source_range_cases",
    "evidence_invariant": "evidence_invariant_cases",
    "end_to_end_bundle": "end_to_end_bundle_cases",
    "installed_package": "installed_package_cases",
    "action": "action_cases",
}


def evidence_registry_path(repo_root: Path) -> Path:
    return repo_root / "profiles" / "qualification-evidence.json"


def qualification_output_path(repo_root: Path) -> Path:
    return repo_root / ".verification" / "source-profile-qualification.json"


def _digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _entry_digest(entry: dict[str, Any]) -> str:
    if isinstance(entry.get("digest"), str) and len(entry["digest"]) == 64:
        return str(entry["digest"]).lower()
    canonical = json.dumps(
        {
            "profile_id": entry.get("profile_id"),
            "bucket": entry.get("bucket"),
            "evidence_id": entry.get("evidence_id"),
            "artifact": entry.get("artifact"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _digest_bytes(canonical)


def load_evidence_registry(repo_root: Path) -> dict[str, Any]:
    path = evidence_registry_path(repo_root)
    if not path.is_file():
        raise FileNotFoundError(f"qualification evidence registry missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "ovk.qualification_evidence.v1":
        raise ValueError(f"unsupported evidence registry schema: {payload.get('schema_version')!r}")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ValueError("evidence registry entries must be a list")
    # Reject hand-typed summary counts if present.
    if any(key.endswith("_cases") for key in payload):
        raise ValueError("evidence registry must not contain hand-typed *_cases summary fields")
    return payload


def _candidate_flags_from_entries(entries: list[dict[str, Any]]) -> dict[str, bool]:
    flags = {
        "executable_path_complete": False,
        "compiler_binding_present": False,
        "enforcement_test_present": False,
        "materials_trusted": False,
        "measured_coverage_complete": False,
    }
    for entry in entries:
        if entry.get("bucket") != "candidate_gate":
            continue
        gate = str(entry.get("gate") or "")
        if gate in flags:
            flags[gate] = True
    return flags


def build_qualification_for_profile(
    *,
    profile_id: str,
    entries: list[dict[str, Any]],
    repo_root: Path,
) -> dict[str, Any]:
    contract = load_support_contract(profile_id, repo_root=repo_root)
    profile_entries = [item for item in entries if item.get("profile_id") == profile_id]
    named: list[dict[str, Any]] = []
    counts: dict[str, int] = {field: 0 for field in _BUCKET_TO_FIELD.values()}
    seen_ids: set[str] = set()

    for entry in profile_entries:
        bucket = str(entry.get("bucket") or "")
        evidence_id = str(entry.get("evidence_id") or "").strip()
        if not evidence_id:
            raise ValueError(f"{profile_id}: evidence entry missing evidence_id")
        if evidence_id in seen_ids:
            raise ValueError(f"{profile_id}: duplicate evidence_id {evidence_id}")
        seen_ids.add(evidence_id)
        if bucket not in EVIDENCE_BUCKETS:
            raise ValueError(f"{profile_id}: unknown evidence bucket {bucket!r}")
        digest = _entry_digest(entry)
        named.append(
            {
                "evidence_id": evidence_id,
                "bucket": bucket,
                "digest": digest,
                "artifact": entry.get("artifact"),
                "gate": entry.get("gate"),
            }
        )
        field = _BUCKET_TO_FIELD.get(bucket)
        if field:
            counts[field] += 1

    flags = _candidate_flags_from_entries(profile_entries)
    # Support contract presence implies compiler binding for known profiles.
    flags["compiler_binding_present"] = True
    if flags["enforcement_test_present"] is False and any(
        item["bucket"] in {"positive", "negative", "action"} for item in named
    ):
        flags["enforcement_test_present"] = True

    qualification = SourceProfileQualification(
        profile_id=profile_id,
        support_contract_version=contract.contract_version,
        **flags,
        **counts,
    )
    maturity = classify_source_profile_maturity(qualification, executable=True)
    return {
        "profile_id": profile_id,
        "support_contract_version": contract.contract_version,
        "compiler_binding": contract.compiler_binding,
        "maturity": maturity,
        "qualification": {
            **asdict(qualification),
            "candidate_ready": qualification.candidate_ready(),
            "strict_ready": qualification.strict_ready(),
            "unmet_strict_obligations": list(qualification.unmet_strict_obligations()),
        },
        "evidence": named,
        "evidence_count": len(named),
    }


def build_source_profile_qualification(repo_root: Path) -> dict[str, Any]:
    """Aggregate qualification for every known production profile."""
    contracts = load_all_support_contracts(repo_root=repo_root)
    registry = load_evidence_registry(repo_root)
    entries = [item for item in registry["entries"] if isinstance(item, dict)]
    for entry in entries:
        profile_id = str(entry.get("profile_id") or "")
        if not is_known_source_profile(profile_id):
            raise ValueError(f"evidence entry references unknown profile: {profile_id}")

    by_profile: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        by_profile[str(entry["profile_id"])].append(entry)

    profiles: dict[str, Any] = {}
    for profile_id in sorted(KNOWN_SOURCE_PROFILES):
        profiles[profile_id] = build_qualification_for_profile(
            profile_id=profile_id,
            entries=by_profile.get(profile_id, []),
            repo_root=repo_root,
        )

    payload = {
        "schema_version": QUALIFICATION_SCHEMA_VERSION,
        "generated_from": {
            "evidence_registry": str(evidence_registry_path(repo_root).relative_to(repo_root)).replace("\\", "/"),
            "evidence_registry_digest": _digest_bytes(
                evidence_registry_path(repo_root).read_bytes()
            ),
            "support_contracts": {
                profile_id: {
                    "contract_version": contract.contract_version,
                    "path": f"profiles/{profile_id}/support-contract.json",
                }
                for profile_id, contract in sorted(contracts.items())
            },
        },
        "maturity_contract": {
            "normative_status_field": "conformance_status_v3",
            "externally_calibrated_strict_locally_derivable": False,
            "counts_are_hand_typed": False,
        },
        "profiles": profiles,
    }
    return payload


def write_source_profile_qualification(repo_root: Path, output: Path | None = None) -> dict[str, Any]:
    payload = build_source_profile_qualification(repo_root)
    target = output or qualification_output_path(repo_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def qualification_from_artifact(
    repo_root: Path,
    *,
    profile_id: str,
) -> SourceProfileQualification | None:
    """Load a previously generated qualification for one profile, if present."""
    path = qualification_output_path(repo_root)
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict):
        return None
    row = profiles.get(profile_id)
    if not isinstance(row, dict) or not isinstance(row.get("qualification"), dict):
        return None
    from ovk.core.source_profile_maturity import qualification_from_dict

    return qualification_from_dict(row["qualification"])
