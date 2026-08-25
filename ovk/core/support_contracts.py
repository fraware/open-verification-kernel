"""Load and validate versioned source-profile support contracts.

Contracts live at ``profiles/<profile-id>/support-contract.json``. They bound
what a profile may claim strictly; unsupported constructs force review.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk.core.source_profiles import KNOWN_SOURCE_PROFILES, PROFILE_COMPILER_BINDINGS, is_known_source_profile

SUPPORT_CONTRACT_SCHEMA_VERSION = "ovk.support_contract.v1"


@dataclass(frozen=True)
class SupportContract:
    profile_id: str
    contract_version: str
    proposition: str
    guarantee_type: str
    compiler_binding: str
    supported_constructs: tuple[str, ...]
    excluded_constructs: tuple[str, ...]
    required_materials: tuple[str, ...]
    language_or_tool_versions: dict[str, str]
    lane: str | None = None
    notes: tuple[str, ...] = ()

    @property
    def version(self) -> str:
        return self.contract_version


def profiles_root(repo_root: Path | None = None) -> Path:
    root = repo_root or Path(__file__).resolve().parents[2]
    return root / "profiles"


def support_contract_path(profile_id: str, *, repo_root: Path | None = None) -> Path:
    return profiles_root(repo_root) / profile_id / "support-contract.json"


def load_support_contract(profile_id: str, *, repo_root: Path | None = None) -> SupportContract:
    """Load a support contract; raise on missing/invalid contracts."""
    if not is_known_source_profile(profile_id):
        raise ValueError(f"unknown source profile: {profile_id}")
    path = support_contract_path(profile_id, repo_root=repo_root)
    if not path.is_file():
        raise FileNotFoundError(f"support contract missing for {profile_id}: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return parse_support_contract(payload, expected_profile_id=profile_id)


def parse_support_contract(
    payload: dict[str, Any],
    *,
    expected_profile_id: str | None = None,
) -> SupportContract:
    if not isinstance(payload, dict):
        raise ValueError("support contract must be an object")
    if payload.get("schema_version") != SUPPORT_CONTRACT_SCHEMA_VERSION:
        raise ValueError(f"unsupported support-contract schema_version: {payload.get('schema_version')!r}")
    profile_id = str(payload.get("profile_id") or "")
    if not profile_id:
        raise ValueError("support contract missing profile_id")
    if expected_profile_id and profile_id != expected_profile_id:
        raise ValueError(f"profile_id mismatch: file={profile_id} expected={expected_profile_id}")
    if not is_known_source_profile(profile_id):
        raise ValueError(f"unknown source profile in support contract: {profile_id}")

    binding = str(payload.get("compiler_binding") or "")
    expected_binding = PROFILE_COMPILER_BINDINGS.get(profile_id)
    if expected_binding and binding != expected_binding:
        raise ValueError(
            f"compiler_binding for {profile_id} must be {expected_binding!r}, got {binding!r}"
        )

    coverage = payload.get("coverage_criteria")
    if not isinstance(coverage, dict) or coverage.get("unsupported_forces") != "review":
        raise ValueError("coverage_criteria.unsupported_forces must be 'review'")

    versions = payload.get("language_or_tool_versions")
    if not isinstance(versions, dict) or not versions:
        raise ValueError("language_or_tool_versions must be a non-empty object")

    required = payload.get("required_materials")
    if not isinstance(required, list) or not required:
        raise ValueError("required_materials must be a non-empty list")

    return SupportContract(
        profile_id=profile_id,
        contract_version=str(payload["contract_version"]),
        proposition=str(payload["proposition"]),
        guarantee_type=str(payload["guarantee_type"]),
        compiler_binding=binding,
        supported_constructs=tuple(str(item) for item in (payload.get("supported_constructs") or [])),
        excluded_constructs=tuple(str(item) for item in (payload.get("excluded_constructs") or [])),
        required_materials=tuple(str(item) for item in required),
        language_or_tool_versions={str(k): str(v) for k, v in versions.items()},
        lane=str(payload["lane"]) if payload.get("lane") else None,
        notes=tuple(str(item) for item in (payload.get("notes") or [])),
    )


def load_all_support_contracts(*, repo_root: Path | None = None) -> dict[str, SupportContract]:
    """Load contracts for every known production profile (fail closed on gaps)."""
    contracts: dict[str, SupportContract] = {}
    missing: list[str] = []
    for profile_id in sorted(KNOWN_SOURCE_PROFILES):
        path = support_contract_path(profile_id, repo_root=repo_root)
        if not path.is_file():
            missing.append(profile_id)
            continue
        contracts[profile_id] = load_support_contract(profile_id, repo_root=repo_root)
    if missing:
        raise FileNotFoundError(f"support contracts missing for profiles: {', '.join(missing)}")
    return contracts


def support_contract_version(profile_id: str, *, repo_root: Path | None = None) -> str | None:
    try:
        return load_support_contract(profile_id, repo_root=repo_root).contract_version
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError):
        return None
