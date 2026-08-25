"""Capability manifest loading and validation (normative claim registry)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ovk.core.execution_models import VALID_RELEASE_STATUSES

REQUIRED_NORMATIVE_FIELDS: tuple[str, ...] = (
    "checker_id",
    "version",
    "implementation",
    "input_contract",
    "output_contract",
    "claim_class",
    "assumptions",
    "trusted_components",
    "failure_semantics",
    "timeout_semantics",
    "unsupported_semantics",
    "determinism_status",
    "release_status",
    "owner",
)

VALID_TIMEOUT_SEMANTICS: frozenset[str] = frozenset({"unknown", "error", "fail"})
VALID_DETERMINISM_STATUSES: frozenset[str] = frozenset(
    {"deterministic", "tool_dependent", "non_deterministic", "unknown"}
)

# Adapters without native execution must stay at or below these statuses.
NON_NATIVE_MAX_RELEASE_STATUS: frozenset[str] = frozenset({"preview", "experimental", "disabled"})
NATIVE_CANDIDATE_CHECKERS: frozenset[str] = frozenset({"opa", "z3", "cbmc"})


def validate_capability_manifest(
    manifest: dict[str, Any],
    *,
    source: str = "manifest",
    require_stable_conformance: bool = True,
    repo_root: Path | None = None,
) -> list[str]:
    """Return validation failure messages for one capability / claim registry entry."""
    failures: list[str] = []
    if not isinstance(manifest, dict):
        return [f"{source}: capability manifest must be a JSON object"]

    for field in REQUIRED_NORMATIVE_FIELDS:
        if field not in manifest:
            failures.append(f"{source}: missing required field {field!r}")
            continue
        value = manifest[field]
        if field in {"assumptions", "trusted_components"}:
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                failures.append(f"{source}: {field} must be an array of strings")
            continue
        if not isinstance(value, str) or not value.strip():
            failures.append(f"{source}: {field} must be a non-empty string")

    release_status = manifest.get("release_status")
    if isinstance(release_status, str) and release_status not in VALID_RELEASE_STATUSES:
        failures.append(
            f"{source}: unknown release_status {release_status!r}; "
            f"expected one of {sorted(VALID_RELEASE_STATUSES)}"
        )

    timeout_semantics = manifest.get("timeout_semantics")
    if isinstance(timeout_semantics, str) and timeout_semantics not in VALID_TIMEOUT_SEMANTICS:
        failures.append(
            f"{source}: unknown timeout_semantics {timeout_semantics!r}; "
            f"expected one of {sorted(VALID_TIMEOUT_SEMANTICS)}"
        )

    determinism = manifest.get("determinism_status")
    if isinstance(determinism, str) and determinism not in VALID_DETERMINISM_STATUSES:
        failures.append(
            f"{source}: unknown determinism_status {determinism!r}; "
            f"expected one of {sorted(VALID_DETERMINISM_STATUSES)}"
        )

    # Honesty: stable requires full seven-item conformance (OVK-PR4).
    # Non-native adapters must stay at preview/experimental/disabled.
    native = manifest.get("native_execution")
    checker = str(manifest.get("checker_id") or manifest.get("tool", {}).get("name") or "")
    if release_status == "stable":
        if checker not in NATIVE_CANDIDATE_CHECKERS and native is not True:
            failures.append(
                f"{source}: only native-execution candidates may use release_status 'stable' "
                f"(checker={checker!r})"
            )
        elif require_stable_conformance:
            from ovk.core.adapter_conformance import is_fully_conformant

            if not is_fully_conformant(checker, root=repo_root):
                failures.append(
                    f"{source}: release_status 'stable' requires full seven-item "
                    f"adapter conformance (OVK-PR4) for {checker!r}"
                )
    elif native is False or (native is None and checker not in NATIVE_CANDIDATE_CHECKERS):
        if (
            isinstance(release_status, str)
            and release_status not in NON_NATIVE_MAX_RELEASE_STATUS
            and release_status in VALID_RELEASE_STATUSES
        ):
            failures.append(
                f"{source}: non-native checker {checker!r} cannot use release_status {release_status!r}"
            )

    return failures


class CapabilityRegistry:
    """Filesystem-backed registry for backend capability manifests."""

    def __init__(self, manifests: list[dict[str, Any]] | None = None) -> None:
        self._manifests = manifests or []

    @classmethod
    def from_directory(cls, path: Path, *, validate: bool = True) -> "CapabilityRegistry":
        manifests: list[dict[str, Any]] = []
        if not path.exists():
            return cls(manifests)
        failures: list[str] = []
        for manifest_path in sorted(path.rglob("capability.json")):
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            if validate:
                failures.extend(validate_capability_manifest(payload, source=str(manifest_path)))
            manifests.append(payload)
        if failures:
            raise ValueError("capability registry validation failed:\n" + "\n".join(failures))
        return cls(manifests)

    def all(self) -> list[dict[str, Any]]:
        return list(self._manifests)

    def by_tool(self, tool_name: str) -> dict[str, Any] | None:
        for manifest in self._manifests:
            if manifest.get("tool", {}).get("name") == tool_name:
                return manifest
        return None

    def by_checker_id(self, checker_id: str) -> dict[str, Any] | None:
        for manifest in self._manifests:
            if manifest.get("checker_id") == checker_id:
                return manifest
        return None

    def supporting_domain(self, domain: str) -> list[dict[str, Any]]:
        return [m for m in self._manifests if domain in m.get("supported_domains", [])]

    def supporting_property_kind(self, property_kind: str) -> list[dict[str, Any]]:
        return [m for m in self._manifests if property_kind in m.get("supported_property_kinds", [])]

    def validate_all(self) -> list[str]:
        """Validate every loaded manifest; return failure messages."""
        failures: list[str] = []
        for manifest in self._manifests:
            checker = str(manifest.get("checker_id") or manifest.get("capability_id") or "unknown")
            failures.extend(validate_capability_manifest(manifest, source=checker))
        return failures
