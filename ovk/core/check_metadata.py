"""Required-check metadata helpers.

The runner treats missing required-check metadata as an honest unknown. This
module normalizes metadata supplied by CI, fixtures, or a protected collector
artifact. Provenance fields are preserved; they are never dropped on load.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ovk.core.metadata_provenance import flatten_protected_artifact_for_loader, parse_protected_artifact


def _as_string_list(value: object) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        return None
    return [str(item) for item in value]


def _extract_contexts(value: object) -> list[str] | None:
    """Extract required check names from common GitHub API shapes."""
    if not isinstance(value, dict):
        return None

    required = value.get("required_status_checks", value)
    if not isinstance(required, dict):
        return None

    contexts: list[str] = []
    raw_contexts = required.get("contexts")
    if isinstance(raw_contexts, list):
        contexts.extend(str(item) for item in raw_contexts)

    raw_checks = required.get("checks")
    if isinstance(raw_checks, list):
        for item in raw_checks:
            if isinstance(item, dict) and item.get("context"):
                contexts.append(str(item["context"]))

    return contexts if contexts else None


def _checks_from_phase(phase: object) -> list[str] | None:
    if not isinstance(phase, dict):
        return None
    checks = phase.get("required_checks")
    if isinstance(checks, list):
        return [str(item) for item in checks]
    return _extract_contexts(phase)


def normalize_required_check_metadata(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize explicit, GitHub-shaped, or protected-artifact metadata.

    Protected acquisition fields are copied through so later trust checks can
    recompute the same canonical payload the collector signed.
    """
    flattened = flatten_protected_artifact_for_loader(data) if parse_protected_artifact(data) else dict(data)

    before = _as_string_list(flattened.get("before_required_checks"))
    after = _as_string_list(flattened.get("after_required_checks"))

    if before is None:
        before = _extract_contexts(flattened.get("before_branch_protection"))
    if after is None:
        after = _extract_contexts(flattened.get("after_branch_protection"))
    if before is None:
        before = _checks_from_phase(flattened.get("before"))
    if after is None:
        after = _checks_from_phase(flattened.get("after"))

    normalized: dict[str, Any] = {
        "before_required_checks": before,
        "after_required_checks": after,
    }
    if isinstance(flattened.get("before"), dict):
        normalized["before"] = dict(flattened["before"])
        if before is not None:
            normalized["before"].setdefault("required_checks", before)
    elif before is not None:
        normalized["before"] = {"required_checks": before}
    if isinstance(flattened.get("after"), dict):
        normalized["after"] = dict(flattened["after"])
        if after is not None:
            normalized["after"].setdefault("required_checks", after)
    elif after is not None:
        normalized["after"] = {"required_checks": after}

    for key in ("_ovk_acquisition", "_ovk_protected_artifact", "_ovk_provenance_conflicts"):
        if key in flattened:
            normalized[key] = flattened[key]
    for key in ("repository", "branch", "base_sha", "head_sha", "source_endpoint", "protected_environments"):
        if key in flattened:
            normalized[key] = flattened[key]
    return normalized


def load_required_check_metadata(path: Path | None) -> dict[str, Any]:
    """Load before/after required-check metadata and any bound acquisition envelope.

    Accepted JSON shapes include explicit check lists, GitHub API objects, and
    ``ProtectedMetadataArtifact`` v1 documents.
    """
    if path is None:
        return {"before_required_checks": None, "after_required_checks": None}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {"before_required_checks": None, "after_required_checks": None}
    return normalize_required_check_metadata(data)
