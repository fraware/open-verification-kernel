"""Synthetic CanonicalDecisionInput.v1 builders for conformance tests only."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

_CANON_PATH = Path(__file__).resolve().parents[1] / "canonicalize.py"


def _load_canonicalize():
    name = "rtk_reference_canonicalize_for_builders"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _CANON_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _git_sha(label: str) -> str:
    return hashlib.sha1(label.encode("utf-8")).hexdigest()


def build_cdi(
    *,
    case_name: str,
    completeness: str,
    elements: list[str],
    changed_paths: list[str],
    artifact_paths: list[str] | None = None,
    include_repair: bool = False,
    corrupt_digest: bool = False,
) -> dict[str, Any]:
    """Build a schema-valid synthetic CDI. Never sourced from sealed holdout."""

    if artifact_paths is None:
        artifact_paths = list(elements)

    decision_input: dict[str, Any] = {
        "schema_version": "CanonicalDecisionInput.v1",
        "decision_input_id": _sha(f"decision:{case_name}"),
        "transition": {
            "transition_id": _sha(f"transition:{case_name}"),
            "repository": "synthetic/rtk-reference-fixture",
            "source_sha": _git_sha(f"source:{case_name}"),
            "target_sha": _git_sha(f"target:{case_name}"),
            "history_rule": "FIRST_PARENT",
            "changed_paths": sorted(changed_paths),
        },
        "claim": {
            "claim_id": f"synthetic-claim:{case_name}",
            "claim_class": "SYNTHETIC_CONFORMANCE",
            "claim_digest": None,
        },
        "evidence_snapshot": {
            "snapshot_id": _sha(f"snapshot:{case_name}"),
            "digest": _sha(f"evidence:{case_name}"),
            "digest_algorithm": "sha256",
            "completeness": completeness,
            "artifact_refs": [
                {"path": path, "sha256": _sha(f"artifact:{case_name}:{path}")}
                for path in sorted(artifact_paths)
            ],
        },
        "context_footprint": {
            "mapping_id": "SYNTHETIC_CONTEXT_FOOTPRINT.v0",
            "footprint_digest": _sha(f"footprint:{case_name}"),
            "elements": sorted(elements),
        },
        "relying_profile": {
            "mapping_id": "SYNTHETIC_RELYING_PROFILE.v0",
            "profile_id": _sha(f"profile:{case_name}"),
            "profile_digest": None,
        },
    }
    if include_repair:
        decision_input["repair_catalog_ref"] = {
            "mapping_id": "SYNTHETIC_REPAIR_CATALOG.v0",
            "catalog_id": _sha(f"repair:{case_name}"),
            "catalog_digest": None,
        }

    canonicalize = _load_canonicalize()
    digest = canonicalize.compute_canonical_digest(decision_input)
    decision_input["canonical_digest"] = "0" * 64 if corrupt_digest else digest
    return decision_input
