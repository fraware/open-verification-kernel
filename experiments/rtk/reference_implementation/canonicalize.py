"""CanonicalDecisionInput.v1 canonicalization (frozen spec).

Implements experiments/rtk/specs/CanonicalDecisionInput.v1.canonicalization.md.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Mapping


_UNIQUE_STRING_ARRAY_FIELDS = frozenset({"changed_paths", "elements"})


def prepare_for_canonicalization(decision_input: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deep copy with canonical_digest removed and uniqueItems arrays sorted."""

    body = copy.deepcopy(dict(decision_input))
    body.pop("canonical_digest", None)
    _sort_unique_item_arrays(body)
    return body


def _sort_unique_item_arrays(node: Any) -> None:
    if isinstance(node, list):
        for item in node:
            _sort_unique_item_arrays(item)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key in _UNIQUE_STRING_ARRAY_FIELDS and isinstance(value, list):
            node[key] = sorted(str(item) for item in value)
        elif key == "artifact_refs" and isinstance(value, list):
            refs = [copy.deepcopy(item) for item in value if isinstance(item, dict)]
            for ref in refs:
                _sort_unique_item_arrays(ref)
            node[key] = sorted(refs, key=lambda ref: str(ref.get("path", "")))
        else:
            _sort_unique_item_arrays(value)


def canonical_json_bytes(decision_input: Mapping[str, Any]) -> bytes:
    """UTF-8 compact JSON preimage with recursive key sort."""

    body = prepare_for_canonicalization(decision_input)
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def compute_canonical_digest(decision_input: Mapping[str, Any]) -> str:
    """SHA-256 hex digest of the frozen canonicalization preimage."""

    return hashlib.sha256(canonical_json_bytes(decision_input)).hexdigest()


def digests_match(decision_input: Mapping[str, Any]) -> bool:
    """True when stored canonical_digest equals the recomputed digest."""

    stored = decision_input.get("canonical_digest")
    if not isinstance(stored, str):
        return False
    return stored == compute_canonical_digest(decision_input)
