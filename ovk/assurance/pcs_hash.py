"""PCS-compatible hashing helpers for verifier-assurance artifacts.

PCS artifact sealing and profile configuration digests MUST use
``pcs_core.hash.canonical_hash``. Local non-PCS digests may fall back to a
compatible Canonical-JSON hasher when pcs-core is unavailable.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ovk.assurance.errors import PinError
from ovk.assurance.pin import ensure_pcs_on_path, resolve_pcs_root

CANONICALIZATION_VERSION = "v1"


def _local_canonical_json_bytes(value: Any) -> bytes:
    """Compatible Canonical JSON serializer used only for non-PCS local digests."""

    def _normalize(item: Any) -> Any:
        if isinstance(item, dict):
            return {str(k): _normalize(item[k]) for k in sorted(item, key=lambda x: str(x))}
        if isinstance(item, list):
            return [_normalize(v) for v in item]
        if isinstance(item, bool) or item is None:
            return item
        if isinstance(item, int) and not isinstance(item, bool):
            return item
        if isinstance(item, float):
            raise PinError(
                "float values are prohibited in Canonical JSON digests; "
                "use a normalized decimal string instead"
            )
        return item

    return json.dumps(_normalize(value), separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _try_pcs_canonical_hash():
    root = resolve_pcs_root()
    if root is None:
        return None
    try:
        ensure_pcs_on_path()
        from pcs_core.hash import canonical_hash as pcs_canonical_hash

        return pcs_canonical_hash
    except Exception:
        return None


def pcs_canonical_hash(value: dict[str, Any]) -> str:
    """Hash a PCS artifact body with pcs_core. Fail closed if unavailable."""
    hasher = _try_pcs_canonical_hash()
    if hasher is None:
        raise PinError(
            "pcs_core.hash.canonical_hash is required to seal or validate PCS artifacts; "
            "resolve the PCS pin (OVK_PCS_CORE_PATH / sibling pcs-core / installed package)"
        )
    return hasher(value)


def sha256_digest(value: Any, *, require_pcs: bool = False) -> str:
    """Return ``sha256:`` + 64 hex for a JSON-like value.

    When ``require_pcs`` is True, always use pcs_core (fail closed).
    Otherwise prefer pcs_core when available; fall back to a local Canonical
    JSON hasher for non-PCS local digests only.
    """
    if isinstance(value, dict):
        hasher = _try_pcs_canonical_hash()
        if hasher is not None:
            return hasher(value)
        if require_pcs:
            raise PinError(
                "pcs_core.hash.canonical_hash is required; PCS pin unavailable"
            )
        digest = hashlib.sha256(_local_canonical_json_bytes(value)).hexdigest()
        return f"sha256:{digest}"

    # Non-dict values: hash Canonical JSON encoding of the value.
    hasher = _try_pcs_canonical_hash()
    if require_pcs and hasher is None:
        raise PinError("pcs_core.hash.canonical_hash is required; PCS pin unavailable")
    if hasher is not None and isinstance(value, (list, dict)):
        # pcs_core.canonical_hash expects a dict; wrap scalars/lists.
        if isinstance(value, list):
            payload = {"_": value}
            # Prefer raw local for lists to avoid wrapping skew — use local bytes.
            digest = hashlib.sha256(_local_canonical_json_bytes(value)).hexdigest()
            return f"sha256:{digest}"
    digest = hashlib.sha256(_local_canonical_json_bytes(value)).hexdigest()
    return f"sha256:{digest}"


def attach_nested_integrity(data: dict[str, Any]) -> dict[str, Any]:
    """Seal a PCS artifact by hashing the body WITHOUT ``integrity``.

    Sets ``integrity: {canonicalization_version: "v1", artifact_digest}``.
    Requires pcs_core (fail closed).
    """
    body = {k: v for k, v in data.items() if k != "integrity"}
    digest = pcs_canonical_hash(body)
    out = dict(body)
    out["integrity"] = {
        "canonicalization_version": CANONICALIZATION_VERSION,
        "artifact_digest": digest,
    }
    return out


def verify_nested_integrity(data: dict[str, Any]) -> str:
    """Recompute and verify nested integrity; return the matching digest."""
    integrity = data.get("integrity")
    if not isinstance(integrity, dict):
        raise PinError("PCS artifact missing nested integrity")
    expected = integrity.get("artifact_digest")
    if not isinstance(expected, str) or not expected.startswith("sha256:"):
        raise PinError("PCS artifact integrity.artifact_digest is missing or invalid")
    body = {k: v for k, v in data.items() if k != "integrity"}
    actual = pcs_canonical_hash(body)
    if actual != expected:
        raise PinError(
            f"PCS artifact integrity mismatch: expected {expected}, recomputed {actual}"
        )
    return actual
