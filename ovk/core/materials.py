"""Canonical construction helpers for content-addressed input materials."""

from __future__ import annotations

import json
from typing import Any, cast

from ovk.core.bundle import content_digest
from ovk.core.execution_models import MaterialKind, MaterialReference, VerificationObligation


def canonical_material_bytes(payload: Any) -> bytes:
    """Serialize material payloads exactly as OVK content digests serialize them."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def compute_material_set_digest(materials: list[Any] | None) -> str:
    """Compute a canonical digest over sorted material ids and content digests."""
    entries: list[dict[str, str]] = []
    for item in materials or []:
        if hasattr(item, "model_dump"):
            payload = item.model_dump(mode="json")
        elif isinstance(item, dict):
            payload = item
        else:
            continue
        material_id = str(payload.get("material_id") or payload.get("id") or "")
        digest = str(payload.get("sha256") or payload.get("digest") or "")
        if material_id or digest:
            entries.append({"material_id": material_id, "sha256": digest})
    entries.sort(key=lambda row: (row["material_id"], row["sha256"]))
    return content_digest({"materials": entries})


def material_set_digest_for_obligation(obligation: VerificationObligation) -> str:
    """Return the canonical material-set digest for one typed obligation."""
    return compute_material_set_digest([item.model_dump(mode="json") for item in obligation.materials])


def material_reference_from_payload(
    *,
    material_id: str,
    kind: str,
    uri: str,
    payload: Any,
    source_revision: str | None,
    trusted: bool = False,
) -> MaterialReference:
    """Build a material reference whose digest and size bind the same payload."""
    serialized = canonical_material_bytes(payload)
    return MaterialReference(
        material_id=material_id[:32],
        kind=cast(MaterialKind, kind),
        uri=uri,
        sha256=content_digest(payload),
        size_bytes=len(serialized),
        source_revision=source_revision,
        trusted=trusted,
    )
