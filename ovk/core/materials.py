"""Canonical construction helpers for content-addressed input materials."""

from __future__ import annotations

import json
from typing import Any, cast

from ovk.core.bundle import content_digest
from ovk.core.execution_models import MaterialKind, MaterialReference


def canonical_material_bytes(payload: Any) -> bytes:
    """Serialize material payloads exactly as OVK content digests serialize them."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


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
