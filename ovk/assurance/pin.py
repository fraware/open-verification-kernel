"""PCS pin resolution for verifier-assurance schemas.

Resolution order (documented in docs/PCS_PIN.md):

1. ``OVK_PCS_CORE_PATH``
2. ``PCS_CORE_PATH``
3. Sibling ``../pcs-core`` relative to the OVK repository root
4. Installed ``pcs-core`` package (when available)

Missing pin / missing required schemas / digest drift / unknown artifact types
fail closed.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path

from ovk.assurance.errors import PinError
from ovk.paths import ovk_data_root

# Authoritative OVK pin surface (all required at the documented pcs-core SHA).
ARTIFACT_SCHEMA_FILES: dict[str, str] = {
    "VerifierProfile.v1": "VerifierProfile.v1.schema.json",
    "VerificationResult.v1": "VerificationResult.v1.schema.json",
    "VerifierInvocationRecord.v1": "VerifierInvocationRecord.v1.schema.json",
    "VerifierReplayReport.v1": "VerifierReplayReport.v1.schema.json",
    "VerifierMutationManifest.v1": "VerifierMutationManifest.v1.schema.json",
}

DEFS_SCHEMA_FILE = "verifier_assurance.defs.json"

# Digests for pcs-core commit fb588a41a7eab68064429e3c4dfb26c328b9863d (docs/PCS_PIN.md).
EXPECTED_SCHEMA_DIGESTS: dict[str, str] = {
    "VerifierProfile.v1": (
        "sha256:a657a63eee47a00419f31008f0adee5559e37fdba2544831e8b297c0a2dbe9bd"
    ),
    "VerificationResult.v1": (
        "sha256:146534a7ebf8ee8cdaecaa57258c0ce11224f50aed1a71196bc7b72d2c5b6d17"
    ),
    "VerifierInvocationRecord.v1": (
        "sha256:3ee1384cd5fae5e08b87870100609a9a9b8cf2502b2c4d92de9dedc1f9ffbc3d"
    ),
    "VerifierReplayReport.v1": (
        "sha256:06660ef51c89385869306c2f1c7f1364bec129b783007cc7a8caa4322582bd3b"
    ),
    "VerifierMutationManifest.v1": (
        "sha256:b82952c1d41ddd151cd71440a5a38f7e768c468c3ff4ae11f3a80325d4cb4819"
    ),
    DEFS_SCHEMA_FILE: (
        "sha256:c417accb1b4bc08d6e6f0f98e71ee6e7c87a923d19c5054a18841e7e04eadabb"
    ),
}

PCS_PIN_COMMIT = "fb588a41a7eab68064429e3c4dfb26c328b9863d"


def _looks_like_pcs_root(path: Path) -> bool:
    schemas = path / "schemas"
    return schemas.is_dir() and (schemas / "VerifierProfile.v1.schema.json").is_file()


def _installed_pcs_root() -> Path | None:
    spec = importlib.util.find_spec("pcs_core")
    if spec is None or spec.origin is None:
        return None
    package_dir = Path(spec.origin).resolve().parent
    # Editable / src layout: pcs-core/python/pcs_core -> pcs-core root
    candidate = package_dir.parent.parent
    if _looks_like_pcs_root(candidate):
        return candidate
    # Wheel may ship schemas next to the package
    if _looks_like_pcs_root(package_dir):
        return package_dir
    if _looks_like_pcs_root(package_dir.parent):
        return package_dir.parent
    return None


def resolve_pcs_root() -> Path | None:
    """Resolve the pcs-core checkout root, or None when unavailable."""
    for env_name in ("OVK_PCS_CORE_PATH", "PCS_CORE_PATH"):
        raw = (os.environ.get(env_name) or "").strip()
        if raw:
            path = Path(raw).expanduser().resolve()
            if _looks_like_pcs_root(path):
                return path
            return None

    ovk_root = ovk_data_root()
    sibling = (ovk_root / ".." / "pcs-core").resolve()
    if _looks_like_pcs_root(sibling):
        return sibling

    return _installed_pcs_root()


def require_pcs_pin() -> Path:
    """Return the resolved PCS root or raise ``PinError``."""
    root = resolve_pcs_root()
    if root is None:
        raise PinError(
            "PCS pin unavailable: set OVK_PCS_CORE_PATH or PCS_CORE_PATH, "
            "place a sibling ../pcs-core checkout, or install pcs-core"
        )
    return root


def ensure_pcs_on_path() -> Path:
    """Ensure ``pcs_core`` is importable by adding ``<pcs-root>/python`` to sys.path."""
    root = require_pcs_pin()
    python_root = root / "python"
    if python_root.is_dir():
        path = str(python_root)
        if path not in sys.path:
            sys.path.insert(0, path)
    return root


def schema_path(artifact_type: str) -> Path:
    """Return the absolute schema path for a pinned VA artifact type."""
    filename = ARTIFACT_SCHEMA_FILES.get(artifact_type)
    if filename is None:
        raise PinError(f"unknown PCS assurance artifact type: {artifact_type!r}")
    root = require_pcs_pin()
    path = root / "schemas" / filename
    if not path.is_file():
        raise PinError(f"PCS schema missing for {artifact_type}: {path}")
    return path


def schemas_dir() -> Path:
    """Return the PCS schemas directory from the resolved pin."""
    root = require_pcs_pin()
    path = root / "schemas"
    if not path.is_dir():
        raise PinError(f"PCS schemas directory missing: {path}")
    return path


def file_digest(path: Path) -> str:
    """Return ``sha256:`` + hex digest of file bytes."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256:{digest}"


@lru_cache(maxsize=1)
def load_schema_digests() -> dict[str, str]:
    """Load digests for pinned VA schema files (fail closed if pin incomplete)."""
    root = require_pcs_pin()
    schemas = root / "schemas"
    digests: dict[str, str] = {}
    for artifact_type, filename in ARTIFACT_SCHEMA_FILES.items():
        path = schemas / filename
        if not path.is_file():
            raise PinError(f"PCS schema missing for {artifact_type}: {path}")
        digests[artifact_type] = file_digest(path)
    defs_path = schemas / DEFS_SCHEMA_FILE
    if not defs_path.is_file():
        raise PinError(f"PCS defs schema missing: {defs_path}")
    digests[DEFS_SCHEMA_FILE] = file_digest(defs_path)
    return digests


def verify_pin_digests(*, expected: Mapping[str, str] | None = None) -> dict[str, str]:
    """Fail closed when resolved schema digests drift from the documented pin table.

    Returns the verified digest map on success.
    """
    table = dict(expected or EXPECTED_SCHEMA_DIGESTS)
    actual = load_schema_digests()
    mismatches: list[str] = []
    for key, want in sorted(table.items()):
        got = actual.get(key)
        if got != want:
            mismatches.append(f"{key}: expected {want}, got {got!r}")
    if mismatches:
        raise PinError(
            "PCS pin schema digest drift (commit "
            f"{PCS_PIN_COMMIT}): " + "; ".join(mismatches)
        )
    return actual
