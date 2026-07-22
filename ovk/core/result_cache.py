"""Content-addressed result cache for lane evaluations."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ovk.core.bundle import content_digest
from ovk.core.release_metadata import OVK_VERSION


DEFAULT_CACHE_DIR = Path(".verification/cache")
DEFAULT_TTL_SECONDS = 86400


def cache_key(
    lane: str,
    data: dict[str, Any],
    *,
    policy_digest: str | None = None,
    subject: dict[str, Any] | None = None,
    execution_fingerprint: dict[str, Any] | None = None,
) -> str:
    """Build a stable cache key for a lane input and its execution context.

    Evidence is subject-bound, so repository and commit identity must participate
    in result-cache keys. The OVK version and optional execution fingerprint
    prevent reuse across incompatible adapter/runtime revisions.
    """
    payload: dict[str, Any] = {
        "ovk_version": OVK_VERSION,
        "lane": lane,
        "input": data,
    }
    if policy_digest:
        payload["policy"] = policy_digest
    if subject:
        payload["subject"] = subject
    if execution_fingerprint:
        payload["execution"] = execution_fingerprint
    return content_digest(payload)


def _cache_path(cache_dir: Path, key: str) -> Path:
    return cache_dir / f"{key}.json"


def get_cached_evidence(
    cache_dir: Path,
    key: str,
    *,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> dict[str, Any] | None:
    """Return cached evidence JSON if present and not expired."""
    path = _cache_path(cache_dir, key)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    cached_at = float(payload.get("cached_at", 0))
    if ttl_seconds > 0 and (time.time() - cached_at) > ttl_seconds:
        path.unlink(missing_ok=True)
        return None
    evidence = payload.get("evidence")
    return evidence if isinstance(evidence, dict) else None


def store_cached_evidence(cache_dir: Path, key: str, evidence: dict[str, Any]) -> None:
    """Persist evidence JSON in the cache."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    payload = {"cached_at": time.time(), "evidence": evidence}
    _cache_path(cache_dir, key).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
