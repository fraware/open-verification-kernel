"""Installation- and repository-scoped cache keys (no cross-repo reuse)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ovk_github_app.errors import IsolationError


def app_cache_key(
    *,
    installation_id: int | str,
    repo_id: int | str,
    namespace: str,
    components: dict[str, Any] | None = None,
) -> str:
    """Build a cache key that always binds installation id and repository id.

    Keys from different installations or repositories never collide: both ids are
    mandatory key material, not optional metadata.
    """
    iid = str(installation_id).strip()
    rid = str(repo_id).strip()
    if not iid or not rid:
        raise IsolationError("cache key requires installation_id and repo_id")
    if not str(namespace).strip():
        raise IsolationError("cache key requires namespace")
    payload = {
        "schema": "ovk.github_app.cache.v1",
        "installation_id": iid,
        "repo_id": rid,
        "namespace": str(namespace).strip(),
        "components": components or {},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assert_cache_key_bound(
    key_material: dict[str, Any],
    *,
    installation_id: int | str,
    repo_id: int | str,
) -> None:
    """Fail closed when key material omits or mismatches installation/repo ids."""
    if "installation_id" not in key_material or "repo_id" not in key_material:
        raise IsolationError("cache key material missing installation_id or repo_id")
    if str(key_material["installation_id"]) != str(installation_id):
        raise IsolationError("cache key installation_id mismatch")
    if str(key_material["repo_id"]) != str(repo_id):
        raise IsolationError("cache key repo_id mismatch")
