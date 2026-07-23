"""Content-addressed verification cache with validated key components.

Namespaces under ``.verification/cache/``:

* ``compiled/`` ΓÇö compiled backend obligations
* ``backend-results/`` ΓÇö per-backend normalized results
* ``aggregate/`` ΓÇö aggregate outcomes only after every selected backend
  attempt has been validated

Legacy ``cache_key`` / ``get_cached_evidence`` / ``store_cached_evidence`` remain
for lane-level evidence caching during the control-plane migration.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk import __version__ as OVK_VERSION
from ovk.core.bundle import content_digest
from ovk.core.execution_models import (
    BackendEnvironmentFingerprint,
    BackendObligation,
    NormalizedBackendResult,
    RoutingDecision,
    VerificationObligation,
)

CACHE_SCHEMA_VERSION = "ovk.cache.v2"
DEFAULT_CACHE_DIR = Path(".verification/cache")
DEFAULT_TTL_SECONDS = 86400

NAMESPACE_COMPILED = "compiled"
NAMESPACE_BACKEND_RESULTS = "backend-results"
NAMESPACE_AGGREGATE = "aggregate"


def cache_key(lane: str, data: dict[str, Any], *, policy_digest: str | None = None) -> str:
    """Build a stable legacy cache key for a lane input."""
    payload: dict[str, Any] = {"lane": lane, "input": data}
    if policy_digest:
        payload["policy"] = policy_digest
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
    """Persist evidence JSON in the legacy flat cache."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    payload = {"cached_at": time.time(), "evidence": evidence}
    _cache_path(cache_dir, key).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _subject_dict(obligation: VerificationObligation) -> dict[str, Any]:
    subject = obligation.subject
    if hasattr(subject, "model_dump"):
        return subject.model_dump(mode="json")
    if isinstance(subject, dict):
        return dict(subject)
    return {"repo": str(getattr(subject, "repo", "")), "head_sha": str(getattr(subject, "head_sha", ""))}


def build_backend_result_key_components(
    *,
    obligation: VerificationObligation,
    routing: RoutingDecision,
    backend_obligation: BackendObligation,
    fingerprint: BackendEnvironmentFingerprint,
    input_format: str = "json",
) -> dict[str, Any]:
    """Construct validated cache identity components for a backend result."""
    return {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "ovk_version": OVK_VERSION,
        "subject": _subject_dict(obligation),
        "obligation_id": obligation.obligation_id,
        "routing_id": routing.routing_id,
        "backend_obligation_id": backend_obligation.backend_obligation_id,
        "environment_digest": fingerprint.environment_digest,
        "policy_digest": obligation.policy_digest,
        "compiler_version": backend_obligation.compiler_version,
        "adapter_version": backend_obligation.adapter_version,
        "input_format": input_format,
        "fallback_mode": routing.fallback_policy.model_dump(mode="json"),
        "aggregation_policy": routing.aggregation_policy,
        "backend": backend_obligation.backend,
        "payload_digest": backend_obligation.payload_digest,
        "namespace": NAMESPACE_BACKEND_RESULTS,
    }


def build_aggregate_key_components(
    *,
    obligation: VerificationObligation,
    routing: RoutingDecision,
    attempt_digests: list[str],
    input_format: str = "json",
) -> dict[str, Any]:
    """Construct validated cache identity for an aggregate outcome."""
    return {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "ovk_version": OVK_VERSION,
        "subject": _subject_dict(obligation),
        "obligation_id": obligation.obligation_id,
        "routing_id": routing.routing_id,
        "backend_obligation_id": None,
        "environment_digest": content_digest({"attempts": sorted(attempt_digests)}),
        "policy_digest": obligation.policy_digest,
        "compiler_version": obligation.compiler_version,
        "adapter_version": None,
        "input_format": input_format,
        "fallback_mode": routing.fallback_policy.model_dump(mode="json"),
        "aggregation_policy": routing.aggregation_policy,
        "attempt_digests": sorted(attempt_digests),
        "namespace": NAMESPACE_AGGREGATE,
    }


def digest_key_components(components: dict[str, Any]) -> str:
    """Digest key components into a content-addressed filename stem."""
    return content_digest(components)


def control_plane_cache_components(
    *,
    obligation: VerificationObligation,
    routing: RoutingDecision,
    backend_obligation: BackendObligation,
    fingerprint: BackendEnvironmentFingerprint,
    input_format: str = "json",
) -> dict[str, Any]:
    """Public alias used by the control plane."""
    return build_backend_result_key_components(
        obligation=obligation,
        routing=routing,
        backend_obligation=backend_obligation,
        fingerprint=fingerprint,
        input_format=input_format,
    )


@dataclass(frozen=True)
class CacheEntry:
    """A validated cache hit."""

    key_digest: str
    components: dict[str, Any]
    payload: dict[str, Any]
    cached_at: float


class HardenedResultCache:
    """Filesystem cache that validates stored key components on every read."""

    def __init__(self, root: Path | None = None, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.root = root or DEFAULT_CACHE_DIR
        self.ttl_seconds = ttl_seconds

    def namespace_dir(self, namespace: str) -> Path:
        if namespace not in {NAMESPACE_COMPILED, NAMESPACE_BACKEND_RESULTS, NAMESPACE_AGGREGATE}:
            raise ValueError(f"unknown cache namespace: {namespace}")
        path = self.root / namespace
        path.mkdir(parents=True, exist_ok=True)
        return path

    def put(
        self,
        components: dict[str, Any],
        payload: dict[str, Any],
        *,
        meta: dict[str, Any] | None = None,
    ) -> str:
        namespace = str(components.get("namespace") or NAMESPACE_BACKEND_RESULTS)
        key_digest = digest_key_components(components)
        record = {
            "cached_at": time.time(),
            "key_digest": key_digest,
            "key_components": components,
            "payload": payload,
            "meta": meta or {},
        }
        path = self.namespace_dir(namespace) / f"{key_digest}.json"
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return key_digest

    def get(self, components: dict[str, Any]) -> CacheEntry | None:
        """Return a cache entry only when stored components match the request."""
        namespace = str(components.get("namespace") or NAMESPACE_BACKEND_RESULTS)
        key_digest = digest_key_components(components)
        path = self.namespace_dir(namespace) / f"{key_digest}.json"
        if not path.exists():
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        cached_at = float(record.get("cached_at", 0))
        if self.ttl_seconds > 0 and (time.time() - cached_at) > self.ttl_seconds:
            path.unlink(missing_ok=True)
            return None
        stored_components = record.get("key_components")
        stored_digest = record.get("key_digest")
        payload = record.get("payload")
        if not isinstance(stored_components, dict) or not isinstance(payload, dict):
            path.unlink(missing_ok=True)
            return None
        if stored_digest != key_digest or digest_key_components(stored_components) != key_digest:
            path.unlink(missing_ok=True)
            return None
        if not _components_match(stored_components, components):
            return None
        return CacheEntry(
            key_digest=key_digest,
            components=stored_components,
            payload=payload,
            cached_at=cached_at,
        )

    def put_backend_result(
        self,
        components: dict[str, Any],
        result: NormalizedBackendResult,
        *,
        meta: dict[str, Any] | None = None,
    ) -> str:
        return self.put(components, result.model_dump(mode="json"), meta=meta)

    def get_backend_result(self, components: dict[str, Any]) -> NormalizedBackendResult | None:
        entry = self.get(components)
        if entry is None:
            return None
        try:
            return NormalizedBackendResult.model_validate(entry.payload)
        except Exception:  # noqa: BLE001 - corrupt cache is a miss
            return None

    def put_aggregate(
        self,
        *,
        obligation: VerificationObligation,
        routing: RoutingDecision,
        attempt_digests: list[str],
        aggregate_payload: dict[str, Any],
        attempts_validated: bool,
        input_format: str = "json",
    ) -> str | None:
        """Store an aggregate only after every selected backend attempt is validated.

        Returns ``None`` (and writes nothing) when ``attempts_validated`` is false
        or when the number of digests does not cover every selected backend.
        """
        if not attempts_validated:
            return None
        if len(attempt_digests) < len(routing.selected):
            return None
        if any(not digest for digest in attempt_digests):
            return None
        components = build_aggregate_key_components(
            obligation=obligation,
            routing=routing,
            attempt_digests=attempt_digests,
            input_format=input_format,
        )
        return self.put(components, aggregate_payload, meta={"attempts_validated": True})

    def get_aggregate(
        self,
        *,
        obligation: VerificationObligation,
        routing: RoutingDecision,
        attempt_digests: list[str],
        input_format: str = "json",
    ) -> dict[str, Any] | None:
        components = build_aggregate_key_components(
            obligation=obligation,
            routing=routing,
            attempt_digests=attempt_digests,
            input_format=input_format,
        )
        entry = self.get(components)
        return None if entry is None else entry.payload


def _components_match(stored: dict[str, Any], requested: dict[str, Any]) -> bool:
    """Require equality on identity-critical fields (not filename alone)."""
    critical = (
        "cache_schema_version",
        "ovk_version",
        "obligation_id",
        "routing_id",
        "backend_obligation_id",
        "environment_digest",
        "policy_digest",
        "compiler_version",
        "adapter_version",
        "input_format",
        "aggregation_policy",
        "namespace",
    )
    for field in critical:
        if field in requested and stored.get(field) != requested.get(field):
            return False
    if "subject" in requested:
        stored_subject = stored.get("subject") or {}
        requested_subject = requested.get("subject") or {}
        if not isinstance(stored_subject, dict) or not isinstance(requested_subject, dict):
            return False
        for key in ("repo", "head_sha", "base_sha"):
            if key in requested_subject and stored_subject.get(key) != requested_subject.get(key):
                return False
    if "fallback_mode" in requested and stored.get("fallback_mode") != requested.get("fallback_mode"):
        return False
    return True


class ControlPlaneResultCache:
    """Adapter implementing the control-plane ``ResultCache`` protocol."""

    def __init__(self, hardened: HardenedResultCache | None = None) -> None:
        self._cache = hardened or HardenedResultCache()
        self._last_components: dict[str, dict[str, Any]] = {}

    def bind_components(self, key: str, components: dict[str, Any]) -> None:
        self._last_components[key] = components

    def get(self, key: str) -> NormalizedBackendResult | None:
        components = self._last_components.get(key)
        if components is None:
            return None
        return self._cache.get_backend_result(components)

    def put(self, key: str, value: NormalizedBackendResult, *, meta: dict[str, Any]) -> None:
        components = self._last_components.get(key)
        if components is None:
            return
        self._cache.put_backend_result(components, value, meta=meta)
