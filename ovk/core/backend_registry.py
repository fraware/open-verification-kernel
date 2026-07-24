"""Backend registry for the solver-agnostic control plane.

The registry is the sole source of registered ``BackendAdapter`` instances for
routing and execution. Duplicate backend identifiers are rejected at registration
time. Candidate ordering is deterministic by descending score then backend id.
"""

from __future__ import annotations

from typing import Any

from ovk.adapters.contract import BackendAdapter
from ovk.core.execution_models import (
    BackendCapabilityAssessment,
    BackendCapabilityManifest,
    ExecutionContext,
    VerificationObligation,
)
from ovk.core.schema_validation import load_json, validate_against_schema
from ovk.paths import schema_path


class BackendRegistryError(ValueError):
    """Raised when registry registration or lookup invariants are violated."""


def _validate_capability_manifest(manifest: BackendCapabilityManifest) -> None:
    """Validate a typed capability manifest against the JSON schema."""
    schema_file = schema_path("verification.capability.schema.json")
    if not schema_file.exists():
        raise BackendRegistryError("capability schema is missing from package data")
    schema = load_json(schema_file)
    payload = manifest.model_dump(mode="json", exclude_none=True)
    report = validate_against_schema(payload, schema)
    if not report.valid:
        issues = "; ".join(
            f"{'/'.join(str(part) for part in issue.path) or '$'}: {issue.message}" for issue in report.issues
        )
        raise BackendRegistryError(f"capability manifest failed schema validation: {issues}")


def _require_adapter_identity(adapter: BackendAdapter) -> tuple[str, str, str]:
    backend_id = str(getattr(adapter, "backend_id", "") or "").strip()
    adapter_id = str(getattr(adapter, "adapter_id", "") or "").strip()
    adapter_version = str(getattr(adapter, "adapter_version", "") or "").strip()
    if not backend_id:
        raise BackendRegistryError("adapter must declare a non-empty backend_id")
    if not adapter_id:
        raise BackendRegistryError(f"adapter {backend_id!r} must declare a non-empty adapter_id")
    if not adapter_version:
        raise BackendRegistryError(f"adapter {backend_id!r} must declare a non-empty adapter_version")
    return backend_id, adapter_id, adapter_version


class BackendRegistry:
    """Deterministic registry of unique backend adapters."""

    def __init__(self) -> None:
        self._by_backend: dict[str, BackendAdapter] = {}
        self._adapter_keys: set[tuple[str, str]] = set()
        self._order: list[str] = []

    def register(self, adapter: BackendAdapter) -> None:
        """Register an adapter. Rejects duplicate backend or adapter identity."""
        backend_id, adapter_id, adapter_version = _require_adapter_identity(adapter)
        if backend_id in self._by_backend:
            raise BackendRegistryError(f"duplicate backend registration: {backend_id}")
        adapter_key = (adapter_id, adapter_version)
        if adapter_key in self._adapter_keys:
            raise BackendRegistryError(f"duplicate adapter identity: {adapter_id}@{adapter_version}")

        manifest = adapter.manifest()
        if not isinstance(manifest, BackendCapabilityManifest):
            raise BackendRegistryError(f"adapter {backend_id!r} manifest() must return BackendCapabilityManifest")
        tool = manifest.tool
        if tool.adapter != adapter_id:
            raise BackendRegistryError(
                f"adapter {backend_id!r} manifest tool.adapter {tool.adapter!r} "
                f"does not match adapter_id {adapter_id!r}"
            )
        if tool.adapter_version != adapter_version:
            raise BackendRegistryError(
                f"adapter {backend_id!r} manifest tool.adapter_version "
                f"{tool.adapter_version!r} does not match adapter_version {adapter_version!r}"
            )
        if not manifest.guarantee.type.strip():
            raise BackendRegistryError(f"adapter {backend_id!r} must declare a guarantee type")
        if not manifest.supported_domains:
            raise BackendRegistryError(f"adapter {backend_id!r} must declare supported_domains")
        if not manifest.supported_property_kinds:
            raise BackendRegistryError(f"adapter {backend_id!r} must declare supported_property_kinds")
        _validate_capability_manifest(manifest)

        # Require compile/run surface present (Protocol methods).
        for method_name in ("can_handle", "compile", "fingerprint", "run", "normalize", "explain"):
            if not callable(getattr(adapter, method_name, None)):
                raise BackendRegistryError(f"adapter {backend_id!r} is missing required method {method_name}")

        self._by_backend[backend_id] = adapter
        self._adapter_keys.add(adapter_key)
        self._order.append(backend_id)

    def get(self, backend: str) -> BackendAdapter | None:
        """Return a registered adapter by backend id, or None if missing."""
        return self._by_backend.get(backend)

    def require(self, backend: str) -> BackendAdapter:
        """Return a registered adapter or raise if missing."""
        adapter = self.get(backend)
        if adapter is None:
            raise BackendRegistryError(f"backend not registered: {backend}")
        return adapter

    def all(self) -> tuple[BackendAdapter, ...]:
        """Return adapters in registration order (deterministic)."""
        return tuple(self._by_backend[backend_id] for backend_id in self._order)

    def backend_ids(self) -> tuple[str, ...]:
        """Return registered backend identifiers in registration order."""
        return tuple(self._order)

    def candidates(
        self,
        obligation: VerificationObligation,
        context: ExecutionContext,
    ) -> list[BackendCapabilityAssessment]:
        """Assess every registered adapter; return deterministic score ordering.

        Ordering: descending score, then ascending backend id for ties.
        """
        assessments: list[BackendCapabilityAssessment] = []
        for adapter in self.all():
            assessment = adapter.can_handle(obligation, context)
            if assessment.backend != adapter.backend_id:
                raise BackendRegistryError(
                    f"adapter {adapter.backend_id!r} returned assessment for backend {assessment.backend!r}"
                )
            assessments.append(assessment)
        return sorted(
            assessments,
            key=lambda item: (-float(item.score), item.backend),
        )

    def as_manifest_dicts(self) -> list[dict[str, Any]]:
        """Return capability manifests as JSON-compatible dicts (registration order)."""
        return [adapter.manifest().model_dump(mode="json") for adapter in self.all()]
