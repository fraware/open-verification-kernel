"""Persistent dependency-aware FastAPI semantic compilation state.

The cache stores typed JSON only. Cached state can reduce semantic compilation
work but cannot directly produce a verification PASS.

A record is accepted only when:
- schema/implementation/OVK versions match;
- repository identity and profile digest match the lookup key;
- key and payload digests validate;
- every typed fragment/contract reconstructs successfully;
- fragment source/profile identities agree with the stored state; and
- contract version maps agree with the reconstructed composition state.

Any failure is a cache miss.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk import __version__ as OVK_VERSION
from ovk.compilers.authorization.fastapi_semantic_fragment import (
    FastApiFileSemanticFragment,
    profile_semantic_digest,
)
from ovk.compilers.authorization.incremental_contract_composition import (
    IncrementalContractCompositionState,
)
from ovk.compilers.authorization.incremental_fastapi_compiler import (
    IncrementalFastApiCompilationResult,
    IncrementalFastApiCompilationState,
    compile_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
    SemanticSummaryCacheStats,
    load_persistent_semantic_summaries,
)
from ovk.core.assurance_ir import (
    AuthorizationGuard,
    ContractUse,
    EffectRef,
    FunctionContract,
    PrincipalRef,
    ProtectedEffect,
    ResourceBinding,
    ResourceRef,
    SemanticPath,
)
from ovk.core.bundle import content_digest


PERSISTENT_FASTAPI_STATE_SCHEMA = "ovk.fastapi_incremental_state_cache.v1"
PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION = "0.5.0"
DEFAULT_PERSISTENT_FASTAPI_STATE_DIR = Path(
    ".verification/cache/fastapi-incremental-state"
)


@dataclass(frozen=True)
class PersistentFastApiCompileResult:
    compilation: IncrementalFastApiCompilationResult
    semantic_summary_stats: SemanticSummaryCacheStats
    previous_state_loaded: bool
    state_written: bool


def _models(items) -> list[dict[str, Any]]:
    return [item.model_dump(mode="json") for item in items]


def _fragment_payload(fragment: FastApiFileSemanticFragment) -> dict[str, Any]:
    return {
        "path": fragment.path,
        "source_digest": fragment.source_digest,
        "profile_digest": fragment.profile_digest,
        "contract_dependencies": dict(
            sorted(fragment.contract_dependencies.items())
        ),
        "authorization_contract_dependencies": dict(
            sorted(
                fragment.authorization_contract_dependencies.items()
            )
        ),
        "unsupported_constructs": list(fragment.unsupported_constructs),
        "principals": _models(fragment.principals),
        "resources": _models(fragment.resources),
        "effects": _models(fragment.effects),
        "guards": _models(fragment.guards),
        "protected_effects": _models(fragment.protected_effects),
        "resource_bindings": _models(fragment.resource_bindings),
        "contract_uses": _models(fragment.contract_uses),
        "paths": _models(fragment.paths),
    }


def _fragment_from_payload(payload: dict[str, Any]) -> FastApiFileSemanticFragment:
    return FastApiFileSemanticFragment(
        path=str(payload["path"]),
        source_digest=str(payload["source_digest"]),
        profile_digest=str(payload["profile_digest"]),
        contract_dependencies={
            str(name): (str(version) if version is not None else None)
            for name, version in (
                payload.get("contract_dependencies") or {}
            ).items()
        },
        authorization_contract_dependencies={
            str(name): (str(version) if version is not None else None)
            for name, version in (
                payload.get("authorization_contract_dependencies") or {}
            ).items()
        },
        unsupported_constructs=tuple(
            str(item)
            for item in payload.get("unsupported_constructs") or []
        ),
        principals=tuple(
            PrincipalRef.model_validate(item)
            for item in payload.get("principals") or []
        ),
        resources=tuple(
            ResourceRef.model_validate(item)
            for item in payload.get("resources") or []
        ),
        effects=tuple(
            EffectRef.model_validate(item)
            for item in payload.get("effects") or []
        ),
        guards=tuple(
            AuthorizationGuard.model_validate(item)
            for item in payload.get("guards") or []
        ),
        protected_effects=tuple(
            ProtectedEffect.model_validate(item)
            for item in payload.get("protected_effects") or []
        ),
        resource_bindings=tuple(
            ResourceBinding.model_validate(item)
            for item in payload.get("resource_bindings") or []
        ),
        contract_uses=tuple(
            ContractUse.model_validate(item)
            for item in payload.get("contract_uses") or []
        ),
        paths=tuple(
            SemanticPath.model_validate(item)
            for item in payload.get("paths") or []
        ),
    )


def _contract_state_payload(
    state: IncrementalContractCompositionState,
) -> dict[str, Any]:
    return {
        "direct_versions": dict(sorted(state.direct_versions.items())),
        "candidate_fingerprints": dict(
            sorted(state.candidate_fingerprints.items())
        ),
        "candidate_dependencies": dict(
            sorted(state.candidate_dependencies.items())
        ),
        "contracts": {
            name: contract.model_dump(mode="json")
            for name, contract in sorted(state.contracts.items())
        },
    }


def _contract_state_from_payload(
    payload: dict[str, Any],
) -> IncrementalContractCompositionState:
    contracts = {
        str(name): FunctionContract.model_validate(contract)
        for name, contract in (payload.get("contracts") or {}).items()
    }
    if any(
        name != contract.qualified_name
        for name, contract in contracts.items()
    ):
        raise ValueError("contract state stable-name mismatch")

    return IncrementalContractCompositionState(
        direct_versions={
            str(name): str(version)
            for name, version in (
                payload.get("direct_versions") or {}
            ).items()
        },
        candidate_fingerprints={
            str(name): str(value)
            for name, value in (
                payload.get("candidate_fingerprints") or {}
            ).items()
        },
        candidate_dependencies={
            str(name): str(value)
            for name, value in (
                payload.get("candidate_dependencies") or {}
            ).items()
        },
        contracts=contracts,
    )


def _state_payload(
    state: IncrementalFastApiCompilationState,
) -> dict[str, Any]:
    if state.contract_composition_state is None:
        raise ValueError(
            "persistent FastAPI state requires contract composition state"
        )
    return {
        "repo": state.repo,
        "head_revision": state.head_revision,
        "source_digests": dict(sorted(state.source_digests.items())),
        "profile_digest": state.profile_digest,
        "contract_versions": dict(sorted(state.contract_versions.items())),
        "fragments": {
            path: _fragment_payload(fragment)
            for path, fragment in sorted(state.fragments.items())
        },
        "assurance_ir_digest": state.assurance_ir_digest,
        "contract_composition_state": _contract_state_payload(
            state.contract_composition_state
        ),
    }


def _state_from_payload(
    payload: dict[str, Any],
) -> IncrementalFastApiCompilationState:
    fragments = {
        str(path): _fragment_from_payload(fragment)
        for path, fragment in (payload.get("fragments") or {}).items()
    }
    for path, fragment in fragments.items():
        if path != fragment.path:
            raise ValueError("fragment map path mismatch")

    contract_state = _contract_state_from_payload(
        payload["contract_composition_state"]
    )
    contract_versions = {
        str(name): str(version)
        for name, version in (
            payload.get("contract_versions") or {}
        ).items()
    }
    reconstructed_versions = {
        name: contract.contract_id
        for name, contract in contract_state.contracts.items()
    }
    if contract_versions != reconstructed_versions:
        raise ValueError("stored contract versions disagree with contract state")

    source_digests = {
        str(path): str(digest)
        for path, digest in (payload.get("source_digests") or {}).items()
    }
    profile_digest = str(payload["profile_digest"])
    for path, fragment in fragments.items():
        if fragment.profile_digest != profile_digest:
            raise ValueError("fragment profile digest mismatch")
        if source_digests.get(path) != fragment.source_digest:
            raise ValueError("fragment source digest mismatch")

    return IncrementalFastApiCompilationState(
        repo=str(payload["repo"]),
        head_revision=(
            str(payload["head_revision"])
            if payload.get("head_revision") is not None
            else None
        ),
        source_digests=source_digests,
        profile_digest=profile_digest,
        contract_versions=contract_versions,
        fragments=fragments,
        assurance_ir_digest=str(payload["assurance_ir_digest"]),
        contract_composition_state=contract_state,
    )


def _key_components(*, repo: str, profile_digest: str) -> dict[str, str]:
    return {
        "schema_version": PERSISTENT_FASTAPI_STATE_SCHEMA,
        "implementation_version": (
            PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION
        ),
        "ovk_version": OVK_VERSION,
        "repo": repo,
        "profile_digest": profile_digest,
    }


class PersistentFastApiIncrementalStateCache:
    """Filesystem-backed latest valid semantic state per repo/profile."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or DEFAULT_PERSISTENT_FASTAPI_STATE_DIR

    def _path(self, *, repo: str, profile_digest: str) -> Path:
        key = content_digest(
            _key_components(repo=repo, profile_digest=profile_digest)
        )
        return self.root / f"{key}.json"

    def get(
        self,
        *,
        repo: str,
        profile_digest: str,
    ) -> IncrementalFastApiCompilationState | None:
        path = self._path(repo=repo, profile_digest=profile_digest)
        if not path.exists():
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            components = record["key_components"]
            payload = record["payload"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            return None

        expected = _key_components(
            repo=repo,
            profile_digest=profile_digest,
        )
        if components != expected:
            return None
        if record.get("key_digest") != content_digest(expected):
            return None
        if record.get("payload_digest") != content_digest(payload):
            return None
        if payload.get("repo") != repo:
            return None
        if payload.get("profile_digest") != profile_digest:
            return None

        try:
            return _state_from_payload(payload)
        except (KeyError, TypeError, ValueError):
            return None

    def put(self, state: IncrementalFastApiCompilationState) -> str:
        payload = _state_payload(state)
        components = _key_components(
            repo=state.repo,
            profile_digest=state.profile_digest,
        )
        record = {
            "cached_at": time.time(),
            "key_components": components,
            "key_digest": content_digest(components),
            "payload": payload,
            "payload_digest": content_digest(payload),
        }

        self.root.mkdir(parents=True, exist_ok=True)
        path = self._path(
            repo=state.repo,
            profile_digest=state.profile_digest,
        )
        temp = path.with_suffix(".tmp")
        temp.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temp.replace(path)
        return str(record["payload_digest"])


def compile_persistent_incremental_fastapi_assurance(
    materials: AuthMaterials,
    profile: FastApiDependencyEffectProfile,
    *,
    semantic_summary_cache: PersistentPythonSemanticSummaryCache,
    state_cache: PersistentFastApiIncrementalStateCache,
) -> PersistentFastApiCompileResult:
    """Compile from persistent summaries and prior semantic state.

    Repository identity is required for cross-worker state reuse. If it is
    absent, semantic summaries may still use their own cache, but higher-level
    state is neither loaded nor persisted.
    """

    summaries = load_persistent_semantic_summaries(
        materials,
        cache=semantic_summary_cache,
    )
    profile_digest = profile_semantic_digest(profile)
    repo = materials.repo

    previous = (
        state_cache.get(
            repo=repo,
            profile_digest=profile_digest,
        )
        if repo
        else None
    )

    compilation = compile_incremental_fastapi_assurance(
        materials,
        profile,
        parsed_index=summaries.parsed_index,
        contract_summary_index=summaries.contract_summary_index,
        route_summary_index=summaries.route_summary_index,
        previous_state=previous,
    )

    written = False
    if repo:
        state_cache.put(compilation.state)
        written = True

    return PersistentFastApiCompileResult(
        compilation=compilation,
        semantic_summary_stats=summaries.stats,
        previous_state_loaded=previous is not None,
        state_written=written,
    )
