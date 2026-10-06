"""Adapter registry for expansion_v2.

Registers identities for source-universe-v0 and the five frozen expansion
candidates. Semantic mapping for materialization is intentionally not supplied
in the interface-freeze pass.
"""

from __future__ import annotations

from typing import Dict

from .adapter_contract import AdapterNotYetImplemented, RepositoryIdentity, SourceRepositoryAdapter

# source-universe-v0 identities (immutable)
V0_IDENTITIES: tuple[RepositoryIdentity, ...] = (
    RepositoryIdentity(
        repository="fraware/CertifyEdge",
        url="https://github.com/fraware/CertifyEdge",
        cutoff_sha="6ef02d54c4697886b20577f10eec683861475db2",
        role="SOURCE_UNIVERSE_V0",
    ),
    RepositoryIdentity(
        repository="SentinelOps-CI/pcs-core",
        url="https://github.com/SentinelOps-CI/pcs-core",
        cutoff_sha="9c971f5f9da8a424924dd8f48d6a3b71a1009e1b",
        role="SOURCE_UNIVERSE_V0",
    ),
)

# Frozen expansion candidates — order and cutoffs match
# SOURCE_REPOSITORY_CANDIDATES.v1.json. Do not add/delete/reorder here without
# a new candidates file version and freeze amendment.
EXPANSION_IDENTITIES: tuple[RepositoryIdentity, ...] = (
    RepositoryIdentity(
        repository="fraware/pcs-bench",
        url="https://github.com/fraware/pcs-bench",
        cutoff_sha="6092cccefee7841dfde1393e6881d433838a2252",
        role="EXPANSION_CANDIDATE",
    ),
    RepositoryIdentity(
        repository="fraware/ovk-consumer-fastapi-terraform",
        url="https://github.com/fraware/ovk-consumer-fastapi-terraform",
        cutoff_sha="784576bc5fd01ac80092662887a896301d4fe186",
        role="EXPANSION_CANDIDATE",
    ),
    RepositoryIdentity(
        repository="fraware/ovk-consumer-express-actions",
        url="https://github.com/fraware/ovk-consumer-express-actions",
        cutoff_sha="31aed31a04c7bca67d3bd6151caf1e42f4b7d1f8",
        role="EXPANSION_CANDIDATE",
    ),
    RepositoryIdentity(
        repository="fraware/environment-assurance-compiler",
        url="https://github.com/fraware/environment-assurance-compiler",
        cutoff_sha="812b4b13f8acdfcafb50de9d794c7fa0b20b31ad",
        role="EXPANSION_CANDIDATE",
    ),
    RepositoryIdentity(
        repository="fraware/lean-project-evidence",
        url="https://github.com/fraware/lean-project-evidence",
        cutoff_sha="4660d97db933b0fbcf5c9af466191055c887bea3",
        role="EXPANSION_CANDIDATE",
    ),
)


def _placeholder(identity: RepositoryIdentity) -> SourceRepositoryAdapter:
    return AdapterNotYetImplemented(identity)


def build_default_registry() -> Dict[str, SourceRepositoryAdapter]:
    """Return adapters for v0 + five expansion identities (all placeholders).

    Placeholder registration freezes the *interface* surface. It does not
    authorize materialization of expansion candidates.
    """
    registry: Dict[str, SourceRepositoryAdapter] = {}
    for identity in V0_IDENTITIES + EXPANSION_IDENTITIES:
        registry[identity.repository] = _placeholder(identity)
    return registry


def frozen_expansion_repository_ids() -> tuple[str, ...]:
    return tuple(identity.repository for identity in EXPANSION_IDENTITIES)


def frozen_v0_repository_ids() -> tuple[str, ...]:
    return tuple(identity.repository for identity in V0_IDENTITIES)
