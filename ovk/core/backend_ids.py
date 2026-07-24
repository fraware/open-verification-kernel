"""Canonical backend identifiers and configuration migration helpers."""

from __future__ import annotations

from collections.abc import Iterable

# Backend ids registered by the typed control plane. Legacy capability manifests
# continue to use short tool names during the migration period.
CANONICAL_CONTROL_PLANE_BACKENDS: frozenset[str] = frozenset(
    {
        "opa-native",
        "self-protection-deterministic",
        "z3-native",
        "authorization-deterministic",
        "infrastructure-deterministic",
        "ci-secrets-deterministic",
        "deployment-deterministic",
        "lane-self-protection",
        "lane-authorization",
        "lane-infrastructure",
        "lane-ci-secrets",
        "lane-deployment",
    }
)

# The original `ovk init` recipe wrote this exact allowlist. It predated typed
# backend ids and was not intended to exclude the five lane adapters. Treat it
# as an unrestricted migration default so existing consumers do not silently
# disable shadow or enforced routing.
LEGACY_STARTER_ALLOWLIST: frozenset[str] = frozenset({"opa", "z3", "cedar"})

BACKEND_ALIASES: dict[str, frozenset[str]] = {
    "opa": frozenset({"opa", "opa-native"}),
    "z3": frozenset({"z3", "z3-native"}),
    "deterministic": frozenset(
        {
            "self-protection-deterministic",
            "authorization-deterministic",
            "infrastructure-deterministic",
            "ci-secrets-deterministic",
            "deployment-deterministic",
            "lane-self-protection",
            "lane-authorization",
            "lane-infrastructure",
            "lane-ci-secrets",
            "lane-deployment",
        }
    ),
    "self_protection": frozenset({"opa-native", "self-protection-deterministic", "lane-self-protection"}),
    "authorization": frozenset({"z3-native", "authorization-deterministic", "lane-authorization"}),
    "infrastructure": frozenset({"infrastructure-deterministic", "lane-infrastructure"}),
    "ci_secrets": frozenset({"ci-secrets-deterministic", "lane-ci-secrets"}),
    "deployment": frozenset({"deployment-deterministic", "lane-deployment"}),
}


def expand_backend_names(values: Iterable[object]) -> list[str]:
    """Expand short policy aliases while preserving explicit identifiers."""
    expanded: set[str] = set()
    for raw in values:
        value = str(raw).strip()
        if not value:
            continue
        expanded.add(value)
        expanded.update(BACKEND_ALIASES.get(value, ()))
    return sorted(expanded)


def normalize_allowed_backends(values: object) -> list[str] | None:
    """Normalize an allowed-backend policy, including the legacy starter recipe."""
    if not isinstance(values, (list, tuple, set, frozenset)):
        return None
    raw = frozenset(str(item).strip() for item in values if str(item).strip())
    if raw == LEGACY_STARTER_ALLOWLIST:
        return None
    return expand_backend_names(raw)


def normalize_denied_backends(values: object) -> list[str]:
    """Normalize denied backend aliases to every matching canonical identifier."""
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    return expand_backend_names(values)
