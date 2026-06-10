"""Registry for external backend adapters."""

from __future__ import annotations

from ovk.adapters.alloy.adapter import ADAPTER as ALLOY_ADAPTER
from ovk.adapters.cedar.adapter import ADAPTER as CEDAR_ADAPTER
from ovk.adapters.cbmc.adapter import ADAPTER as CBMC_ADAPTER
from ovk.adapters.dafny.adapter import ADAPTER as DAFNY_ADAPTER
from ovk.adapters.kani.adapter import ADAPTER as KANI_ADAPTER
from ovk.adapters.lean.adapter import ADAPTER as LEAN_ADAPTER
from ovk.adapters.tla.adapter import ADAPTER as TLA_ADAPTER
from ovk.adapters.verus.adapter import ADAPTER as VERUS_ADAPTER
from ovk.adapters.external.base_adapter import BaseExternalAdapter


WAVE1_ADAPTERS: list[BaseExternalAdapter] = [CEDAR_ADAPTER, TLA_ADAPTER, KANI_ADAPTER]
WAVE2_ADAPTERS: list[BaseExternalAdapter] = [
    DAFNY_ADAPTER,
    VERUS_ADAPTER,
    LEAN_ADAPTER,
    CBMC_ADAPTER,
    ALLOY_ADAPTER,
]
ALL_EXTERNAL_ADAPTERS: list[BaseExternalAdapter] = WAVE1_ADAPTERS + WAVE2_ADAPTERS


def adapter_by_name(name: str) -> BaseExternalAdapter | None:
    """Return a registered adapter by backend tool name."""
    for adapter in ALL_EXTERNAL_ADAPTERS:
        if adapter.backend_name == name:
            return adapter
    return None


def all_external_adapters() -> list[BaseExternalAdapter]:
    """Return all registered external adapters."""
    return list(ALL_EXTERNAL_ADAPTERS)
