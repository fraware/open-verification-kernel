"""Repository-specific expansion_v2 adapters.

v0 adapters wrap authentic extract/materialize modules without modifying them.
Expansion adapters supply repository-specific source-side semantics for the
five frozen candidates.
"""

from __future__ import annotations

from .v0_certifyedge import CertifyEdgeAdapter
from .v0_pcs_core import PcsCoreAdapter
from .expansion_pcs_bench import PcsBenchAdapter
from .expansion_ovk_consumer import (
    OvkConsumerExpressActionsAdapter,
    OvkConsumerFastapiTerraformAdapter,
)
from .expansion_eac import EnvironmentAssuranceCompilerAdapter
from .expansion_lpe import LeanProjectEvidenceAdapter

__all__ = [
    "CertifyEdgeAdapter",
    "PcsCoreAdapter",
    "PcsBenchAdapter",
    "OvkConsumerFastapiTerraformAdapter",
    "OvkConsumerExpressActionsAdapter",
    "EnvironmentAssuranceCompilerAdapter",
    "LeanProjectEvidenceAdapter",
]
