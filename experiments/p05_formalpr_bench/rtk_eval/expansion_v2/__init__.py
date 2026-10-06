"""RTK source-universe expansion v2: generic adapter interface freeze.

This package is **new** methodology machinery. It is not recovered authentic v0
census/extractor code. Do not process the five frozen expansion candidates for
materialization until the adapter interface and v0 compatibility gate pass
human review.
"""

from __future__ import annotations

from .adapter_contract import (
    ADAPTER_METHOD_NAMES,
    PROHIBITED_CAPABILITIES,
    SourceRepositoryAdapter,
)
from .reason_codes import EXCLUSION_REASON_CODES, ExclusionReasonCode

__all__ = [
    "ADAPTER_METHOD_NAMES",
    "EXCLUSION_REASON_CODES",
    "ExclusionReasonCode",
    "PROHIBITED_CAPABILITIES",
    "SourceRepositoryAdapter",
]

SCHEMA_VERSION = "rtk.expansion_v2.adapter_interface.v0"
PROTOCOL_PATH = "experiments/rtk/SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v2.md"
STATUS = "V2_METHODOLOGY_INTERFACE_FROZEN_PENDING_MATERIALIZATION"
