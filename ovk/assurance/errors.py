"""Assurance-mode error hierarchy (fail closed)."""

from __future__ import annotations


class AssuranceError(Exception):
    """Base error for verifier-assurance operations."""


class PinError(AssuranceError):
    """PCS pin resolution or schema availability failure."""


class MutationError(AssuranceError):
    """Typed mutation refused or unsupported."""


class ReplayError(AssuranceError):
    """Invocation replay failed closed (drift, missing deps, invalid claim)."""


class EvidenceError(AssuranceError):
    """Evidence pack layout or content validation failure."""
