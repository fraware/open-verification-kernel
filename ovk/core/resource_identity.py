"""Restricted symbolic resource-identity terms.

These terms are intentionally small. They encode only identity facts an extractor
is authorized to claim from its declared source profile. They do not model
arbitrary program expressions.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, field_validator

from ovk.core.bundle import content_digest


IdentityTermKind = Literal["symbol", "literal"]


class ResourceIdentityTerm(BaseModel):
    """Canonical identity term used by resource-binding verification."""

    kind: IdentityTermKind
    value: str

    @field_validator("value")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("resource identity term value must be non-empty")
        return value

    @classmethod
    def symbol(cls, name: str) -> "ResourceIdentityTerm":
        return cls(kind="symbol", value=name)

    @classmethod
    def literal(cls, value: str) -> "ResourceIdentityTerm":
        return cls(kind="literal", value=value)

    @property
    def term_id(self) -> str:
        return f"rid:{content_digest(self.model_dump(mode='json'))[:16]}"
