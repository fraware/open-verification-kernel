"""Restricted symbolic resource-identity terms.

These terms are intentionally small. They encode only identity facts an extractor
is authorized to claim from its declared source profile. They do not model
arbitrary program expressions.

Interpretation provenance prevents a shared raw input from being conflated after
different decoders, coercions, validators, or canonicalizers have been applied.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, field_validator, model_validator

from ovk.core.bundle import content_digest


IdentityTermKind = Literal["symbol", "literal"]


class ResourceInterpretation(BaseModel):
    """Typed interpretation contract for one externally sourced identity value.

    input_origin is a canonical source identifier such as
    request.path.backfill_id. decoder names the source-grounded interpretation
    operation. output_type and constraints describe the semantic value produced
    by that operation.

    This object is descriptive evidence from the extractor. Merely naming two
    different decoders does not prove either equivalence or inequivalence.
    """

    input_origin: str
    decoder: str
    output_type: str
    constraints: tuple[str, ...] = ()

    @field_validator("input_origin", "decoder", "output_type")
    @classmethod
    def _required_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("resource interpretation fields must be non-empty")
        return value

    @field_validator("constraints")
    @classmethod
    def _canonical_constraints(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized: list[str] = []
        for value in values:
            item = value.strip()
            if not item:
                raise ValueError(
                    "resource interpretation constraints must be non-empty"
                )
            normalized.append(item)
        return tuple(sorted(set(normalized)))


class ResourceIdentityTerm(BaseModel):
    """Canonical identity term used by resource-binding verification.

    Plain symbols preserve the historical v1 semantics. Interpreted symbols add
    the source-input interpretation contract needed to distinguish values that
    share an apparent source name but pass through different decoders.
    """

    kind: IdentityTermKind
    value: str
    interpretation: ResourceInterpretation | None = None

    @field_validator("value")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("resource identity term value must be non-empty")
        return value

    @model_validator(mode="after")
    def _interpretation_shape(self) -> "ResourceIdentityTerm":
        if self.kind == "literal" and self.interpretation is not None:
            raise ValueError(
                "literal resource identities cannot carry interpretation provenance"
            )
        return self

    @classmethod
    def symbol(cls, name: str) -> "ResourceIdentityTerm":
        return cls(kind="symbol", value=name)

    @classmethod
    def interpreted_symbol(
        cls,
        name: str,
        *,
        input_origin: str,
        decoder: str,
        output_type: str,
        constraints: tuple[str, ...] = (),
    ) -> "ResourceIdentityTerm":
        return cls(
            kind="symbol",
            value=name,
            interpretation=ResourceInterpretation(
                input_origin=input_origin,
                decoder=decoder,
                output_type=output_type,
                constraints=constraints,
            ),
        )

    @classmethod
    def literal(cls, value: str) -> "ResourceIdentityTerm":
        return cls(kind="literal", value=value)

    def canonical_payload(self) -> dict:
        """Return the stable identity payload used by digests and caches."""

        payload: dict = {
            "kind": self.kind,
            "value": self.value,
        }
        if self.interpretation is not None:
            payload["interpretation"] = self.interpretation.model_dump(
                mode="json"
            )
        return payload

    @property
    def term_id(self) -> str:
        return f"rid:{content_digest(self.canonical_payload())[:16]}"
