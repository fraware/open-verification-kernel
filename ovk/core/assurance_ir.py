"""Typed semantic interchange model for repository assurance.

The Assurance IR sits between source/profile extraction and verification-obligation
compilation. Constructing a valid IR does not establish any security property.
Extractors must record provenance, abstraction coverage, unsupported semantics,
and assumptions explicitly.

The IR records what an extractor claims about a repository revision. Soundness of
source-to-IR extraction is a separate obligation from soundness of any verifier
that consumes the IR.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange, VerificationSubject
from ovk.core.resource_identity import ResourceIdentityTerm


CoverageStatus = Literal["complete", "partial", "unknown", "inapplicable"]
BindingRelation = Literal["equal", "same_tenant", "custom"]
BindingProjection = Literal["identity", "scope", "attribute"]
ContractTermKind = Literal["parameter", "return_attribute", "literal"]
ContractRelation = Literal["eq", "non_null"]
ContractDerivation = Literal["direct", "composed"]
ClaimKind = Literal[
    "protected_effect_integrity",
    "authorization",
    "tenant_isolation",
    "state_invariant",
    "information_flow",
    "custom",
]


class SemanticOrigin(BaseModel):
    """Source provenance for one semantic fact."""

    path: str
    extractor_id: str
    extractor_version: str
    source_range: SourceRange | None = None
    material_digest: str | None = None

    @field_validator("path", "extractor_id", "extractor_version")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("semantic provenance fields must be non-empty")
        return value


class PrincipalRef(BaseModel):
    """Symbolic principal derived from source or approved repository intent."""

    principal_id: str
    symbol: str
    principal_type: str | None = None
    origin: SemanticOrigin | None = None


class ResourceRef(BaseModel):
    """Symbolic resource whose identity may participate in proof obligations."""

    resource_id: str
    symbol: str
    resource_type: str | None = None
    tenant_symbol: str | None = None
    identity_term: ResourceIdentityTerm | None = None
    scope_term: ResourceIdentityTerm | None = None
    attribute_terms: dict[str, ResourceIdentityTerm] = Field(default_factory=dict)
    origin: SemanticOrigin | None = None


class EffectRef(BaseModel):
    """Open namespaced effect such as billing.invoice.refund."""

    effect_id: str
    name: str
    origin: SemanticOrigin | None = None

    @field_validator("name")
    @classmethod
    def _effect_name_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("effect name must be non-empty")
        return value


class PathCondition(BaseModel):
    """A source-grounded predicate constraining a semantic path."""

    condition_id: str
    expression: str
    origin: SemanticOrigin | None = None

    @field_validator("expression")
    @classmethod
    def _expression_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("path condition expression must be non-empty")
        return value


class AuthorizationGuard(BaseModel):
    """Authorization decision observed on an execution path."""

    guard_id: str
    principal_id: str
    effect_id: str
    resource_id: str
    condition_ids: list[str] = Field(default_factory=list)
    origin: SemanticOrigin


class ProtectedEffect(BaseModel):
    """Security-sensitive effect whose execution requires assurance."""

    protected_effect_id: str
    principal_id: str
    effect_id: str
    resource_id: str
    condition_ids: list[str] = Field(default_factory=list)
    origin: SemanticOrigin


class ContractTerm(BaseModel):
    """Serializable term used in interprocedural pre/postconditions."""

    kind: ContractTermKind
    name: str | None = None
    value: str | None = None

    @model_validator(mode="after")
    def _shape_is_valid(self) -> "ContractTerm":
        if self.kind in {"parameter", "return_attribute"}:
            if self.name is None or not self.name.strip():
                raise ValueError(f"{self.kind} contract term requires name")
            if self.value is not None:
                raise ValueError(f"{self.kind} contract term does not accept value")
        elif self.kind == "literal":
            if self.value is None:
                raise ValueError("literal contract term requires value")
            if self.name is not None:
                raise ValueError("literal contract term does not accept name")
        return self

    @classmethod
    def parameter(cls, name: str) -> "ContractTerm":
        return cls(kind="parameter", name=name)

    @classmethod
    def return_attribute(cls, name: str) -> "ContractTerm":
        return cls(kind="return_attribute", name=name)

    @classmethod
    def literal(cls, value: str) -> "ContractTerm":
        return cls(kind="literal", value=value)


class ContractPredicate(BaseModel):
    """Decidable predicate in the v1 interprocedural contract language."""

    relation: ContractRelation
    left: ContractTerm
    right: ContractTerm | None = None

    @model_validator(mode="after")
    def _predicate_shape(self) -> "ContractPredicate":
        if self.relation == "non_null":
            if self.right is not None:
                raise ValueError("non_null predicate is unary")
            if self.left.kind != "parameter":
                raise ValueError("v1 non_null predicate requires a parameter term")
        elif self.relation == "eq":
            if self.right is None:
                raise ValueError("eq predicate requires right term")
        return self


class FunctionContract(BaseModel):
    """Named, source-grounded pre/post contract for a callable."""

    contract_id: str
    qualified_name: str
    derivation: ContractDerivation = "direct"
    depends_on: list[str] = Field(default_factory=list)
    positional_parameters: list[str] = Field(default_factory=list)
    preconditions: list[ContractPredicate] = Field(default_factory=list)
    postconditions: list[ContractPredicate] = Field(default_factory=list)
    origin: SemanticOrigin

    @field_validator("qualified_name")
    @classmethod
    def _qualified_name_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("function contract qualified_name must be non-empty")
        return value


class ContractUse(BaseModel):
    """One source-grounded consumption of a FunctionContract."""

    use_id: str
    contract_id: str
    qualified_name: str
    resource_id: str
    established_attributes: list[str] = Field(default_factory=list)
    origin: SemanticOrigin

    @field_validator("use_id", "contract_id", "qualified_name", "resource_id")
    @classmethod
    def _contract_use_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("contract use fields must be non-empty")
        return value


class ResourceReturnContract(BaseModel):
    """Source-derived postcondition for a function returning a resource."""

    contract_id: str
    qualified_name: str
    return_scope_parameter: str
    return_scope_attribute: str
    requires_non_null_argument: bool = True
    origin: SemanticOrigin

    @field_validator("qualified_name", "return_scope_parameter", "return_scope_attribute")
    @classmethod
    def _contract_fields_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("resource return contract fields must be non-empty")
        return value


class ResourceBinding(BaseModel):
    """Required relationship between authorized and acted-upon resources."""

    binding_id: str
    authorized_resource_id: str
    acted_resource_id: str
    relation: BindingRelation = "equal"
    authorized_projection: BindingProjection = "identity"
    acted_projection: BindingProjection = "identity"
    authorized_attribute: str | None = None
    acted_attribute: str | None = None
    predicate: str | None = None
    condition_ids: list[str] = Field(default_factory=list)
    origin: SemanticOrigin

    @model_validator(mode="after")
    def _binding_shape(self) -> "ResourceBinding":
        if self.relation == "custom" and (self.predicate is None or not self.predicate.strip()):
            raise ValueError("custom resource binding requires predicate")
        if self.authorized_projection == "attribute":
            if self.authorized_attribute is None or not self.authorized_attribute.strip():
                raise ValueError("authorized attribute projection requires authorized_attribute")
        elif self.authorized_attribute is not None:
            raise ValueError("authorized_attribute requires attribute projection")
        if self.acted_projection == "attribute":
            if self.acted_attribute is None or not self.acted_attribute.strip():
                raise ValueError("acted attribute projection requires acted_attribute")
        elif self.acted_attribute is not None:
            raise ValueError("acted_attribute requires attribute projection")
        return self


class SemanticPath(BaseModel):
    """One source-grounded path from entrypoint toward protected behavior."""

    path_id: str
    entrypoint: str
    guard_ids: list[str] = Field(default_factory=list)
    protected_effect_ids: list[str] = Field(default_factory=list)
    binding_ids: list[str] = Field(default_factory=list)
    contract_use_ids: list[str] = Field(default_factory=list)
    condition_ids: list[str] = Field(default_factory=list)
    coverage_status: CoverageStatus | None = None
    unsupported_constructs: list[str] = Field(default_factory=list)
    coverage_assumptions: list[str] = Field(default_factory=list)
    origin: SemanticOrigin | None = None


class AssuranceClaim(BaseModel):
    """Durable semantic claim to be compiled into verification obligations later."""

    claim_id: str
    claim_kind: ClaimKind
    statement: str
    subject_ids: list[str] = Field(default_factory=list)
    assumption_ids: list[str] = Field(default_factory=list)
    acceptable_guarantees: list[str] = Field(default_factory=list)
    origin: SemanticOrigin | None = None

    @field_validator("statement")
    @classmethod
    def _statement_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("assurance claim statement must be non-empty")
        return value


class AssuranceCoverage(BaseModel):
    """Extractor coverage over the source profile represented by this IR."""

    status: CoverageStatus
    confidence: float = Field(ge=0.0, le=1.0)
    supported_constructs: list[str] = Field(default_factory=list)
    unsupported_constructs: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class AssuranceExtractorIdentity(BaseModel):
    extractor_id: str
    extractor_version: str
    source_profile_id: str | None = None


class AssuranceIR(BaseModel):
    """Canonical semantic interchange object for a repository revision."""

    schema_version: Literal["ovk.assurance_ir.v1"] = "ovk.assurance_ir.v1"
    subject: VerificationSubject
    extractor: AssuranceExtractorIdentity
    coverage: AssuranceCoverage

    principals: list[PrincipalRef] = Field(default_factory=list)
    resources: list[ResourceRef] = Field(default_factory=list)
    effects: list[EffectRef] = Field(default_factory=list)
    conditions: list[PathCondition] = Field(default_factory=list)
    guards: list[AuthorizationGuard] = Field(default_factory=list)
    protected_effects: list[ProtectedEffect] = Field(default_factory=list)
    resource_bindings: list[ResourceBinding] = Field(default_factory=list)
    resource_return_contracts: list[ResourceReturnContract] = Field(default_factory=list)
    function_contracts: list[FunctionContract] = Field(default_factory=list)
    contract_uses: list[ContractUse] = Field(default_factory=list)
    paths: list[SemanticPath] = Field(default_factory=list)
    claims: list[AssuranceClaim] = Field(default_factory=list)
    assumptions: dict[str, str] = Field(default_factory=dict)

    def canonical_payload(self) -> dict:
        """Return order-stable JSON payload for identity and evidence binding."""

        payload = self.model_dump(mode="json")
        collection_keys = {
            "principals": "principal_id",
            "resources": "resource_id",
            "effects": "effect_id",
            "conditions": "condition_id",
            "guards": "guard_id",
            "protected_effects": "protected_effect_id",
            "resource_bindings": "binding_id",
            "resource_return_contracts": "contract_id",
            "function_contracts": "contract_id",
            "contract_uses": "use_id",
            "paths": "path_id",
            "claims": "claim_id",
        }
        for field_name, identity_key in collection_keys.items():
            payload[field_name] = sorted(payload[field_name], key=lambda item: item[identity_key])

        payload["coverage"]["supported_constructs"] = sorted(payload["coverage"]["supported_constructs"])
        payload["coverage"]["unsupported_constructs"] = sorted(payload["coverage"]["unsupported_constructs"])
        payload["coverage"]["assumptions"] = sorted(payload["coverage"]["assumptions"])

        for field_name in ("guards", "protected_effects", "resource_bindings", "paths"):
            for item in payload[field_name]:
                if "condition_ids" in item:
                    item["condition_ids"] = sorted(item["condition_ids"])

        for item in payload["paths"]:
            item["guard_ids"] = sorted(item["guard_ids"])
            item["protected_effect_ids"] = sorted(item["protected_effect_ids"])
            item["binding_ids"] = sorted(item["binding_ids"])
            item["contract_use_ids"] = sorted(item["contract_use_ids"])
            item["unsupported_constructs"] = sorted(item["unsupported_constructs"])
            item["coverage_assumptions"] = sorted(item["coverage_assumptions"])

        for item in payload["function_contracts"]:
            item["depends_on"] = sorted(item["depends_on"])
            item["preconditions"] = sorted(
                item["preconditions"],
                key=lambda pred: content_digest(pred),
            )
            item["postconditions"] = sorted(
                item["postconditions"],
                key=lambda pred: content_digest(pred),
            )

        for item in payload["contract_uses"]:
            item["established_attributes"] = sorted(item["established_attributes"])

        for item in payload["claims"]:
            item["subject_ids"] = sorted(item["subject_ids"])
            item["assumption_ids"] = sorted(item["assumption_ids"])
            item["acceptable_guarantees"] = sorted(item["acceptable_guarantees"])

        payload["assumptions"] = dict(sorted(payload["assumptions"].items()))
        return payload

    @property
    def assurance_ir_digest(self) -> str:
        """Content identity for this normalized semantic model."""

        return content_digest(self.canonical_payload())


def compute_assurance_ir_digest(ir: AssuranceIR | dict) -> str:
    """Compute the v1 Assurance IR content digest."""

    parsed = ir if isinstance(ir, AssuranceIR) else AssuranceIR.model_validate(ir)
    return parsed.assurance_ir_digest
