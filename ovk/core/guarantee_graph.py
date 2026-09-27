"""Durable guarantee graph over revision-specific Assurance IR.

A GuaranteeSpec is an explicit repository-level assurance object with identity that
survives individual pull requests. Source extraction never creates or silently
changes a guarantee. Instead, each repository revision binds the declared
guarantee to exactly one current ProtectedEffect through a semantic selector.

This module deliberately separates:
- durable organizational intent (GuaranteeSpec);
- revision-specific source binding (GuaranteeBinding);
- semantic transition classification (GuaranteeTransition).

It does not claim that a changed guarantee is strengthened or weakened. Those
relations require a proof of implication that is outside the v1 graph.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ovk.core.assurance_ir import AssuranceIR
from ovk.core.bundle import content_digest
from ovk.core.incremental_assurance import protected_effect_semantic_digest


GuaranteeType = Literal["protected_effect_integrity_v1"]
GuaranteeBindingStatus = Literal["bound", "unresolved", "ambiguous"]
GuaranteeTransitionKind = Literal[
    "new_guarantee",
    "removed_guarantee",
    "definition_modified",
    "newly_bound",
    "binding_lost",
    "semantic_support_unchanged",
    "semantic_support_changed",
    "unresolved",
]


class GuaranteeSelector(BaseModel):
    """Semantic selector used to bind one durable guarantee to current IR.

    effect_name is required because namespaced effects are the most stable
    application-facing semantic identifier currently represented in Assurance IR.
    Optional principal/resource/path fields may narrow the match. A selector must
    resolve to exactly one ProtectedEffect; zero or multiple matches fail closed.
    """

    effect_name: str
    principal_symbol: str | None = None
    principal_type: str | None = None
    resource_symbol: str | None = None
    resource_type: str | None = None
    entrypoint: str | None = None

    @field_validator(
        "effect_name",
        "principal_symbol",
        "principal_type",
        "resource_symbol",
        "resource_type",
        "entrypoint",
    )
    @classmethod
    def _strip_nonempty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("guarantee selector strings must be non-empty")
        return value


class GuaranteeSpec(BaseModel):
    """Durable repository-level assurance intent."""

    guarantee_id: str
    spec_version: str = "1"
    guarantee_type: GuaranteeType = "protected_effect_integrity_v1"
    statement: str
    selector: GuaranteeSelector
    assumptions: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    origin_intent: dict[str, Any] = Field(default_factory=dict)

    @field_validator("guarantee_id", "spec_version", "statement")
    @classmethod
    def _required_nonempty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("guarantee identity, version, and statement must be non-empty")
        return value

    @field_validator("dependencies")
    @classmethod
    def _normalized_dependencies(cls, values: list[str]) -> list[str]:
        normalized = [value.strip() for value in values if value.strip()]
        if len(normalized) != len(set(normalized)):
            raise ValueError("guarantee dependencies must be unique")
        return normalized

    @model_validator(mode="after")
    def _no_self_dependency(self) -> "GuaranteeSpec":
        if self.guarantee_id in self.dependencies:
            raise ValueError("guarantee cannot depend on itself")
        return self

    @property
    def definition_digest(self) -> str:
        """Content address of the declared guarantee definition."""
        return content_digest(self.model_dump(mode="json"))


class GuaranteeBinding(BaseModel):
    """Binding of one durable guarantee to one repository revision."""

    guarantee_id: str
    status: GuaranteeBindingStatus
    assurance_ir_digest: str
    protected_effect_id: str | None = None
    semantic_slice_digest: str | None = None
    matched_protected_effect_ids: list[str] = Field(default_factory=list)
    reason: str


class GuaranteeGraphRevision(BaseModel):
    """Guarantee graph materialized against one Assurance IR revision."""

    assurance_ir_digest: str
    subject_repo: str
    subject_head_sha: str
    spec_definition_digests: dict[str, str]
    bindings: list[GuaranteeBinding]
    dependency_edges: dict[str, list[str]]

    def binding_for(self, guarantee_id: str) -> GuaranteeBinding:
        matches = [item for item in self.bindings if item.guarantee_id == guarantee_id]
        if len(matches) != 1:
            raise ValueError(f"guarantee binding missing or duplicated: {guarantee_id}")
        return matches[0]


class GuaranteeTransition(BaseModel):
    """Mechanically justified transition for one durable guarantee."""

    guarantee_id: str
    kind: GuaranteeTransitionKind
    reason: str
    base_binding: GuaranteeBinding | None = None
    head_binding: GuaranteeBinding | None = None
    dependency_affected: bool = False
    dependency_change_roots: list[str] = Field(default_factory=list)


class GuaranteeTransitionReport(BaseModel):
    base_assurance_ir_digest: str
    head_assurance_ir_digest: str
    transitions: list[GuaranteeTransition]


def _validate_guarantee_specs(specs: list[GuaranteeSpec]) -> dict[str, GuaranteeSpec]:
    by_id: dict[str, GuaranteeSpec] = {}
    for spec in specs:
        if spec.guarantee_id in by_id:
            raise ValueError(f"duplicate guarantee_id: {spec.guarantee_id}")
        by_id[spec.guarantee_id] = spec

    for spec in specs:
        missing = [dep for dep in spec.dependencies if dep not in by_id]
        if missing:
            raise ValueError(
                f"guarantee {spec.guarantee_id} references unknown dependencies: "
                + ", ".join(sorted(missing))
            )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(guarantee_id: str) -> None:
        if guarantee_id in visited:
            return
        if guarantee_id in visiting:
            raise ValueError(f"guarantee dependency cycle includes: {guarantee_id}")
        visiting.add(guarantee_id)
        for dependency in by_id[guarantee_id].dependencies:
            visit(dependency)
        visiting.remove(guarantee_id)
        visited.add(guarantee_id)

    for guarantee_id in sorted(by_id):
        visit(guarantee_id)

    return by_id


def _matches_selector(
    ir: AssuranceIR,
    protected_effect_id: str,
    selector: GuaranteeSelector,
) -> bool:
    protected_by_id = {
        item.protected_effect_id: item for item in ir.protected_effects
    }
    effect_by_id = {item.effect_id: item for item in ir.effects}
    principal_by_id = {item.principal_id: item for item in ir.principals}
    resource_by_id = {item.resource_id: item for item in ir.resources}

    protected = protected_by_id.get(protected_effect_id)
    if protected is None:
        return False
    effect = effect_by_id.get(protected.effect_id)
    principal = principal_by_id.get(protected.principal_id)
    resource = resource_by_id.get(protected.resource_id)
    if effect is None or principal is None or resource is None:
        return False

    if effect.name != selector.effect_name:
        return False
    if (
        selector.principal_symbol is not None
        and principal.symbol != selector.principal_symbol
    ):
        return False
    if (
        selector.principal_type is not None
        and principal.principal_type != selector.principal_type
    ):
        return False
    if (
        selector.resource_symbol is not None
        and resource.symbol != selector.resource_symbol
    ):
        return False
    if (
        selector.resource_type is not None
        and resource.resource_type != selector.resource_type
    ):
        return False
    if selector.entrypoint is not None:
        matching_paths = [
            path
            for path in ir.paths
            if protected_effect_id in path.protected_effect_ids
            and path.entrypoint == selector.entrypoint
        ]
        if not matching_paths:
            return False
    return True


def bind_guarantee(ir: AssuranceIR, spec: GuaranteeSpec) -> GuaranteeBinding:
    """Bind a durable guarantee to exactly one current ProtectedEffect."""

    matches = sorted(
        item.protected_effect_id
        for item in ir.protected_effects
        if _matches_selector(ir, item.protected_effect_id, spec.selector)
    )
    if not matches:
        return GuaranteeBinding(
            guarantee_id=spec.guarantee_id,
            status="unresolved",
            assurance_ir_digest=ir.assurance_ir_digest,
            matched_protected_effect_ids=[],
            reason="semantic selector matched no protected effect",
        )
    if len(matches) > 1:
        return GuaranteeBinding(
            guarantee_id=spec.guarantee_id,
            status="ambiguous",
            assurance_ir_digest=ir.assurance_ir_digest,
            matched_protected_effect_ids=matches,
            reason="semantic selector matched multiple protected effects",
        )

    protected_effect_id = matches[0]
    return GuaranteeBinding(
        guarantee_id=spec.guarantee_id,
        status="bound",
        assurance_ir_digest=ir.assurance_ir_digest,
        protected_effect_id=protected_effect_id,
        semantic_slice_digest=protected_effect_semantic_digest(
            ir, protected_effect_id
        ),
        matched_protected_effect_ids=matches,
        reason="semantic selector resolved uniquely",
    )


def build_guarantee_graph_revision(
    ir: AssuranceIR,
    specs: list[GuaranteeSpec],
) -> GuaranteeGraphRevision:
    """Validate and materialize durable guarantees against one revision."""

    by_id = _validate_guarantee_specs(specs)
    bindings = [
        bind_guarantee(ir, by_id[guarantee_id])
        for guarantee_id in sorted(by_id)
    ]
    return GuaranteeGraphRevision(
        assurance_ir_digest=ir.assurance_ir_digest,
        subject_repo=ir.subject.repo,
        subject_head_sha=ir.subject.head_sha,
        spec_definition_digests={
            guarantee_id: by_id[guarantee_id].definition_digest
            for guarantee_id in sorted(by_id)
        },
        bindings=bindings,
        dependency_edges={
            guarantee_id: sorted(by_id[guarantee_id].dependencies)
            for guarantee_id in sorted(by_id)
        },
    )


def _direct_transition(
    guarantee_id: str,
    *,
    base_specs: dict[str, GuaranteeSpec],
    head_specs: dict[str, GuaranteeSpec],
    base_graph: GuaranteeGraphRevision,
    head_graph: GuaranteeGraphRevision,
) -> GuaranteeTransition:
    base_spec = base_specs.get(guarantee_id)
    head_spec = head_specs.get(guarantee_id)

    if base_spec is None and head_spec is not None:
        return GuaranteeTransition(
            guarantee_id=guarantee_id,
            kind="new_guarantee",
            reason="guarantee definition is new in the head revision",
            head_binding=head_graph.binding_for(guarantee_id),
        )
    if base_spec is not None and head_spec is None:
        return GuaranteeTransition(
            guarantee_id=guarantee_id,
            kind="removed_guarantee",
            reason="guarantee definition is absent from the head revision",
            base_binding=base_graph.binding_for(guarantee_id),
        )
    assert base_spec is not None and head_spec is not None

    base_binding = base_graph.binding_for(guarantee_id)
    head_binding = head_graph.binding_for(guarantee_id)

    if base_spec.definition_digest != head_spec.definition_digest:
        return GuaranteeTransition(
            guarantee_id=guarantee_id,
            kind="definition_modified",
            reason="durable guarantee definition changed explicitly",
            base_binding=base_binding,
            head_binding=head_binding,
        )

    if base_binding.status != "bound" and head_binding.status == "bound":
        return GuaranteeTransition(
            guarantee_id=guarantee_id,
            kind="newly_bound",
            reason="previously unresolved guarantee now binds uniquely",
            base_binding=base_binding,
            head_binding=head_binding,
        )
    if base_binding.status == "bound" and head_binding.status != "bound":
        return GuaranteeTransition(
            guarantee_id=guarantee_id,
            kind="binding_lost",
            reason=(
                "previously bound guarantee is no longer uniquely bound: "
                + head_binding.reason
            ),
            base_binding=base_binding,
            head_binding=head_binding,
        )
    if base_binding.status != "bound" or head_binding.status != "bound":
        return GuaranteeTransition(
            guarantee_id=guarantee_id,
            kind="unresolved",
            reason="guarantee is not uniquely bound in both revisions",
            base_binding=base_binding,
            head_binding=head_binding,
        )

    if base_binding.semantic_slice_digest == head_binding.semantic_slice_digest:
        return GuaranteeTransition(
            guarantee_id=guarantee_id,
            kind="semantic_support_unchanged",
            reason="bound protected-effect semantic support slice is unchanged",
            base_binding=base_binding,
            head_binding=head_binding,
        )

    return GuaranteeTransition(
        guarantee_id=guarantee_id,
        kind="semantic_support_changed",
        reason=(
            "bound protected-effect semantic support slice changed; "
            "fresh assurance is required"
        ),
        base_binding=base_binding,
        head_binding=head_binding,
    )


def compare_guarantee_graphs(
    *,
    base_ir: AssuranceIR,
    head_ir: AssuranceIR,
    base_specs: list[GuaranteeSpec],
    head_specs: list[GuaranteeSpec] | None = None,
) -> GuaranteeTransitionReport:
    """Compare durable guarantees across two repository revisions.

    Dependency impact is propagated transitively over the union of base and head
    dependency edges. This marks dependents as affected; it does not assert that
    their own semantic support changed.
    """

    resolved_head_specs = head_specs if head_specs is not None else base_specs
    base_by_id = _validate_guarantee_specs(base_specs)
    head_by_id = _validate_guarantee_specs(resolved_head_specs)

    base_graph = build_guarantee_graph_revision(base_ir, base_specs)
    head_graph = build_guarantee_graph_revision(head_ir, resolved_head_specs)

    all_ids = sorted(set(base_by_id) | set(head_by_id))
    transitions = {
        guarantee_id: _direct_transition(
            guarantee_id,
            base_specs=base_by_id,
            head_specs=head_by_id,
            base_graph=base_graph,
            head_graph=head_graph,
        )
        for guarantee_id in all_ids
    }

    reverse_dependencies: dict[str, set[str]] = {}
    for graph in (base_graph, head_graph):
        for dependent, dependencies in graph.dependency_edges.items():
            for dependency in dependencies:
                reverse_dependencies.setdefault(dependency, set()).add(dependent)

    changed_roots = {
        guarantee_id
        for guarantee_id, transition in transitions.items()
        if transition.kind != "semantic_support_unchanged"
    }

    roots_by_dependent: dict[str, set[str]] = {
        guarantee_id: set() for guarantee_id in transitions
    }
    for root in sorted(changed_roots):
        queue: deque[str] = deque(sorted(reverse_dependencies.get(root, set())))
        seen: set[str] = set()
        while queue:
            dependent = queue.popleft()
            if dependent in seen:
                continue
            seen.add(dependent)
            if dependent in roots_by_dependent:
                roots_by_dependent[dependent].add(root)
            queue.extend(sorted(reverse_dependencies.get(dependent, set())))

    output: list[GuaranteeTransition] = []
    for guarantee_id in all_ids:
        transition = transitions[guarantee_id]
        roots = sorted(roots_by_dependent.get(guarantee_id, set()))
        output.append(
            transition.model_copy(
                update={
                    "dependency_affected": bool(roots),
                    "dependency_change_roots": roots,
                }
            )
        )

    return GuaranteeTransitionReport(
        base_assurance_ir_digest=base_ir.assurance_ir_digest,
        head_assurance_ir_digest=head_ir.assurance_ir_digest,
        transitions=output,
    )
