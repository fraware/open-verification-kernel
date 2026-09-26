"""Bind one cached FastAPI route syntax summary into semantic IR fragments.

The binder is profile-aware and contract-version-aware, while RouteFileSummary is
profile-independent. This separation permits safe reuse of unchanged syntax
summaries and, later, already-bound semantic fragments when their dependencies
remain identical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ovk.compilers.authorization.fastapi_route_summary import (
    CallSummary,
    RouteFileSummary,
)
from ovk.core.assurance_ir import (
    AuthorizationGuard,
    ContractUse,
    EffectRef,
    FunctionContract,
    PrincipalRef,
    ProtectedEffect,
    ResourceBinding,
    ResourceRef,
    SemanticPath,
)
from ovk.core.bundle import content_digest
from ovk.core.resource_identity import ResourceIdentityTerm


def _semantic_id(prefix: str, value: str) -> str:
    return f"{prefix}:{content_digest(value)[:16]}"


def _typed_contract_projection(
    contract: FunctionContract,
    return_attribute: str,
):
    matches = []
    for predicate in contract.postconditions:
        if (
            predicate.relation == "eq"
            and predicate.right is not None
            and predicate.left.kind == "return_attribute"
            and predicate.left.name == return_attribute
            and predicate.right.kind in {"parameter", "literal"}
            and (
                (
                    predicate.right.kind == "parameter"
                    and predicate.right.name is not None
                )
                or (
                    predicate.right.kind == "literal"
                    and predicate.right.value is not None
                )
            )
        ):
            matches.append(predicate)
    return matches[0] if len(matches) == 1 else None


def _requires_non_null_parameter(
    contract: FunctionContract,
    parameter_name: str,
) -> bool:
    return any(
        predicate.relation == "non_null"
        and predicate.left.kind == "parameter"
        and predicate.left.name == parameter_name
        for predicate in contract.preconditions
    )


def _actual_argument(
    call: CallSummary,
    *,
    parameter_name: str,
    positional_parameters: list[str],
):
    keyword = call.keyword(parameter_name)
    if keyword is not None:
        return keyword
    if parameter_name not in positional_parameters:
        return None
    index = positional_parameters.index(parameter_name)
    if len(call.positional_arguments) <= index:
        return None
    return call.positional_arguments[index]


def _instantiate_contract_attributes(
    *,
    call: CallSummary,
    contract: FunctionContract,
) -> tuple[dict[str, ResourceIdentityTerm], set[str], set[str]]:
    terms: dict[str, ResourceIdentityTerm] = {}
    omitted: set[str] = set()
    unresolved: set[str] = set()

    for predicate in contract.postconditions:
        if (
            predicate.relation != "eq"
            or predicate.right is None
            or predicate.left.kind != "return_attribute"
            or predicate.left.name is None
            or predicate.right.kind not in {"parameter", "literal"}
        ):
            continue

        attribute = predicate.left.name
        if predicate.right.kind == "literal":
            if predicate.right.value is None:
                continue
            terms[attribute] = ResourceIdentityTerm.literal(
                predicate.right.value
            )
            continue

        parameter = predicate.right.name
        if parameter is None:
            continue
        argument = _actual_argument(
            call,
            parameter_name=parameter,
            positional_parameters=contract.positional_parameters,
        )
        if argument is None:
            omitted.add(attribute)
            continue
        if (
            _requires_non_null_parameter(contract, parameter)
            and not argument.provably_non_null
        ):
            unresolved.add(attribute)
            continue
        if argument.term is None:
            unresolved.add(attribute)
            continue
        terms[attribute] = argument.term

    return terms, omitted, unresolved


@dataclass(frozen=True)
class FastApiFileSemanticFragment:
    """Semantic objects produced by one source file under one binding context."""

    path: str
    source_digest: str
    profile_digest: str
    contract_dependencies: dict[str, str | None] = field(default_factory=dict)
    unsupported_constructs: tuple[str, ...] = ()
    principals: tuple[PrincipalRef, ...] = ()
    resources: tuple[ResourceRef, ...] = ()
    effects: tuple[EffectRef, ...] = ()
    guards: tuple[AuthorizationGuard, ...] = ()
    protected_effects: tuple[ProtectedEffect, ...] = ()
    resource_bindings: tuple[ResourceBinding, ...] = ()
    contract_uses: tuple[ContractUse, ...] = ()
    paths: tuple[SemanticPath, ...] = ()


def profile_semantic_digest(profile: Any) -> str:
    """Digest all profile fields that influence semantic route binding."""

    payload = {
        "sink_effects": dict(sorted(profile.sink_effects.items())),
        "sink_identity_args": dict(sorted(profile.sink_identity_args.items())),
        "sink_scope_keywords": dict(sorted(profile.sink_scope_keywords.items())),
        "sink_missing_scope_unconstrained": sorted(
            profile.sink_missing_scope_unconstrained
        ),
        "sink_contracts": dict(sorted(profile.sink_contracts.items())),
        "sink_contract_scope_attributes": dict(
            sorted(profile.sink_contract_scope_attributes.items())
        ),
        "sink_contract_identity_attributes": dict(
            sorted(profile.sink_contract_identity_attributes.items())
        ),
        "sink_binding_relations": dict(
            sorted(profile.sink_binding_relations.items())
        ),
        "sink_binding_authorized_projections": dict(
            sorted(profile.sink_binding_authorized_projections.items())
        ),
        "sink_binding_acted_projections": dict(
            sorted(profile.sink_binding_acted_projections.items())
        ),
        "sink_binding_authorized_attributes": dict(
            sorted(profile.sink_binding_authorized_attributes.items())
        ),
        "sink_binding_acted_attributes": dict(
            sorted(profile.sink_binding_acted_attributes.items())
        ),
        "dependency_guard_resources": dict(
            sorted(profile.dependency_guard_resources.items())
        ),
        "dependency_guard_effects": {
            key: sorted(value)
            for key, value in sorted(profile.dependency_guard_effects.items())
        },
        "principal_parameter": profile.principal_parameter,
    }
    return content_digest(payload)


def bind_route_file_summary(
    file_summary: RouteFileSummary,
    *,
    profile: Any,
    contracts_by_name: Mapping[str, FunctionContract],
) -> FastApiFileSemanticFragment:
    """Bind one file summary against current profile and function contracts."""

    principals: dict[str, PrincipalRef] = {}
    resources: dict[str, ResourceRef] = {}
    effects: dict[str, EffectRef] = {}
    guards: dict[str, AuthorizationGuard] = {}
    protected: dict[str, ProtectedEffect] = {}
    bindings: dict[str, ResourceBinding] = {}
    contract_uses: dict[str, ContractUse] = {}
    paths: dict[str, SemanticPath] = {}
    unsupported: list[str] = []
    dependencies: dict[str, str | None] = {}

    for handler in file_summary.handlers:
        if handler.has_control_flow:
            unsupported.append(
                f"{file_summary.path}:{handler.handler_name}:"
                "control_flow_outside_profile"
            )

        dependency_by_name = {
            item.dependency_name: item
            for item in handler.dependencies
        }

        principal_symbol = profile.principal_parameter
        principal_id = _semantic_id("principal", principal_symbol)
        principals.setdefault(
            principal_id,
            PrincipalRef(
                principal_id=principal_id,
                symbol=principal_symbol,
                principal_type="fastapi_dependency_result",
                origin=handler.origin,
            ),
        )

        for call in handler.calls:
            sink = profile.sink_effect_names(
                call.full_name,
                call.leaf_name,
            )
            if sink is None:
                continue
            sink_key, effect_name = sink
            identity_index = profile.identity_arg(sink_key)
            if len(call.positional_arguments) <= identity_index:
                unsupported.append(
                    f"{file_summary.path}:{handler.handler_name}:"
                    f"unsupported_sink_identity_signature:{sink_key}"
                )
                continue

            identity_expression = call.positional_arguments[identity_index]
            identity_term = None
            if profile.contract_identity_attribute_for_sink(sink_key) is None:
                identity_term = identity_expression.term
                if identity_term is None:
                    unsupported.append(
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"unsupported_sink_identity_expression:{sink_key}"
                    )
                    continue

            scope_term: ResourceIdentityTerm | None = None
            contract_attribute_terms: dict[str, ResourceIdentityTerm] = {}
            expected_contract_name = profile.contract_for_sink(sink_key)
            inferred_contract: FunctionContract | None = None
            if expected_contract_name is not None:
                inferred_contract = contracts_by_name.get(
                    expected_contract_name
                )
                dependencies[expected_contract_name] = (
                    inferred_contract.contract_id
                    if inferred_contract is not None
                    else None
                )
                if call.resolved_qualified_name != expected_contract_name:
                    unsupported.append(
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"sink_contract_target_unresolved:"
                        f"{sink_key}:{expected_contract_name}"
                    )
                    inferred_contract = None
                elif inferred_contract is None:
                    unsupported.append(
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"required_sink_contract_missing:"
                        f"{expected_contract_name}"
                    )

            if inferred_contract is not None:
                (
                    contract_attribute_terms,
                    omitted_contract_attributes,
                    unresolved_contract_attributes,
                ) = _instantiate_contract_attributes(
                    call=call,
                    contract=inferred_contract,
                )

                scope_attribute = (
                    profile.contract_scope_attribute_for_sink(sink_key)
                )
                if scope_attribute is not None:
                    scope_post = _typed_contract_projection(
                        inferred_contract,
                        scope_attribute,
                    )
                    if scope_post is None:
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            f"required_scope_postcondition_missing:"
                            f"{expected_contract_name}:{scope_attribute}"
                        )
                    elif scope_attribute in contract_attribute_terms:
                        scope_term = contract_attribute_terms[scope_attribute]
                    elif scope_attribute in omitted_contract_attributes:
                        scope_term = ResourceIdentityTerm.symbol(
                            f"$scope:{file_summary.path}:"
                            f"{handler.handler_name}:{call.line}"
                        )
                    else:
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            f"contract_precondition_unproved:"
                            f"{expected_contract_name}:{scope_attribute}"
                        )

                identity_attribute = (
                    profile.contract_identity_attribute_for_sink(sink_key)
                )
                if identity_attribute is not None:
                    identity_post = _typed_contract_projection(
                        inferred_contract,
                        identity_attribute,
                    )
                    if identity_post is None:
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            f"required_identity_postcondition_missing:"
                            f"{expected_contract_name}:{identity_attribute}"
                        )
                    elif identity_attribute in contract_attribute_terms:
                        identity_term = contract_attribute_terms[
                            identity_attribute
                        ]
                    else:
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            "required_identity_argument_or_precondition_unproved:"
                            f"{expected_contract_name}:{identity_attribute}"
                        )

                _ = unresolved_contract_attributes

            elif expected_contract_name is None:
                scope_keyword = profile.scope_keyword(sink_key)
                if scope_keyword is not None:
                    scope_expression = call.keyword(scope_keyword)
                    if scope_expression is not None:
                        scope_term = scope_expression.term
                        if scope_term is None:
                            unsupported.append(
                                f"{file_summary.path}:{handler.handler_name}:"
                                f"unsupported_sink_scope_expression:{sink_key}"
                            )
                    elif profile.missing_scope_is_unconstrained(sink_key):
                        scope_term = ResourceIdentityTerm.symbol(
                            f"$scope:{file_summary.path}:"
                            f"{handler.handler_name}:{call.line}"
                        )
                    else:
                        unsupported.append(
                            f"{file_summary.path}:{handler.handler_name}:"
                            f"required_sink_scope_missing:{sink_key}"
                        )

            effect_id = _semantic_id("effect", effect_name)
            acted_id = _semantic_id(
                "resource",
                (
                    f"{file_summary.path}:{handler.handler_name}:{call.line}:"
                    f"{identity_expression.rendered}"
                ),
            )
            protected_id = _semantic_id(
                "protected",
                f"{acted_id}:{effect_name}",
            )
            effects.setdefault(
                effect_id,
                EffectRef(
                    effect_id=effect_id,
                    name=effect_name,
                    origin=call.origin,
                ),
            )
            resources[acted_id] = ResourceRef(
                resource_id=acted_id,
                symbol=identity_expression.rendered,
                identity_term=identity_term,
                scope_term=scope_term,
                attribute_terms=contract_attribute_terms,
                origin=identity_expression.origin,
            )

            contract_use_ids: list[str] = []
            if inferred_contract is not None:
                use_id = _semantic_id(
                    "contract-use",
                    (
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"{call.line}:{inferred_contract.contract_id}:"
                        f"{acted_id}"
                    ),
                )
                contract_uses[use_id] = ContractUse(
                    use_id=use_id,
                    contract_id=inferred_contract.contract_id,
                    qualified_name=inferred_contract.qualified_name,
                    resource_id=acted_id,
                    established_attributes=sorted(
                        contract_attribute_terms
                    ),
                    origin=call.origin,
                )
                contract_use_ids.append(use_id)

            guard_ids: list[str] = []
            binding_ids: list[str] = []
            for (
                dep_name,
                allowed_effects,
            ) in profile.dependency_guard_effects.items():
                if effect_name not in allowed_effects:
                    continue
                dep_record = dependency_by_name.get(dep_name)
                resource_symbol = profile.dependency_guard_resources.get(
                    dep_name
                )
                if dep_record is None or resource_symbol is None:
                    continue
                if (
                    dep_record.parameter_name
                    != profile.principal_parameter
                ):
                    unsupported.append(
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"dependency_principal_mismatch:{dep_name}"
                    )
                    continue

                guard_resource_id = _semantic_id(
                    "resource",
                    resource_symbol,
                )
                resources.setdefault(
                    guard_resource_id,
                    ResourceRef(
                        resource_id=guard_resource_id,
                        symbol=resource_symbol,
                        identity_term=ResourceIdentityTerm.symbol(
                            resource_symbol
                        ),
                        origin=dep_record.origin,
                    ),
                )
                guard_id = _semantic_id(
                    "guard",
                    (
                        f"{file_summary.path}:{handler.handler_name}:"
                        f"{dep_name}:{effect_name}:{resource_symbol}"
                    ),
                )
                guards[guard_id] = AuthorizationGuard(
                    guard_id=guard_id,
                    principal_id=principal_id,
                    effect_id=effect_id,
                    resource_id=guard_resource_id,
                    origin=dep_record.origin,
                )
                guard_ids.append(guard_id)

                relation = profile.binding_relation_for_sink(sink_key)
                authorized_projection = (
                    profile.binding_authorized_projection_for_sink(
                        sink_key
                    )
                )
                acted_projection = (
                    profile.binding_acted_projection_for_sink(sink_key)
                )
                authorized_attribute = (
                    profile.binding_authorized_attribute_for_sink(
                        sink_key
                    )
                )
                acted_attribute = (
                    profile.binding_acted_attribute_for_sink(sink_key)
                )
                binding_id = _semantic_id(
                    "binding",
                    (
                        f"{guard_id}:{guard_resource_id}:{acted_id}:"
                        f"{relation}:{authorized_projection}:"
                        f"{acted_projection}:{authorized_attribute}:"
                        f"{acted_attribute}"
                    ),
                )
                bindings[binding_id] = ResourceBinding(
                    binding_id=binding_id,
                    authorized_resource_id=guard_resource_id,
                    acted_resource_id=acted_id,
                    relation=relation,
                    authorized_projection=authorized_projection,
                    acted_projection=acted_projection,
                    authorized_attribute=authorized_attribute,
                    acted_attribute=acted_attribute,
                    origin=call.origin,
                )
                binding_ids.append(binding_id)

            protected[protected_id] = ProtectedEffect(
                protected_effect_id=protected_id,
                principal_id=principal_id,
                effect_id=effect_id,
                resource_id=acted_id,
                origin=call.origin,
            )
            path_id = _semantic_id(
                "path",
                (
                    f"{handler.method}:{handler.route_path}:"
                    f"{handler.handler_name}:{protected_id}"
                ),
            )
            paths[path_id] = SemanticPath(
                path_id=path_id,
                entrypoint=f"{handler.method} {handler.route_path}",
                guard_ids=sorted(guard_ids),
                protected_effect_ids=[protected_id],
                binding_ids=sorted(binding_ids),
                contract_use_ids=sorted(contract_use_ids),
                origin=handler.origin,
            )

    return FastApiFileSemanticFragment(
        path=file_summary.path,
        source_digest=file_summary.source_digest,
        profile_digest=profile_semantic_digest(profile),
        contract_dependencies=dict(sorted(dependencies.items())),
        unsupported_constructs=tuple(sorted(set(unsupported))),
        principals=tuple(
            sorted(principals.values(), key=lambda item: item.principal_id)
        ),
        resources=tuple(
            sorted(resources.values(), key=lambda item: item.resource_id)
        ),
        effects=tuple(
            sorted(effects.values(), key=lambda item: item.effect_id)
        ),
        guards=tuple(
            sorted(guards.values(), key=lambda item: item.guard_id)
        ),
        protected_effects=tuple(
            sorted(
                protected.values(),
                key=lambda item: item.protected_effect_id,
            )
        ),
        resource_bindings=tuple(
            sorted(bindings.values(), key=lambda item: item.binding_id)
        ),
        contract_uses=tuple(
            sorted(contract_uses.values(), key=lambda item: item.use_id)
        ),
        paths=tuple(
            sorted(paths.values(), key=lambda item: item.path_id)
        ),
    )


def fragment_dependencies_match(
    fragment: FastApiFileSemanticFragment,
    *,
    profile: Any,
    contracts_by_name: Mapping[str, FunctionContract],
) -> bool:
    """Return whether profile and consumed contract versions are unchanged."""

    if fragment.profile_digest != profile_semantic_digest(profile):
        return False
    current = {
        name: (
            contracts_by_name[name].contract_id
            if name in contracts_by_name
            else None
        )
        for name in fragment.contract_dependencies
    }
    return current == fragment.contract_dependencies
