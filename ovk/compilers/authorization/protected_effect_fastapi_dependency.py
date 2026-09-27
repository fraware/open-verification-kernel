"""FastAPI dependency-to-effect Assurance IR profile.

This additive profile models a common production FastAPI authorization shape:

    user = Depends(require_workspace_member)
    ...
    await svc.get(resource_id, workspace_id=workspace_id)

The dependency is an authorization decision over a declared route resource.
A configured service call is the protected effect. The profile can require the
acted resource's scope to equal the resource authorized by the dependency.

The profile is intentionally narrow and advisory. Unsupported control flow,
dynamic routes, unsupported dependency forms, or unresolved sink signatures
lower extraction coverage instead of being silently ignored.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from ovk.compilers.authorization.base import normalize_path
from ovk.compilers.authorization.fastapi_include_router_dependencies import (
    infer_include_router_dependencies,
)
from ovk.compilers.authorization.fastapi_route_summary import (
    CallSummary,
    RouteSummaryIndex,
    build_route_summary_index,
    route_summary_index_matches_materials,
)
from ovk.compilers.authorization.fastapi_semantic_fragment import (
    assemble_fastapi_assurance_ir,
    bind_route_file_summary,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.python_ast_index import (
    ParsedPythonMaterials,
    parse_head_python_materials,
    parsed_index_matches_materials,
)
from ovk.compilers.authorization.route_dependency_effectiveness import (
    infer_route_dependency_effectiveness,
)
from ovk.compilers.authorization.resource_return_contracts import (
    ContractSummaryIndex,
    build_contract_summary_index,
    contract_summary_index_matches_materials,
    infer_function_contracts,
    infer_resource_return_contracts,
)
from ovk.core.assurance_ir import (
    AssuranceIR,
    BindingProjection,
    BindingRelation,
    SemanticOrigin,
)
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange
from ovk.core.resource_identity import ResourceIdentityTerm


_SOURCE_PROFILE_ID = "assurance.fastapi.dependency_effects.ast_v1"
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})
_CONTROL_FLOW = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match, ast.With, ast.AsyncWith)


@dataclass(frozen=True)
class ResourceScopeAssertionSemantics:
    """Semantics for a configured fail-closed resource-scope assertion helper.

    If a matching call returns normally, the source profile asserts that the
    acted resource attribute argument equals the authorization resource
    argument.
    """

    acted_scope_arg: int = 0
    authorized_resource_arg: int = 1
    acted_scope_attribute: str = "workspace_id"

    def __post_init__(self) -> None:
        if self.acted_scope_arg < 0 or self.authorized_resource_arg < 0:
            raise ValueError("scope assertion argument indexes must be non-negative")
        if not self.acted_scope_attribute.strip():
            raise ValueError("scope assertion attribute must be non-empty")


@dataclass(frozen=True)
class ResourceOwnershipAssertionSemantics:
    """Semantics for one fail-closed resource ownership assertion.

    A configured loader binds a route resource key to a loaded resource object.
    A supported source assertion rejects the continuing path when a present
    resource owner attribute differs from the configured principal attribute.

    truthy_when_present is required only for source forms that use a truthy
    resource presence check instead of an explicit is-not-None test.
    """

    resource_identity_attribute: str
    owner_attribute: str
    principal_attribute: str
    authorized_effects: tuple[str, ...]
    allow_missing_resource: bool = True
    truthy_when_present: bool = False

    def __post_init__(self) -> None:
        for value, label in (
            (self.resource_identity_attribute, "resource_identity_attribute"),
            (self.owner_attribute, "owner_attribute"),
            (self.principal_attribute, "principal_attribute"),
        ):
            if not value.strip():
                raise ValueError(f"{label} must be non-empty")
        if not self.authorized_effects:
            raise ValueError("ownership assertion authorized_effects must be non-empty")
        if any(not effect.strip() for effect in self.authorized_effects):
            raise ValueError("ownership assertion effects must be non-empty")


@dataclass(frozen=True)
class FastApiDependencyEffectProfile:
    """Explicit semantics for dependency guards and protected service calls."""

    sink_effects: dict[str, str]
    sink_identity_args: dict[str, int] = field(default_factory=dict)
    # Sink key -> static capability/resource identity. When present, no source
    # argument is interpreted as resource identity for that sink.
    sink_static_resources: dict[str, str] = field(default_factory=dict)
    sink_scope_keywords: dict[str, str] = field(default_factory=dict)
    sink_missing_scope_unconstrained: frozenset[str] = frozenset()
    # Helper name -> explicit fail-closed resource-scope assertion semantics.
    scope_assertions: dict[str, ResourceScopeAssertionSemantics] = field(
        default_factory=dict
    )
    # Loader call -> source-grounded fail-closed ownership assertion semantics.
    ownership_assertions: dict[str, ResourceOwnershipAssertionSemantics] = field(
        default_factory=dict
    )
    # Sink key -> source-derived contract qualified name, e.g. AgentService.get.
    sink_contracts: dict[str, str] = field(default_factory=dict)
    # Sink key -> returned attribute whose equality contract denotes resource scope.
    sink_contract_scope_attributes: dict[str, str] = field(default_factory=dict)
    # Sink key -> returned attribute whose equality contract denotes resource identity.
    sink_contract_identity_attributes: dict[str, str] = field(default_factory=dict)

    # Per-sink authorization/resource binding semantics.
    sink_binding_relations: dict[str, BindingRelation] = field(default_factory=dict)
    sink_binding_authorized_projections: dict[str, BindingProjection] = field(default_factory=dict)
    sink_binding_acted_projections: dict[str, BindingProjection] = field(default_factory=dict)
    sink_binding_authorized_attributes: dict[str, str] = field(default_factory=dict)
    sink_binding_acted_attributes: dict[str, str] = field(default_factory=dict)

    # Dependency name -> handler parameter holding the authorized resource key.
    dependency_guard_resources: dict[str, str] = field(default_factory=dict)
    # Dependency name -> effect names the dependency authorizes in this profile.
    dependency_guard_effects: dict[str, tuple[str, ...]] = field(default_factory=dict)

    # Direct route-decorator dependency name -> candidate static capability/resource.
    # This mapping identifies intended mediation only. It does not establish
    # that the dependency implementation is an effective authorization check.
    route_dependency_guard_resources: dict[str, str] = field(default_factory=dict)
    # Direct route-decorator dependency name -> effects it is intended to mediate.
    route_dependency_guard_effects: dict[str, tuple[str, ...]] = field(default_factory=dict)

    principal_parameter: str = "user"

    def __post_init__(self) -> None:
        static_sinks = set(self.sink_static_resources)
        conflicting_maps = {
            "sink_identity_args": set(self.sink_identity_args),
            "sink_scope_keywords": set(self.sink_scope_keywords),
            "sink_missing_scope_unconstrained": set(
                self.sink_missing_scope_unconstrained
            ),
            "sink_contracts": set(self.sink_contracts),
            "sink_contract_scope_attributes": set(
                self.sink_contract_scope_attributes
            ),
            "sink_contract_identity_attributes": set(
                self.sink_contract_identity_attributes
            ),
            "sink_binding_relations": set(self.sink_binding_relations),
            "sink_binding_authorized_projections": set(
                self.sink_binding_authorized_projections
            ),
            "sink_binding_acted_projections": set(
                self.sink_binding_acted_projections
            ),
            "sink_binding_authorized_attributes": set(
                self.sink_binding_authorized_attributes
            ),
            "sink_binding_acted_attributes": set(
                self.sink_binding_acted_attributes
            ),
        }
        for label, keys in conflicting_maps.items():
            conflict = sorted(static_sinks & keys)
            if conflict:
                raise ValueError(
                    "static sink resources cannot combine with "
                    f"{label}: " + ", ".join(conflict)
                )

        if any(
            not str(value).strip()
            for value in self.sink_static_resources.values()
        ):
            raise ValueError("static sink resources must be non-empty")

        route_resource_keys = set(self.route_dependency_guard_resources)
        route_effect_keys = set(self.route_dependency_guard_effects)
        if route_resource_keys != route_effect_keys:
            raise ValueError(
                "route dependency guard resource/effect keys must match"
            )
        modeled_effects = set(self.sink_effects.values())
        for dependency, resource in (
            self.route_dependency_guard_resources.items()
        ):
            if not dependency.strip() or not resource.strip():
                raise ValueError(
                    "route dependency guard names/resources must be non-empty"
                )
            effects = self.route_dependency_guard_effects[dependency]
            if not effects or any(not effect.strip() for effect in effects):
                raise ValueError(
                    "route dependency guard effects must be non-empty"
                )
            unknown = sorted(set(effects) - modeled_effects)
            if unknown:
                raise ValueError(
                    "route dependency guard effects absent from sink model: "
                    + ", ".join(unknown)
                )

    def sink_effect_names(
        self,
        full_name: str,
        leaf_name: str | None,
    ) -> tuple[str, str] | None:
        for key in (full_name, leaf_name):
            if key and key in self.sink_effects:
                return key, self.sink_effects[key]
        return None

    def sink_effect(self, call: ast.Call) -> tuple[str, str] | None:
        return self.sink_effect_names(
            ast.unparse(call.func),
            _name_of(call.func),
        )

    def identity_arg(self, sink_key: str) -> int:
        return int(self.sink_identity_args.get(sink_key, 0))

    def static_resource_for_sink(self, sink_key: str) -> str | None:
        return self.sink_static_resources.get(sink_key)

    def route_dependency_guard_names(
        self,
        full_name: str,
        leaf_name: str | None,
    ) -> tuple[str, str, tuple[str, ...]] | None:
        """Resolve governed route-level candidate-mediation intent.

        The returned mapping is not proof that the dependency fails closed.
        Source-derived dependency semantics must establish effectiveness before
        a Protected Effect claim can pass.
        """
        for key in (full_name, leaf_name):
            if not key:
                continue
            resource = self.route_dependency_guard_resources.get(key)
            effects = self.route_dependency_guard_effects.get(key)
            if resource is not None and effects is not None:
                return key, resource, effects
        return None

    def scope_keyword(self, sink_key: str) -> str | None:
        return self.sink_scope_keywords.get(sink_key)

    def missing_scope_is_unconstrained(self, sink_key: str) -> bool:
        return sink_key in self.sink_missing_scope_unconstrained

    def scope_assertion_names(
        self,
        full_name: str,
        leaf_name: str | None,
    ) -> tuple[str, ResourceScopeAssertionSemantics] | None:
        """Resolve explicitly configured scope-assertion semantics for a call."""
        for key in (full_name, leaf_name):
            if key and key in self.scope_assertions:
                return key, self.scope_assertions[key]
        return None

    def ownership_assertion_names(
        self,
        full_name: str,
        leaf_name: str | None,
    ) -> tuple[str, ResourceOwnershipAssertionSemantics] | None:
        for key in (full_name, leaf_name):
            if key and key in self.ownership_assertions:
                return key, self.ownership_assertions[key]
        return None

    def contract_for_sink(self, sink_key: str) -> str | None:
        return self.sink_contracts.get(sink_key)

    def contract_scope_attribute_for_sink(self, sink_key: str) -> str | None:
        return self.sink_contract_scope_attributes.get(sink_key)

    def contract_identity_attribute_for_sink(self, sink_key: str) -> str | None:
        return self.sink_contract_identity_attributes.get(sink_key)

    def binding_relation_for_sink(self, sink_key: str) -> BindingRelation:
        return self.sink_binding_relations.get(sink_key, "same_tenant")

    def binding_authorized_projection_for_sink(self, sink_key: str) -> BindingProjection:
        return self.sink_binding_authorized_projections.get(sink_key, "identity")

    def binding_acted_projection_for_sink(self, sink_key: str) -> BindingProjection:
        return self.sink_binding_acted_projections.get(sink_key, "scope")

    def binding_authorized_attribute_for_sink(self, sink_key: str) -> str | None:
        return self.sink_binding_authorized_attributes.get(sink_key)

    def binding_acted_attribute_for_sink(self, sink_key: str) -> str | None:
        return self.sink_binding_acted_attributes.get(sink_key)


def _name_of(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id=_SOURCE_PROFILE_ID,
        extractor_version="0.1.0",
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _semantic_id(prefix: str, value: str) -> str:
    return f"{prefix}:{content_digest(value)[:16]}"


def _route_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str] | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        method = decorator.func.attr.lower()
        if method not in _HTTP_METHODS or not decorator.args:
            continue
        route = _const_str(decorator.args[0])
        if route is None:
            continue
        return method.upper(), normalize_path("", route)
    return None


def _has_control_flow(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(isinstance(node, _CONTROL_FLOW) for statement in handler.body for node in ast.walk(statement))


def _body_calls(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    calls = [
        node
        for statement in handler.body
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
    ]
    return sorted(calls, key=lambda item: (getattr(item, "lineno", 0), getattr(item, "col_offset", 0)))


def _depends_name(node: ast.AST | None) -> str | None:
    if not isinstance(node, ast.Call) or _name_of(node.func) not in {"Depends", "Security"}:
        return None
    if not node.args:
        return None
    return _name_of(node.args[0])


def _dependency_parameters(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, str, ast.AST]]:
    """Return (parameter_name, dependency_name, source_node)."""

    found: list[tuple[str, str, ast.AST]] = []
    positional = list(handler.args.posonlyargs) + list(handler.args.args)
    defaults = list(handler.args.defaults)
    if defaults:
        for arg, default in zip(positional[-len(defaults):], defaults):
            dep = _depends_name(default)
            if dep:
                found.append((arg.arg, dep, default))

    for arg, default in zip(handler.args.kwonlyargs, handler.args.kw_defaults):
        dep = _depends_name(default)
        if dep:
            found.append((arg.arg, dep, default))
    return found


def _keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _symbol_term(node: ast.AST) -> ResourceIdentityTerm | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, bool)):
        rendered = str(node.value)
        if not rendered.strip():
            return None
        return ResourceIdentityTerm.literal(rendered)
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return ResourceIdentityTerm.symbol(ast.unparse(node))
    return None


def _constructor_aliases(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for statement in handler.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(statement.value, ast.Call):
            continue
        constructor = _name_of(statement.value.func)
        if constructor:
            aliases[target.id] = constructor
    return aliases


def _resolved_call_qualified_name(
    call: ast.Call,
    constructor_aliases: dict[str, str],
) -> str | None:
    if not isinstance(call.func, ast.Attribute):
        return None

    receiver = call.func.value
    if isinstance(receiver, ast.Name):
        constructor = constructor_aliases.get(receiver.id)
        if constructor:
            return f"{constructor}.{call.func.attr}"

    if isinstance(receiver, ast.Call):
        constructor = _name_of(receiver.func)
        if constructor:
            return f"{constructor}.{call.func.attr}"
    return None


def _annotation_excludes_none(annotation: ast.AST | None) -> bool:
    if annotation is None:
        return False
    rendered = ast.unparse(annotation)
    return "None" not in rendered and "Optional" not in rendered


def _provably_non_null_parameters(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    result: set[str] = set()
    positional = list(handler.args.posonlyargs) + list(handler.args.args)
    default_count = len(handler.args.defaults)
    required_positional = positional[:-default_count] if default_count else positional
    for arg in required_positional:
        if _annotation_excludes_none(arg.annotation):
            result.add(arg.arg)

    for arg, default in zip(handler.args.kwonlyargs, handler.args.kw_defaults):
        if default is None and _annotation_excludes_none(arg.annotation):
            result.add(arg.arg)
    return result


def _expr_provably_non_null(node: ast.AST, non_null_parameters: set[str]) -> bool:
    if isinstance(node, ast.Constant):
        return node.value is not None
    return isinstance(node, ast.Name) and node.id in non_null_parameters


def _actual_argument_for_parameter(
    call: ast.Call,
    *,
    parameter_name: str,
    contract_parameter_order: list[str],
) -> ast.AST | None:
    keyword = _keyword_value(call, parameter_name)
    if keyword is not None:
        return keyword
    if parameter_name not in contract_parameter_order:
        return None
    index = contract_parameter_order.index(parameter_name)
    if len(call.args) <= index:
        return None
    return call.args[index]


def _typed_contract_projection(
    *,
    contract,
    return_attribute: str,
):
    """Return the unique eq(return.<attr>, parameter) postcondition."""

    matches = []
    for predicate in contract.postconditions:
        if (
            predicate.relation == "eq"
            and predicate.right is not None
            and predicate.left.kind == "return_attribute"
            and predicate.left.name == return_attribute
            and predicate.right.kind in {"parameter", "literal"}
            and (
                (predicate.right.kind == "parameter" and predicate.right.name is not None)
                or (predicate.right.kind == "literal" and predicate.right.value is not None)
            )
        ):
            matches.append(predicate)
    if len(matches) != 1:
        return None
    return matches[0]


def _requires_non_null_parameter(contract, parameter_name: str) -> bool:
    return any(
        predicate.relation == "non_null"
        and predicate.left.kind == "parameter"
        and predicate.left.name == parameter_name
        for predicate in contract.preconditions
    )


def _instantiate_contract_attributes(
    *,
    call: ast.Call,
    contract,
    non_null_parameters: set[str],
) -> tuple[dict[str, ResourceIdentityTerm], set[str], set[str]]:
    """Instantiate proven return-attribute equalities at one call site.

    Returns:
      terms: proven return attribute -> actual argument term
      omitted: attributes whose source parameter is omitted at this call
      unresolved: attributes whose source argument/precondition cannot be proved
    """

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
            or (
                predicate.right.kind == "parameter"
                and predicate.right.name is None
            )
            or (
                predicate.right.kind == "literal"
                and predicate.right.value is None
            )
        ):
            continue

        attribute = predicate.left.name

        if predicate.right.kind == "literal":
            assert predicate.right.value is not None
            terms[attribute] = ResourceIdentityTerm.literal(predicate.right.value)
            continue

        parameter = predicate.right.name
        assert parameter is not None
        argument = _actual_argument_for_parameter(
            call,
            parameter_name=parameter,
            contract_parameter_order=contract.positional_parameters,
        )
        if argument is None:
            omitted.add(attribute)
            continue

        if (
            _requires_non_null_parameter(contract, parameter)
            and not _expr_provably_non_null(argument, non_null_parameters)
        ):
            unresolved.add(attribute)
            continue

        term = _symbol_term(argument)
        if term is None:
            unresolved.add(attribute)
            continue
        terms[attribute] = term

    return terms, omitted, unresolved


def _summary_actual_argument_for_parameter(
    call: CallSummary,
    *,
    parameter_name: str,
    contract_parameter_order: list[str],
):
    keyword = call.keyword(parameter_name)
    if keyword is not None:
        return keyword
    if parameter_name not in contract_parameter_order:
        return None
    index = contract_parameter_order.index(parameter_name)
    if len(call.positional_arguments) <= index:
        return None
    return call.positional_arguments[index]


def _instantiate_contract_attributes_from_summary(
    *,
    call: CallSummary,
    contract,
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
            or (
                predicate.right.kind == "parameter"
                and predicate.right.name is None
            )
            or (
                predicate.right.kind == "literal"
                and predicate.right.value is None
            )
        ):
            continue

        attribute = predicate.left.name
        if predicate.right.kind == "literal":
            assert predicate.right.value is not None
            terms[attribute] = ResourceIdentityTerm.literal(
                predicate.right.value
            )
            continue

        parameter = predicate.right.name
        assert parameter is not None
        argument = _summary_actual_argument_for_parameter(
            call,
            parameter_name=parameter,
            contract_parameter_order=contract.positional_parameters,
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


class FastApiDependencyEffectExtractor:
    """Compile the dependency-guard/service-effect FastAPI subset to Assurance IR."""

    source_profile_id = _SOURCE_PROFILE_ID

    def compile(
        self,
        materials: AuthMaterials,
        profile: FastApiDependencyEffectProfile,
        *,
        parsed_index: ParsedPythonMaterials | None = None,
        contract_summary_index: ContractSummaryIndex | None = None,
        route_summary_index: RouteSummaryIndex | None = None,
    ) -> AssuranceIR:
        if parsed_index is None:
            parsed = parse_head_python_materials(materials)
        else:
            if not parsed_index_matches_materials(parsed_index, materials):
                raise ValueError(
                    "parsed Python index does not match supplied head materials"
                )
            parsed = parsed_index

        include_router_dependencies = infer_include_router_dependencies(
            parsed_trees=parsed.trees,
        )

        guard_effectiveness_evidence = infer_route_dependency_effectiveness(
            parsed_trees=parsed.trees,
            dependency_names=profile.route_dependency_guard_resources,
        )
        guard_effectiveness_by_name = {
            item.dependency_name: item
            for item in guard_effectiveness_evidence
        }

        if contract_summary_index is None:
            contract_summaries = build_contract_summary_index(
                materials,
                parsed_trees=parsed.trees,
                source_digests=parsed.source_digests,
            )
        else:
            if not contract_summary_index_matches_materials(
                contract_summary_index,
                materials,
            ):
                raise ValueError(
                    "contract summary index does not match supplied head materials"
                )
            contract_summaries = contract_summary_index

        function_contracts = infer_function_contracts(
            materials,
            summary_index=contract_summaries,
        )
        resource_return_contracts = infer_resource_return_contracts(
            materials,
            function_contracts=function_contracts,
        )
        contracts_by_name = {
            contract.qualified_name: contract
            for contract in function_contracts
        }

        if route_summary_index is None:
            route_summaries = build_route_summary_index(
                materials,
                parsed_trees=parsed.trees,
                source_digests=parsed.source_digests,
            )
        else:
            if not route_summary_index_matches_materials(
                route_summary_index,
                materials,
            ):
                raise ValueError(
                    "route summary index does not match supplied head materials"
                )
            route_summaries = route_summary_index

        fragments = {
            path: bind_route_file_summary(
                summary,
                profile=profile,
                contracts_by_name=contracts_by_name,
                guard_effectiveness_by_name=guard_effectiveness_by_name,
                external_route_dependencies_by_router=(
                    include_router_dependencies.dependencies_by_target.get(
                        path,
                        {},
                    )
                ),
                route_attachment_digest=(
                    include_router_dependencies.digest_for(path)
                ),
            )
            for path, summary in sorted(route_summaries.summaries.items())
            if summary.handlers
        }
        missing_route_summaries = [
            path
            for path in sorted(materials.head_files)
            if path not in parsed.syntax_errors
            and path not in route_summaries.summaries
        ]

        return assemble_fastapi_assurance_ir(
            materials=materials,
            function_contracts=function_contracts,
            resource_return_contracts=resource_return_contracts,
            guard_effectiveness_evidence=guard_effectiveness_evidence,
            fragments=fragments,
            syntax_errors=parsed.syntax_errors,
            missing_route_summary_paths=missing_route_summaries,
        )
