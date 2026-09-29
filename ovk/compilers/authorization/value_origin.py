"""Explicit value-origin provenance for FastAPI handler values.

This module records where a value came from. It does not classify values as
trusted or untrusted and does not authorize bypasses.

Simple Name rebinding is tracked in statement order (bounded SSA): provenance
survives ``x = request.state.f`` / ``x = http_param`` then uses of ``x``. Forms
that defeat resolution (tuple unpacking, multi-target assigns, attribute
aliases, reassignment after use) yield ``unknown_origin``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from ovk.core.assurance_ir import SemanticOrigin, ValueOriginEvidence
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


_HTTP_PARAM_FORBIDDEN_ALIASES = frozenset(
    {
        "Annotated",
        "alias",
        "validation_alias",
        "serialization_alias",
    }
)

# Sentinel: name is poisoned / unresolvable under the bounded alias calculus.
_POISONED = object()


@dataclass
class AliasState:
    """Bounded statement-order alias environment for simple Name bindings."""

    bindings: dict[str, ValueOriginEvidence | object] = field(default_factory=dict)
    used: set[str] = field(default_factory=set)

    def lookup(self, name: str) -> ValueOriginEvidence | object | None:
        return self.bindings.get(name)

    def mark_used(self, name: str) -> None:
        if name in self.bindings:
            self.used.add(name)

    def poison(self, name: str) -> None:
        self.bindings[name] = _POISONED

    def bind(self, name: str, evidence: ValueOriginEvidence) -> None:
        if name in self.used:
            # Reassignment after observed use: refuse further resolution.
            self.poison(name)
            return
        self.bindings[name] = evidence


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="assurance.fastapi.value_origin.ast_v1",
        extractor_version="0.4.0",
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _evidence_id(kind: str, expression: str) -> str:
    return "vorigin:" + content_digest({"kind": kind, "expression": expression})[:16]


def _is_request_state_attribute(node: ast.AST) -> tuple[bool, str | None]:
    """Detect request.state.<attr> or getattr(request.state, \"attr\", ...)."""

    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "request"
        and node.value.attr == "state"
    ):
        return True, node.attr

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Attribute)
        and isinstance(node.args[0].value, ast.Name)
        and node.args[0].value.id == "request"
        and node.args[0].attr == "state"
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    ):
        return True, node.args[1].value

    return False, None


def _looks_like_config_name(name: str) -> bool:
    """True for bounded config-binding names — never bare ALL_CAPS alone.

    Supported forms:
    - explicit module/object names ``settings`` / ``config`` / ``SETTINGS`` /
      ``CONFIG`` (Attribute bases such as ``settings.X``);
    - conventional config suffixes/prefixes ``*_CONFIG``, ``*_SETTINGS``,
      ``CONFIG_*``.

    Bare identifiers such as ``BYPASS_FILTER``, ``ALLOW_ALL``, or ``DEBUG``
    are not proved ``server_configuration`` merely because they are ALL_CAPS.
    Prefer ``unknown_origin`` over a false authorizing PASS.
    """

    return (
        name.endswith("_CONFIG")
        or name.endswith("_SETTINGS")
        or name.startswith("CONFIG_")
        or name in {"settings", "config", "SETTINGS", "CONFIG"}
    )


def _unknown(
    *,
    path: str,
    node: ast.AST,
    expression: str,
    value_id: str | None = None,
    dependencies: list[str] | None = None,
) -> ValueOriginEvidence:
    return ValueOriginEvidence(
        evidence_id=_evidence_id("unknown_origin", expression),
        value_id=value_id or f"value:unknown:{expression}",
        origin_kind="unknown_origin",
        source_expression=expression,
        dependencies=list(dependencies or []),
        origin=_origin(path, node),
    )


def classify_expression_origin(
    node: ast.AST,
    *,
    path: str,
    handler_param_names: frozenset[str],
    alias_state: AliasState | None = None,
) -> ValueOriginEvidence:
    """Classify one expression's origin without inventing trust.

    When ``alias_state`` is provided, simple Name aliases resolve through the
    bounded SSA environment. Ambiguous / poisoned names are ``unknown_origin``.
    """

    rendered = ast.unparse(node)
    is_state, attr = _is_request_state_attribute(node)
    if is_state:
        return ValueOriginEvidence(
            evidence_id=_evidence_id("request_state_attribute", rendered),
            value_id=f"value:{attr or rendered}",
            origin_kind="request_state_attribute",
            source_expression=rendered,
            dependencies=[],
            origin=_origin(path, node),
        )

    if isinstance(node, ast.Constant):
        return ValueOriginEvidence(
            evidence_id=_evidence_id("literal_constant", rendered),
            value_id=f"value:literal:{rendered}",
            origin_kind="literal_constant",
            source_expression=rendered,
            dependencies=[],
            origin=_origin(path, node),
        )

    if isinstance(node, ast.Name):
        if alias_state is not None:
            bound = alias_state.lookup(node.id)
            if bound is _POISONED:
                alias_state.mark_used(node.id)
                return _unknown(
                    path=path,
                    node=node,
                    expression=rendered,
                    value_id=f"value:alias:{node.id}",
                )
            if isinstance(bound, ValueOriginEvidence):
                alias_state.mark_used(node.id)
                # Preserve origin kind through the alias; record dependency.
                return ValueOriginEvidence(
                    evidence_id=_evidence_id(bound.origin_kind, rendered),
                    value_id=f"value:alias:{node.id}",
                    origin_kind=bound.origin_kind,
                    source_expression=rendered,
                    dependencies=[bound.evidence_id],
                    origin=_origin(path, node),
                )

        if node.id in handler_param_names:
            return ValueOriginEvidence(
                evidence_id=_evidence_id("externally_bound_http_value", rendered),
                value_id=f"value:param:{node.id}",
                origin_kind="externally_bound_http_value",
                source_expression=rendered,
                dependencies=[],
                origin=_origin(path, node),
            )
        if _looks_like_config_name(node.id):
            return ValueOriginEvidence(
                evidence_id=_evidence_id("server_configuration", rendered),
                value_id=f"value:config:{node.id}",
                origin_kind="server_configuration",
                source_expression=rendered,
                dependencies=[],
                origin=_origin(path, node),
            )
        return ValueOriginEvidence(
            evidence_id=_evidence_id("unknown_origin", rendered),
            value_id=f"value:unknown:{node.id}",
            origin_kind="unknown_origin",
            source_expression=rendered,
            dependencies=[],
            origin=_origin(path, node),
        )

    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        # Attribute through a Name that is not the literal ``request.state``
        # chain: refuse when the base is an alias (defeats resolution).
        if alias_state is not None and alias_state.lookup(node.value.id) is not None:
            alias_state.mark_used(node.value.id)
            return _unknown(
                path=path,
                node=node,
                expression=rendered,
                value_id=f"value:attr_alias:{rendered}",
            )
        if _looks_like_config_name(node.value.id):
            return ValueOriginEvidence(
                evidence_id=_evidence_id("server_configuration", rendered),
                value_id=f"value:config:{rendered}",
                origin_kind="server_configuration",
                source_expression=rendered,
                dependencies=[],
                origin=_origin(path, node),
            )

    # Derived / compound forms are recorded without inventing a stronger origin.
    return ValueOriginEvidence(
        evidence_id=_evidence_id("derived_value", rendered),
        value_id=f"value:derived:{content_digest(rendered)[:12]}",
        origin_kind="derived_value",
        source_expression=rendered,
        dependencies=[],
        origin=_origin(path, node),
    )


def _assign_targets_are_simple_name(targets: list[ast.expr]) -> ast.Name | None:
    """Return the single Name target iff assignment is a simple Name bind."""

    if len(targets) != 1:
        return None
    target = targets[0]
    if isinstance(target, ast.Name):
        return target
    return None


def _collect_assign_target_names(target: ast.expr) -> list[str]:
    names: list[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_collect_assign_target_names(elt))
    elif isinstance(target, ast.Starred):
        names.extend(_collect_assign_target_names(target.value))
    return names


def _collect_assigned_names_in_statements(statements: list[ast.stmt]) -> set[str]:
    """Collect Name targets assigned anywhere under ``statements`` (deep)."""

    assigned: set[str] = set()

    def _visit(statement: ast.stmt) -> None:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                assigned.update(_collect_assign_target_names(target))
        elif isinstance(statement, ast.AnnAssign):
            assigned.update(_collect_assign_target_names(statement.target))
        elif isinstance(statement, ast.AugAssign):
            assigned.update(_collect_assign_target_names(statement.target))
        elif isinstance(statement, ast.NamedExpr) and isinstance(
            statement.target, ast.Name
        ):
            assigned.add(statement.target.id)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            assigned.update(_collect_assign_target_names(statement.target))
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                if item.optional_vars is not None:
                    assigned.update(_collect_assign_target_names(item.optional_vars))
        elif isinstance(statement, ast.Try):
            for handler in statement.handlers:
                if handler.name:
                    assigned.add(handler.name)
                for child in handler.body:
                    _visit(child)
        for attr in ("body", "orelse", "finalbody"):
            block = getattr(statement, attr, None)
            if isinstance(block, list):
                for child in block:
                    if isinstance(child, ast.stmt):
                        _visit(child)

    for statement in statements:
        _visit(statement)
    return assigned


def _apply_assignment(
    statement: ast.Assign,
    *,
    path: str,
    handler_param_names: frozenset[str],
    alias_state: AliasState,
) -> None:
    simple = _assign_targets_are_simple_name(statement.targets)
    if simple is None:
        # Multi-target / tuple unpack / attribute targets defeat resolution.
        for target in statement.targets:
            for name in _collect_assign_target_names(target):
                alias_state.poison(name)
            # Attribute / subscript targets also defeat any Name base aliasing.
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                alias_state.poison(target.value.id)
            if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                alias_state.poison(target.value.id)
        return

    # RHS classification uses the *current* environment (before this bind).
    rhs = classify_expression_origin(
        statement.value,
        path=path,
        handler_param_names=handler_param_names,
        alias_state=alias_state,
    )
    if rhs.origin_kind == "unknown_origin" and not rhs.dependencies:
        # Unresolved RHS still records a binding so later uses stay unknown
        # rather than falling back to inventing a stronger origin.
        alias_state.bind(simple.id, rhs)
        return
    alias_state.bind(simple.id, rhs)


def _mark_name_uses(node: ast.AST, alias_state: AliasState) -> None:
    """Mark Names observed in a non-binding position as used."""

    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Load, ast.Del)):
            alias_state.mark_used(child.id)
        elif isinstance(child, ast.Name) and not hasattr(child, "ctx"):
            # Parsed fragments / synthetic Names may lack ctx.
            alias_state.mark_used(child.id)


def apply_statement_bindings(
    statement: ast.stmt,
    *,
    path: str,
    handler_param_names: frozenset[str],
    alias_state: AliasState,
) -> None:
    if isinstance(statement, ast.Assign):
        _mark_name_uses(statement.value, alias_state)
        _apply_assignment(
            statement,
            path=path,
            handler_param_names=handler_param_names,
            alias_state=alias_state,
        )
        return
    if isinstance(statement, ast.AnnAssign) and statement.value is not None:
        _mark_name_uses(statement.value, alias_state)
        if isinstance(statement.target, ast.Name):
            rhs = classify_expression_origin(
                statement.value,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            alias_state.bind(statement.target.id, rhs)
        else:
            for name in _collect_assign_target_names(statement.target):
                alias_state.poison(name)
        return
    if isinstance(statement, (ast.AugAssign, ast.NamedExpr)):
        # In-place / walrus forms are outside the bounded simple-rebinding
        # calculus — poison the written name when statically known.
        if isinstance(statement, ast.AugAssign):
            _mark_name_uses(statement.value, alias_state)
            target = statement.target
        else:
            _mark_name_uses(statement.value, alias_state)
            target = statement.target
        if isinstance(target, ast.Name):
            alias_state.poison(target.id)
        return
    if isinstance(statement, (ast.For, ast.AsyncFor)):
        _mark_name_uses(statement.iter, alias_state)
        for name in _collect_assign_target_names(statement.target):
            alias_state.poison(name)
        for child in list(statement.body) + list(statement.orelse):
            apply_statement_bindings(
                child,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
        return
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        for item in statement.items:
            _mark_name_uses(item.context_expr, alias_state)
            if item.optional_vars is not None:
                for name in _collect_assign_target_names(item.optional_vars):
                    alias_state.poison(name)
        for child in statement.body:
            apply_statement_bindings(
                child,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
        return
    if isinstance(statement, (ast.If, ast.While)):
        # Path-insensitive join: names assigned on any branch are poisoned so
        # a branch-local trusted rebind cannot overwrite a client alias and
        # authorize a write that remains reachable on the other path.
        _mark_name_uses(statement.test, alias_state)
        assigned_on_branches = _collect_assigned_names_in_statements(
            list(statement.body) + list(statement.orelse)
        )
        for child in list(statement.body) + list(statement.orelse):
            apply_statement_bindings(
                child,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
        for name in assigned_on_branches:
            alias_state.poison(name)
        return
    if isinstance(statement, ast.Try):
        for child in statement.body:
            apply_statement_bindings(
                child,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
        for handler in statement.handlers:
            if handler.name:
                alias_state.poison(handler.name)
            for child in handler.body:
                apply_statement_bindings(
                    child,
                    path=path,
                    handler_param_names=handler_param_names,
                    alias_state=alias_state,
                )
        for child in statement.orelse:
            apply_statement_bindings(
                child,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
        for child in statement.finalbody:
            apply_statement_bindings(
                child,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
        return
    if isinstance(statement, (ast.Return, ast.Expr, ast.Raise, ast.Assert)):
        value = getattr(statement, "value", None) or getattr(statement, "exc", None) or getattr(
            statement, "test", None
        )
        if isinstance(statement, ast.Assert):
            _mark_name_uses(statement.test, alias_state)
            if statement.msg is not None:
                _mark_name_uses(statement.msg, alias_state)
        elif value is not None:
            _mark_name_uses(value, alias_state)
        return
    # Conservative: any other statement form that mentions Names marks them used.
    _mark_name_uses(statement, alias_state)


def build_alias_state(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    path: str,
    handler_param_names: frozenset[str],
) -> AliasState:
    """Walk handler body in order and build the bounded alias environment."""

    state = AliasState()
    for statement in handler.body:
        apply_statement_bindings(
            statement,
            path=path,
            handler_param_names=handler_param_names,
            alias_state=state,
        )
    return state


def classify_expression_origin_with_aliases(
    node: ast.AST,
    *,
    path: str,
    handler_param_names: frozenset[str],
    handler: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
    alias_state: AliasState | None = None,
) -> ValueOriginEvidence:
    """Classify with optional prebuilt or freshly built alias state."""

    state = alias_state
    if state is None and handler is not None:
        state = build_alias_state(
            handler,
            path=path,
            handler_param_names=handler_param_names,
        )
    return classify_expression_origin(
        node,
        path=path,
        handler_param_names=handler_param_names,
        alias_state=state,
    )


_FASTAPI_PARAM_CALLEES = frozenset(
    {"Query", "Path", "Header", "Cookie", "Body", "Form"}
)


def _call_func_name(func: ast.AST) -> str | None:
    """Return the bare callee name for ``Name`` or ``Attribute`` call funcs."""

    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _fastapi_param_call_is_unsupported(call: ast.Call) -> bool:
    """Refuse non-ordinary FastAPI parameter binding call forms.

    Bare ``Query(...)`` / ``Path(...)`` without alias keywords remain ordinary
    HTTP bindings. Attribute callees (``fastapi.Query``) and any alias /
    validation_alias keyword refuse — Unknown > false PASS.
    """

    callee = _call_func_name(call.func)
    if callee not in _FASTAPI_PARAM_CALLEES:
        return False
    if isinstance(call.func, ast.Attribute):
        return True
    for keyword in call.keywords:
        if keyword.arg in {"alias", "validation_alias", "serialization_alias"}:
            return True
    return False


def _parameter_has_unsupported_binding(arg: ast.arg, default: ast.AST | None) -> bool:
    """Refuse alias / Annotated / dynamic FastAPI binding forms.

    ``typing.Annotated`` Attribute forms are refused the same way as bare
    ``Annotated`` names.
    """

    def _node_is_unsupported(child: ast.AST) -> bool:
        if isinstance(child, ast.Name) and child.id in _HTTP_PARAM_FORBIDDEN_ALIASES:
            return True
        if isinstance(child, ast.Attribute) and child.attr == "Annotated":
            return True
        if isinstance(child, ast.Attribute) and child.attr in {
            "alias",
            "validation_alias",
            "serialization_alias",
        }:
            return True
        if isinstance(child, ast.Call) and _fastapi_param_call_is_unsupported(child):
            return True
        return False

    annotation = arg.annotation
    if annotation is not None:
        for child in ast.walk(annotation):
            if _node_is_unsupported(child):
                return True
    if default is not None:
        for child in ast.walk(default):
            if _node_is_unsupported(child):
                return True
            if isinstance(child, ast.Name) and child.id == "Annotated":
                return True
    return False


def extract_handler_value_origins(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    path: str = "<handler>",
) -> tuple[ValueOriginEvidence, ...]:
    """Extract value-origin evidence for ordinary FastAPI handler parameters.

    Supported ordinary parameters (no alias/Annotated/dynamic binding) are
    classified as externally_bound_http_value. Unsupported binding forms yield
    unknown_origin. Function-name inference never invents origin.

    Simple Name aliases of HTTP params / request.state attributes are also
    surfaced so provenance survives rebinding. Forms that defeat resolution
    remain ``unknown_origin``.
    """

    found: list[ValueOriginEvidence] = []
    positional = list(handler.args.posonlyargs) + list(handler.args.args)
    defaults = list(handler.args.defaults)
    default_offset = len(positional) - len(defaults)

    # Skip typical self/cls if present on methods (route handlers rarely have them).
    start = 0
    if positional and positional[0].arg in {"self", "cls"}:
        start = 1

    param_names: list[str] = []
    for index, arg in enumerate(positional[start:], start=start):
        default = None
        if index >= default_offset:
            default = defaults[index - default_offset]
        # Depends/Security parameters are dependency results, not HTTP values.
        if (
            default is not None
            and isinstance(default, ast.Call)
            and isinstance(default.func, ast.Name)
            and default.func.id in {"Depends", "Security"}
        ):
            continue

        param_names.append(arg.arg)
        if _parameter_has_unsupported_binding(arg, default):
            found.append(
                ValueOriginEvidence(
                    evidence_id=_evidence_id("unknown_origin", arg.arg),
                    value_id=f"value:param:{arg.arg}",
                    origin_kind="unknown_origin",
                    source_expression=arg.arg,
                    dependencies=[],
                    origin=_origin(path, arg),
                )
            )
            continue

        found.append(
            ValueOriginEvidence(
                evidence_id=_evidence_id("externally_bound_http_value", arg.arg),
                value_id=f"value:param:{arg.arg}",
                origin_kind="externally_bound_http_value",
                source_expression=arg.arg,
                dependencies=[],
                origin=_origin(path, arg),
            )
        )

    handler_param_names = frozenset(param_names)
    # Statement-order alias walk: emit evidence for proved Name aliases and
    # for request.state reads (direct or via alias).
    alias_state = AliasState()
    for statement in handler.body:
        # Capture request.state reads and Name uses *before* applying the
        # statement's own binding effects when the statement is an assign of
        # those expressions.
        if isinstance(statement, ast.Assign):
            simple = _assign_targets_are_simple_name(statement.targets)
            if simple is not None:
                rhs_evidence = classify_expression_origin(
                    statement.value,
                    path=path,
                    handler_param_names=handler_param_names,
                    alias_state=alias_state,
                )
                if rhs_evidence.origin_kind in {
                    "request_state_attribute",
                    "externally_bound_http_value",
                    "literal_constant",
                    "server_configuration",
                }:
                    # Alias evidence: the bound name carries the same kind.
                    alias_evidence = ValueOriginEvidence(
                        evidence_id=_evidence_id(
                            rhs_evidence.origin_kind, simple.id
                        ),
                        value_id=f"value:alias:{simple.id}",
                        origin_kind=rhs_evidence.origin_kind,
                        source_expression=simple.id,
                        dependencies=[rhs_evidence.evidence_id],
                        origin=_origin(path, statement),
                    )
                    found.append(alias_evidence)
            _apply_assignment(
                statement,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            continue

        # Non-assign statements: surface request.state reads and alias Name uses.
        for node in ast.walk(statement):
            is_state, _attr = _is_request_state_attribute(node)
            if is_state:
                found.append(
                    classify_expression_origin(
                        node,
                        path=path,
                        handler_param_names=handler_param_names,
                        alias_state=alias_state,
                    )
                )
            elif isinstance(node, ast.Name):
                bound = alias_state.lookup(node.id)
                if isinstance(bound, ValueOriginEvidence) and bound.origin_kind in {
                    "request_state_attribute",
                    "externally_bound_http_value",
                }:
                    found.append(
                        classify_expression_origin(
                            node,
                            path=path,
                            handler_param_names=handler_param_names,
                            alias_state=alias_state,
                        )
                    )

        apply_statement_bindings(
            statement,
            path=path,
            handler_param_names=handler_param_names,
            alias_state=alias_state,
        )

    # Deduplicate by evidence_id while preserving order.
    seen: set[str] = set()
    unique: list[ValueOriginEvidence] = []
    for item in found:
        if item.evidence_id in seen:
            continue
        seen.add(item.evidence_id)
        unique.append(item)
    return tuple(unique)


def extract_value_origins_from_source(
    source: str,
    *,
    path: str = "<handler>",
    function_name: str | None = None,
) -> tuple[ValueOriginEvidence, ...]:
    tree = ast.parse(source)
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if function_name is not None:
        functions = [node for node in functions if node.name == function_name]
    if not functions:
        raise ValueError("no function found for value-origin extraction")
    return extract_handler_value_origins(functions[0], path=path)


def classify_name_after_handler_bindings(
    source: str,
    *,
    name: str,
    path: str = "<handler>",
    function_name: str | None = None,
) -> ValueOriginEvidence:
    """Classify a Name after applying the handler's bounded alias calculus.

    Used by tests and closed-world writers to ask: after the handler body
    bindings, what origin does ``name`` carry?
    """

    tree = ast.parse(source)
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if function_name is not None:
        functions = [node for node in functions if node.name == function_name]
    if not functions:
        raise ValueError("no function found for value-origin extraction")
    handler = functions[0]
    positional = list(handler.args.posonlyargs) + list(handler.args.args)
    start = 1 if positional and positional[0].arg in {"self", "cls"} else 0
    param_names = frozenset(
        arg.arg for arg in positional[start:] if arg.arg not in {"self", "cls"}
    )
    state = build_alias_state(
        handler,
        path=path,
        handler_param_names=param_names,
    )
    return classify_expression_origin(
        ast.Name(id=name, ctx=ast.Load()),
        path=path,
        handler_param_names=param_names,
        alias_state=state,
    )
