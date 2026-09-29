"""Closed-world trusted bypass-authority analysis.

Bypass is modeled as an authorization mechanism, not an exemption from
Protected Effect Integrity. Client/input-controlled bypasses that skip
ordinary guards FAIL. Source-proved server-authority bypasses may authorize a
path. Unresolved writer provenance is UNKNOWN ΓÇö never PASS.

Closed-world write accounting extends across repository-local modules in the
same FastAPI compilation unit when callers provide a multi-file unit. Writers
in statically resolvable unit-local imports are accounted. Unresolvable or
dynamic imports make the closed-world condition incomplete ΓÇö authorized PASS
is refused (Unknown > false PASS). Absence of a discovered writer is never
positive proof of trust.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Literal

from ovk.compilers.authorization.value_origin import (
    AliasState,
    apply_statement_bindings,
    classify_expression_origin,
    extract_handler_value_origins,
    _collect_assign_target_names,
    _collect_assigned_names_in_statements,
    _mark_name_uses,
)
from ovk.core.assurance_ir import SemanticOrigin, ValueOriginEvidence
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


BypassAuthorityStatus = Literal[
    "violated",
    "authorized",
    "unknown",
]


@dataclass(frozen=True)
class BypassAuthorityFinding:
    """Closed-world finding for one request.state field used as a bypass."""

    field_name: str
    status: BypassAuthorityStatus
    reason: str
    read_expression: str
    write_count: int
    origin_kinds: tuple[str, ...]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class StateAttributeWrite:
    field_name: str
    value_expression: str
    origin: ValueOriginEvidence
    dynamic: bool
    source_range: SourceRange | None
    path: str = "<module>"


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="assurance.fastapi.bypass_authority.ast_v1",
        extractor_version="0.2.0",
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _is_request_state_target(node: ast.AST) -> str | None:
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "request"
        and node.value.attr == "state"
    ):
        return node.attr
    return None


def _is_request_state_setattr_call(node: ast.Call) -> bool:
    """True for ``setattr(request.state, ...)`` or ``request.state.__setattr__(...)``."""

    if (
        isinstance(node.func, ast.Name)
        and node.func.id == "setattr"
        and len(node.args) >= 3
        and isinstance(node.args[0], ast.Attribute)
        and isinstance(node.args[0].value, ast.Name)
        and node.args[0].value.id == "request"
        and node.args[0].attr == "state"
    ):
        return True
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "__setattr__"
        and isinstance(node.func.value, ast.Attribute)
        and isinstance(node.func.value.value, ast.Name)
        and node.func.value.value.id == "request"
        and node.func.value.attr == "state"
        and len(node.args) >= 2
    ):
        return True
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "__setattr__"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "object"
        and len(node.args) >= 3
        and isinstance(node.args[0], ast.Attribute)
        and isinstance(node.args[0].value, ast.Name)
        and node.args[0].value.id == "request"
        and node.args[0].attr == "state"
    ):
        return True
    return False


def _setattr_name_and_value(
    node: ast.Call,
) -> tuple[ast.AST, ast.AST]:
    """Return (name_node, value_node) for a request.state setattr-shaped call."""

    if isinstance(node.func, ast.Name) and node.func.id == "setattr":
        return node.args[1], node.args[2]
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "__setattr__"
        and isinstance(node.func.value, ast.Attribute)
    ):
        return node.args[0], node.args[1]
    # object.__setattr__(request.state, name, value)
    return node.args[1], node.args[2]


def _collect_writes_in_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    path: str,
    handler_param_names: frozenset[str],
) -> list[StateAttributeWrite]:
    """Collect state writes under statement-order alias tracking.

    Provenance for ``request.state.f = x`` survives when ``x`` is a simple
    rebinding of an HTTP param / config / literal / request.state attribute.
    Nested compound statements are visited so branch-local overwrites cannot
    disappear from closed-world accounting.
    """

    writes: list[StateAttributeWrite] = []
    alias_state = AliasState()

    def _classify(node: ast.AST) -> ValueOriginEvidence:
        return classify_expression_origin(
            node,
            path=path,
            handler_param_names=handler_param_names,
            alias_state=alias_state,
        )

    def _record_assign_target(
        target: ast.AST,
        value: ast.AST,
        statement: ast.stmt,
        *,
        dynamic: bool,
    ) -> None:
        field = _is_request_state_target(target)
        if field is None:
            return
        writes.append(
            StateAttributeWrite(
                field_name=field,
                value_expression=ast.unparse(value),
                origin=_classify(value),
                dynamic=dynamic,
                source_range=_origin(path, statement).source_range,
                path=path,
            )
        )

    def _record_dynamic_calls(statement: ast.stmt) -> None:
        for node in ast.walk(statement):
            if not isinstance(node, ast.Call):
                continue
            if _is_request_state_setattr_call(node):
                name_node, value_node = _setattr_name_and_value(node)
                if isinstance(name_node, ast.Constant) and isinstance(
                    name_node.value, str
                ):
                    field = name_node.value
                else:
                    field = "__dynamic__"
                writes.append(
                    StateAttributeWrite(
                        field_name=field,
                        value_expression=ast.unparse(value_node),
                        origin=_classify(value_node),
                        dynamic=True,
                        source_range=_origin(path, node).source_range,
                        path=path,
                    )
                )
            rendered = ast.unparse(node)
            if "request.state" in rendered and any(
                marker in rendered
                for marker in ("update(", "copy(", "__dict__", "vars(")
            ):
                writes.append(
                    StateAttributeWrite(
                        field_name="__wildcard__",
                        value_expression=rendered,
                        origin=_classify(node),
                        dynamic=True,
                        source_range=_origin(path, node).source_range,
                        path=path,
                    )
                )

    def _visit_statement(statement: ast.stmt) -> None:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                _record_assign_target(
                    target, statement.value, statement, dynamic=False
                )
            apply_statement_bindings(
                statement,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            return

        if isinstance(statement, ast.AnnAssign) and statement.value is not None:
            _record_assign_target(
                statement.target, statement.value, statement, dynamic=False
            )
            apply_statement_bindings(
                statement,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            return

        if isinstance(statement, ast.AugAssign):
            _record_assign_target(
                statement.target, statement.value, statement, dynamic=True
            )
            apply_statement_bindings(
                statement,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            return

        if isinstance(statement, (ast.If, ast.While)):
            _mark_name_uses(statement.test, alias_state)
            assigned_on_branches = _collect_assigned_names_in_statements(
                list(statement.body) + list(statement.orelse)
            )
            for child in list(statement.body) + list(statement.orelse):
                _visit_statement(child)
            for name in assigned_on_branches:
                alias_state.poison(name)
            return

        if isinstance(statement, (ast.For, ast.AsyncFor)):
            _mark_name_uses(statement.iter, alias_state)
            assigned = _collect_assigned_names_in_statements(
                list(statement.body) + list(statement.orelse)
            )
            assigned.update(_collect_assign_target_names(statement.target))
            for child in list(statement.body) + list(statement.orelse):
                _visit_statement(child)
            for name in assigned:
                alias_state.poison(name)
            return

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            assigned = _collect_assigned_names_in_statements(list(statement.body))
            for item in statement.items:
                _mark_name_uses(item.context_expr, alias_state)
                if item.optional_vars is not None:
                    assigned.update(_collect_assign_target_names(item.optional_vars))
            for child in statement.body:
                _visit_statement(child)
            for name in assigned:
                alias_state.poison(name)
            return

        if isinstance(statement, ast.Try):
            assigned = _collect_assigned_names_in_statements(
                list(statement.body)
                + list(statement.orelse)
                + list(statement.finalbody)
            )
            for handler in statement.handlers:
                assigned.update(_collect_assigned_names_in_statements(handler.body))
                if handler.name:
                    assigned.add(handler.name)
            for child in statement.body:
                _visit_statement(child)
            for handler in statement.handlers:
                for child in handler.body:
                    _visit_statement(child)
            for child in list(statement.orelse) + list(statement.finalbody):
                _visit_statement(child)
            for name in assigned:
                alias_state.poison(name)
            return

        # Ordinary statements: setattr / wildcard calls anywhere in this node.
        _record_dynamic_calls(statement)
        apply_statement_bindings(
            statement,
            path=path,
            handler_param_names=handler_param_names,
            alias_state=alias_state,
        )

    for statement in fn.body:
        _visit_statement(statement)
    return writes


def _collect_state_writes(
    tree: ast.AST,
    *,
    path: str,
    handler_param_names: frozenset[str],
) -> tuple[StateAttributeWrite, ...]:
    writes: list[StateAttributeWrite] = []
    # Prefer per-function alias tracking so rebinding inside a writer is proved.
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if functions:
        for fn in functions:
            writes.extend(
                _collect_writes_in_function(
                    fn,
                    path=path,
                    handler_param_names=handler_param_names,
                )
            )
        # Module-level writes (outside functions) still matter.
        module_level = [
            node
            for node in tree.body
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        if module_level:
            alias_state = AliasState()
            for statement in module_level:
                if isinstance(statement, ast.Assign):
                    for target in statement.targets:
                        field = _is_request_state_target(target)
                        if field is None:
                            continue
                        writes.append(
                            StateAttributeWrite(
                                field_name=field,
                                value_expression=ast.unparse(statement.value),
                                origin=classify_expression_origin(
                                    statement.value,
                                    path=path,
                                    handler_param_names=handler_param_names,
                                    alias_state=alias_state,
                                ),
                                dynamic=False,
                                source_range=_origin(path, statement).source_range,
                            path=path,
                            )
                        )
                    apply_statement_bindings(
                        statement,
                        path=path,
                        handler_param_names=handler_param_names,
                        alias_state=alias_state,
                    )
        return tuple(writes)

    # Fallback: whole-tree walk without function grouping.
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                field = _is_request_state_target(target)
                if field is None:
                    continue
                origin = classify_expression_origin(
                    node.value,
                    path=path,
                    handler_param_names=handler_param_names,
                )
                writes.append(
                    StateAttributeWrite(
                        field_name=field,
                        value_expression=ast.unparse(node.value),
                        origin=origin,
                        dynamic=False,
                        source_range=_origin(path, node).source_range,
                    path=path,
                    )
                )
    return tuple(writes)


def _collect_state_reads(tree: ast.AST) -> tuple[tuple[str, str], ...]:
    reads: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        field = _is_request_state_target(node)
        if field is not None:
            reads.append((field, ast.unparse(node)))
            continue
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
            reads.append((node.args[1].value, ast.unparse(node)))
    # unique by expression
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for field, expr in reads:
        if expr in seen:
            continue
        seen.add(expr)
        unique.append((field, expr))
    return tuple(unique)


def analyze_bypass_authority(
    source: str,
    *,
    path: str = "<module>",
    function_name: str | None = None,
    bypass_fields: frozenset[str] | None = None,
) -> tuple[BypassAuthorityFinding, ...]:
    """Analyze closed-world bypass authority for a single source unit."""

    tree = ast.parse(source)
    all_functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    unit_param_names = frozenset(
        arg.arg
        for fn in all_functions
        for arg in list(fn.args.posonlyargs) + list(fn.args.args)
        if arg.arg not in {"self", "cls"}
    )
    functions = list(all_functions)
    if function_name is not None:
        functions = [node for node in functions if node.name == function_name]
    if not functions:
        handler = None
    else:
        handler = functions[0]

    origins = (
        extract_handler_value_origins(handler, path=path)
        if handler is not None
        else ()
    )
    writes = _collect_state_writes(
        tree, path=path, handler_param_names=unit_param_names
    )
    reads = _collect_state_reads(tree)
    fields = bypass_fields or frozenset(field for field, _ in reads)
    findings: list[BypassAuthorityFinding] = []

    for field in sorted(fields):
        field_reads = [expr for name, expr in reads if name == field]
        field_writes = [item for item in writes if item.field_name == field]
        wildcard = [
            item
            for item in writes
            if item.field_name in {"__wildcard__", "__dynamic__"}
        ]
        dynamic = [item for item in field_writes if item.dynamic] + wildcard
        all_origins = tuple(
            sorted({item.origin.origin_kind for item in field_writes})
        )
        evidence_ids = tuple(
            sorted({item.origin.evidence_id for item in field_writes})
        )
        read_expression = (
            field_reads[0] if field_reads else f"request.state.{field}"
        )

        if dynamic:
            findings.append(
                BypassAuthorityFinding(
                    field_name=field,
                    status="unknown",
                    reason="dynamic_or_wildcard_state_mutation",
                    read_expression=read_expression,
                    write_count=len(field_writes) + len(wildcard),
                    origin_kinds=all_origins,
                    evidence_ids=evidence_ids,
                )
            )
            continue

        if not field_writes:
            findings.append(
                BypassAuthorityFinding(
                    field_name=field,
                    status="unknown",
                    reason="unresolved_writer_provenance",
                    read_expression=read_expression,
                    write_count=0,
                    origin_kinds=(),
                    evidence_ids=(),
                )
            )
            continue

        kinds = {item.origin.origin_kind for item in field_writes}
        if "externally_bound_http_value" in kinds:
            findings.append(
                BypassAuthorityFinding(
                    field_name=field,
                    status="violated",
                    reason="client_controlled_bypass_write",
                    read_expression=read_expression,
                    write_count=len(field_writes),
                    origin_kinds=all_origins,
                    evidence_ids=evidence_ids,
                )
            )
            continue

        if "unknown_origin" in kinds:
            findings.append(
                BypassAuthorityFinding(
                    field_name=field,
                    status="unknown",
                    reason="unresolved_write_origin",
                    read_expression=read_expression,
                    write_count=len(field_writes),
                    origin_kinds=all_origins,
                    evidence_ids=evidence_ids,
                )
            )
            continue

        if kinds <= {"server_configuration", "literal_constant"}:
            findings.append(
                BypassAuthorityFinding(
                    field_name=field,
                    status="authorized",
                    reason="source_proved_server_authority_write",
                    read_expression=read_expression,
                    write_count=len(field_writes),
                    origin_kinds=all_origins,
                    evidence_ids=evidence_ids,
                )
            )
            continue

        findings.append(
            BypassAuthorityFinding(
                field_name=field,
                status="unknown",
                reason="unsupported_write_origin_mix",
                read_expression=read_expression,
                write_count=len(field_writes),
                origin_kinds=all_origins,
                evidence_ids=evidence_ids,
            )
        )

    _ = origins
    return tuple(findings)



def bypass_authority_digest(findings: tuple[BypassAuthorityFinding, ...]) -> str:
    return content_digest(
        [
            {
                "field_name": item.field_name,
                "status": item.status,
                "reason": item.reason,
                "read_expression": item.read_expression,
                "write_count": item.write_count,
                "origin_kinds": list(item.origin_kinds),
                "evidence_ids": list(item.evidence_ids),
            }
            for item in findings
        ]
    )

