"""Closed-world trusted bypass-authority analysis.

Bypass is modeled as an authorization mechanism, not an exemption from
Protected Effect Integrity. Client/input-controlled bypasses that skip
ordinary guards FAIL. Source-proved server-authority bypasses may authorize a
path. Unresolved writer provenance is UNKNOWN — never PASS.

Closed-world write accounting extends across repository-local modules in the
same FastAPI compilation unit when callers provide a multi-file unit. Writers
in statically resolvable unit-local imports are accounted. Unresolvable or
dynamic imports make the closed-world condition incomplete — authorized PASS
is refused (Unknown > false PASS). Absence of a discovered writer is never
positive proof of trust.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Literal, Mapping

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
class ClosedWorldCondition:
    """Explicit closed-world accounting status for one analysis unit."""

    complete: bool
    accounted_paths: tuple[str, ...]
    unresolvable_imports: tuple[str, ...]
    reason: str


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
    closed_world: ClosedWorldCondition | None = None


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
        extractor_version="0.3.0",
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


def _normalize_unit_path(path: str) -> str:
    return path.replace("\\", "/")


def _module_path_in_unit(
    module: str,
    *,
    available_paths: set[str],
) -> str | None:
    """Resolve an absolute module name to a unique path in the unit, else None."""

    stem = module.replace(".", "/")
    suffixes = (f"{stem}.py", f"{stem}/__init__.py")
    candidates = sorted(
        path
        for path in available_paths
        if any(
            path == suffix or path.endswith("/" + suffix)
            for suffix in suffixes
        )
    )
    return candidates[0] if len(candidates) == 1 else None


def _unit_package_roots(available_paths: set[str]) -> frozenset[str]:
    """Top-level package/module names present in the compilation unit."""

    roots: set[str] = set()
    for path in available_paths:
        parts = path.split("/")
        if not parts:
            continue
        if parts[0].endswith(".py"):
            roots.add(parts[0][:-3])
        else:
            roots.add(parts[0])
    return frozenset(roots)


def _import_module_name(
    node: ast.ImportFrom,
    *,
    importer_path: str,
) -> str | None:
    """Resolve ImportFrom to an absolute module name within the unit, if possible."""

    if node.level and node.level > 0:
        # Relative import: resolve against importer package.
        importer = _normalize_unit_path(importer_path)
        if importer.endswith(".py"):
            importer = importer[: -len(".py")]
        parts = importer.split("/")
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        # Go up ``level`` packages from the containing package.
        package_parts = parts[:-1] if parts else []
        if node.level - 1 > len(package_parts):
            return None
        if node.level > 1:
            package_parts = package_parts[: -(node.level - 1)]
        if node.module:
            package_parts = list(package_parts) + node.module.split(".")
        return ".".join(package_parts) if package_parts else None
    return node.module


def _evaluate_closed_world(
    files: Mapping[str, str],
) -> ClosedWorldCondition:
    """Establish whether the unit's import graph is closed and resolvable.

    Repository-local imports whose top-level package is present in the unit
    must resolve to a unit path. Unresolvable local imports, star imports, and
    dynamic import forms make the closed-world condition incomplete — never an
    authorized PASS. Third-party / stdlib imports (top-level not in the unit)
    are outside this closed world and do not, by themselves, complete or break
    it; absence of writers outside the unit is still not positive proof.
    """

    available = {_normalize_unit_path(path) for path in files}
    roots = _unit_package_roots(available)
    unresolvable: list[str] = []
    accounted = tuple(sorted(available))

    for path, source in sorted(files.items()):
        norm = _normalize_unit_path(path)
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            unresolvable.append(f"{norm}:syntax_error")
            continue
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                if any(alias.name == "*" for alias in node.names):
                    unresolvable.append(f"{norm}:star_import")
                    continue
                module_name = _import_module_name(node, importer_path=norm)
                if module_name is None:
                    unresolvable.append(f"{norm}:unresolved_relative_import")
                    continue
                top = module_name.split(".", 1)[0]
                if top not in roots:
                    # External to the compilation unit — out of closed-world
                    # writer accounting (explicitly not positive proof).
                    continue
                resolved = _module_path_in_unit(
                    module_name, available_paths=available
                )
                if resolved is None:
                    unresolvable.append(
                        f"{norm}:unresolvable_local_import:{module_name}"
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".", 1)[0]
                    if top not in roots:
                        continue
                    resolved = _module_path_in_unit(
                        alias.name, available_paths=available
                    )
                    if resolved is None:
                        unresolvable.append(
                            f"{norm}:unresolvable_local_import:{alias.name}"
                        )

        # Dynamic imports anywhere in the module (including nested function
        # bodies) make the closed world incomplete — Unknown > false PASS.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in {
                "__import__",
                "import_module",
            }:
                unresolvable.append(f"{norm}:dynamic_import")
                break
            if isinstance(func, ast.Attribute) and func.attr == "import_module":
                unresolvable.append(f"{norm}:dynamic_import")
                break

    complete = not unresolvable
    reason = (
        "closed_world_complete_over_unit"
        if complete
        else "closed_world_incomplete_unresolvable_imports"
    )
    return ClosedWorldCondition(
        complete=complete,
        accounted_paths=accounted,
        unresolvable_imports=tuple(sorted(set(unresolvable))),
        reason=reason,
    )


def _findings_for_writes_and_reads(
    *,
    writes: tuple[StateAttributeWrite, ...],
    reads: tuple[tuple[str, str], ...],
    bypass_fields: frozenset[str] | None,
    closed_world: ClosedWorldCondition,
) -> tuple[BypassAuthorityFinding, ...]:
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

        def _emit(
            status: BypassAuthorityStatus,
            reason: str,
            *,
            write_count: int,
            origin_kinds: tuple[str, ...] = (),
            ids: tuple[str, ...] = (),
        ) -> None:
            findings.append(
                BypassAuthorityFinding(
                    field_name=field,
                    status=status,
                    reason=reason,
                    read_expression=read_expression,
                    write_count=write_count,
                    origin_kinds=origin_kinds,
                    evidence_ids=ids,
                    closed_world=closed_world,
                )
            )

        if dynamic:
            _emit(
                "unknown",
                "dynamic_or_wildcard_state_mutation",
                write_count=len(field_writes) + len(wildcard),
                origin_kinds=all_origins,
                ids=evidence_ids,
            )
            continue

        if not field_writes:
            # Absence of discovered writers is not positive proof.
            _emit(
                "unknown",
                "unresolved_writer_provenance",
                write_count=0,
            )
            continue

        kinds = {item.origin.origin_kind for item in field_writes}
        if "externally_bound_http_value" in kinds:
            # Definite client control — still violated even if closed-world
            # is incomplete (Unknown > false PASS, but FAIL is sound).
            _emit(
                "violated",
                "client_controlled_bypass_write",
                write_count=len(field_writes),
                origin_kinds=all_origins,
                ids=evidence_ids,
            )
            continue

        if "unknown_origin" in kinds:
            _emit(
                "unknown",
                "unresolved_write_origin",
                write_count=len(field_writes),
                origin_kinds=all_origins,
                ids=evidence_ids,
            )
            continue

        if kinds <= {"server_configuration", "literal_constant"}:
            if not closed_world.complete:
                # Cannot authorize when local import graph is incomplete —
                # missing modules may contain client writers.
                _emit(
                    "unknown",
                    "closed_world_incomplete",
                    write_count=len(field_writes),
                    origin_kinds=all_origins,
                    ids=evidence_ids,
                )
                continue
            _emit(
                "authorized",
                "source_proved_server_authority_write",
                write_count=len(field_writes),
                origin_kinds=all_origins,
                ids=evidence_ids,
            )
            continue

        _emit(
            "unknown",
            "unsupported_write_origin_mix",
            write_count=len(field_writes),
            origin_kinds=all_origins,
            ids=evidence_ids,
        )

    return tuple(findings)


def analyze_bypass_authority_unit(
    files: Mapping[str, str],
    *,
    entry_path: str,
    function_name: str | None = None,
    bypass_fields: frozenset[str] | None = None,
) -> tuple[BypassAuthorityFinding, ...]:
    """Closed-world bypass analysis over a multi-file compilation unit.

    Writers in every unit file are accounted. The closed-world condition is
    complete only when repository-local imports resolve inside the unit.
    ``entry_path`` selects where bypass reads are observed.
    """

    if not files:
        raise ValueError("compilation unit must contain at least one file")
    normalized = {
        _normalize_unit_path(path): source for path, source in files.items()
    }
    entry = _normalize_unit_path(entry_path)
    if entry not in normalized:
        raise ValueError(f"entry_path {entry_path!r} not in compilation unit")

    closed_world = _evaluate_closed_world(normalized)

    unit_param_names: set[str] = set()
    for path, source in sorted(normalized.items()):
        tree = ast.parse(source, filename=path)
        for fn in tree.body:
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for arg in list(fn.args.posonlyargs) + list(fn.args.args):
                if arg.arg not in {"self", "cls"}:
                    unit_param_names.add(arg.arg)

    param_names = frozenset(unit_param_names)
    all_writes: list[StateAttributeWrite] = []
    for path, source in sorted(normalized.items()):
        tree = ast.parse(source, filename=path)
        all_writes.extend(
            _collect_state_writes(
                tree,
                path=path,
                handler_param_names=param_names,
            )
        )

    entry_tree = ast.parse(normalized[entry], filename=entry)
    entry_functions = [
        node
        for node in entry_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if function_name is not None:
        entry_functions = [
            node for node in entry_functions if node.name == function_name
        ]
    handler = entry_functions[0] if entry_functions else None
    reads = _collect_state_reads(handler if handler is not None else entry_tree)
    # Keep extract call for audit packaging symmetry with single-file path.
    if handler is not None:
        extract_handler_value_origins(handler, path=entry)

    return _findings_for_writes_and_reads(
        writes=tuple(all_writes),
        reads=reads,
        bypass_fields=bypass_fields,
        closed_world=closed_world,
    )


def analyze_bypass_authority(
    source: str,
    *,
    path: str = "<module>",
    function_name: str | None = None,
    bypass_fields: frozenset[str] | None = None,
) -> tuple[BypassAuthorityFinding, ...]:
    """Analyze closed-world bypass authority for a single source unit.

    Prefer :func:`analyze_bypass_authority_unit` when the FastAPI compilation
    unit spans multiple repository-local modules.
    """

    return analyze_bypass_authority_unit(
        {path: source},
        entry_path=path,
        function_name=function_name,
        bypass_fields=bypass_fields,
    )


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
                "closed_world": (
                    {
                        "complete": item.closed_world.complete,
                        "accounted_paths": list(item.closed_world.accounted_paths),
                        "unresolvable_imports": list(
                            item.closed_world.unresolvable_imports
                        ),
                        "reason": item.closed_world.reason,
                    }
                    if item.closed_world is not None
                    else None
                ),
            }
            for item in findings
        ]
    )
