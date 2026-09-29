"""Closed-world trusted bypass-authority analysis.

Bypass is modeled as an authorization mechanism, not an exemption from
Protected Effect Integrity. Client/input-controlled bypasses that skip
ordinary guards FAIL. Source-proved server-authority bypasses may authorize a
path. Unresolved writer provenance is UNKNOWN — never PASS.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Literal

from ovk.compilers.authorization.value_origin import (
    classify_expression_origin,
    extract_handler_value_origins,
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


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="assurance.fastapi.bypass_authority.ast_v1",
        extractor_version="0.1.0",
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


def _collect_state_writes(
    tree: ast.AST,
    *,
    path: str,
    handler_param_names: frozenset[str],
) -> tuple[StateAttributeWrite, ...]:
    writes: list[StateAttributeWrite] = []
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
                    )
                )
        elif isinstance(node, ast.AugAssign):
            field = _is_request_state_target(node.target)
            if field is not None:
                writes.append(
                    StateAttributeWrite(
                        field_name=field,
                        value_expression=ast.unparse(node),
                        origin=classify_expression_origin(
                            node.value,
                            path=path,
                            handler_param_names=handler_param_names,
                        ),
                        dynamic=True,
                        source_range=_origin(path, node).source_range,
                    )
                )
        elif isinstance(node, ast.Call):
            # setattr(request.state, name, value) — dynamic unless name is literal.
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "setattr"
                and len(node.args) >= 3
                and isinstance(node.args[0], ast.Attribute)
                and isinstance(node.args[0].value, ast.Name)
                and node.args[0].value.id == "request"
                and node.args[0].attr == "state"
            ):
                name_node = node.args[1]
                value_node = node.args[2]
                if isinstance(name_node, ast.Constant) and isinstance(
                    name_node.value, str
                ):
                    field = name_node.value
                    dynamic = False
                else:
                    field = "__dynamic__"
                    dynamic = True
                writes.append(
                    StateAttributeWrite(
                        field_name=field,
                        value_expression=ast.unparse(value_node),
                        origin=classify_expression_origin(
                            value_node,
                            path=path,
                            handler_param_names=handler_param_names,
                        ),
                        dynamic=dynamic or True,  # setattr is always closed-world fragile
                        source_range=_origin(path, node).source_range,
                    )
                )
            # request.state.__dict__.update(...) / wildcard copy markers
            rendered = ast.unparse(node)
            if "request.state" in rendered and any(
                marker in rendered
                for marker in ("update(", "copy(", "__dict__", "vars(")
            ):
                writes.append(
                    StateAttributeWrite(
                        field_name="__wildcard__",
                        value_expression=rendered,
                        origin=classify_expression_origin(
                            node,
                            path=path,
                            handler_param_names=handler_param_names,
                        ),
                        dynamic=True,
                        source_range=_origin(path, node).source_range,
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
    """Analyze closed-world bypass authority for request.state fields.

    If bypass_fields is None, every requested state field that is read is
    analyzed. Absence of discovered writers is UNKNOWN, not proof of trust.

    Writer origin classification uses parameter names from **all** functions in
    the unit: middleware writers must still see their HTTP parameters even when
    ``function_name`` selects the effect handler for reads.
    """

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
        # Module-level writes still matter for closed-world accounting.
        handler = None
        scope: ast.AST = tree
    else:
        handler = functions[0]
        scope = tree  # closed-world over the whole unit

    origins = (
        extract_handler_value_origins(handler, path=path)
        if handler is not None
        else ()
    )
    writes = _collect_state_writes(
        scope,
        path=path,
        handler_param_names=unit_param_names,
    )
    reads = _collect_state_reads(handler if handler is not None else tree)

    fields = bypass_fields or frozenset(field for field, _ in reads)
    findings: list[BypassAuthorityFinding] = []

    for field in sorted(fields):
        field_reads = [expr for name, expr in reads if name == field]
        field_writes = [item for item in writes if item.field_name == field]
        wildcard = [item for item in writes if item.field_name in {"__wildcard__", "__dynamic__"}]
        dynamic = [item for item in field_writes if item.dynamic] + wildcard

        all_origins = tuple(
            sorted({item.origin.origin_kind for item in field_writes})
        )
        evidence_ids = tuple(
            sorted({item.origin.evidence_id for item in field_writes})
        )
        read_expression = field_reads[0] if field_reads else f"request.state.{field}"

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
            # Absence of discovered writers is not positive proof.
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
        if "externally_bound_http_value" in kinds or "unknown_origin" in kinds:
            # Client/input-controlled or unresolved write → violated when used
            # to skip authorization (caller decides FAIL vs path evaluation).
            status: BypassAuthorityStatus = (
                "violated"
                if "externally_bound_http_value" in kinds
                else "unknown"
            )
            reason = (
                "client_controlled_bypass_write"
                if status == "violated"
                else "unresolved_write_origin"
            )
            findings.append(
                BypassAuthorityFinding(
                    field_name=field,
                    status=status,
                    reason=reason,
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

    # Include param-origin evidence ids for audit packaging.
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
