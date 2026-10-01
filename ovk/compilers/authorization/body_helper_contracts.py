"""Body-authorization-helper implementation evidence (#148 / #151 / #152).

Profile declaration alone never establishes effectiveness. A reachable
denial-shaped raise is also insufficient: it does not prove the raise
implements the authorization policy represented by the profile
(Unknown > false PASS). Helpers therefore remain ``unproved`` until a
machine-checkable authorization predicate or digest-bound contract is
modeled.

Implementation analysis still resolves the exact callee symbol and records
source/semantic digests so fragments can dependency-track helper bodies
(#152). No-op, shadowed, dead-code-only, and unresolved definitions stay
unproved with distinct diagnostic reasons. Callsite-local rebinding also
refuses establishment even when a module-level definition exists.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ovk.core.bundle import content_digest


@dataclass(frozen=True)
class BodyHelperImplementationEvidence:
    helper_name: str
    path: str
    line: int
    status: str
    reason: str
    qualified_symbol: str = ""
    source_digest: str = ""
    implementation_digest: str = ""
    evidence_id: str = ""


def _is_http_exception_constructor(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "HTTPException"
    if isinstance(node, ast.Attribute):
        return node.attr == "HTTPException"
    return False


def _is_auth_deny_raise(node: ast.Raise) -> bool:
    if node.exc is None:
        return True
    if _is_http_exception_constructor(node.exc):
        return True
    if isinstance(node.exc, ast.Call) and _is_http_exception_constructor(
        node.exc.func
    ):
        return True
    if isinstance(node.exc, (ast.Name, ast.Attribute)):
        return True
    return False


def _constant_bool(test: ast.AST) -> bool | None:
    if isinstance(test, ast.Constant) and isinstance(test.value, bool):
        return test.value
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = _constant_bool(test.operand)
        if inner is None:
            return None
        return not inner
    return None


def _block_has_reachable_fail_closed_raise(body: Sequence[ast.stmt]) -> bool:
    """True when a deny-shaped raise is reachable under constant folding.

    Constant-false branches and statements after an unconditional return are
    ignored so dead ``raise HTTPException`` cannot establish effectiveness.
    Nested function/class bodies are not attributed to the helper itself.
    """

    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.Raise):
            if _is_auth_deny_raise(stmt):
                return True
            continue
        if isinstance(stmt, ast.Return):
            # Unconditional return makes subsequent sibling statements dead.
            return False
        if isinstance(stmt, ast.If):
            flag = _constant_bool(stmt.test)
            if flag is True:
                if _block_has_reachable_fail_closed_raise(stmt.body):
                    return True
            elif flag is False:
                if _block_has_reachable_fail_closed_raise(stmt.orelse):
                    return True
            else:
                if _block_has_reachable_fail_closed_raise(stmt.body):
                    return True
                if _block_has_reachable_fail_closed_raise(stmt.orelse):
                    return True
            continue
        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            if _block_has_reachable_fail_closed_raise(stmt.body):
                return True
            if isinstance(stmt, (ast.For, ast.AsyncFor)) and _block_has_reachable_fail_closed_raise(
                stmt.orelse
            ):
                return True
            if isinstance(stmt, ast.While) and _block_has_reachable_fail_closed_raise(
                stmt.orelse
            ):
                return True
            continue
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            if _block_has_reachable_fail_closed_raise(stmt.body):
                return True
            continue
        if isinstance(stmt, ast.Try):
            if _block_has_reachable_fail_closed_raise(stmt.body):
                return True
            for handler in stmt.handlers:
                if _block_has_reachable_fail_closed_raise(handler.body):
                    return True
            if _block_has_reachable_fail_closed_raise(stmt.orelse):
                return True
            if _block_has_reachable_fail_closed_raise(stmt.finalbody):
                return True
            continue
        if isinstance(stmt, ast.Match):
            for case in stmt.cases:
                if _block_has_reachable_fail_closed_raise(case.body):
                    return True
            continue
    return False


def _body_is_noop(body: list[ast.stmt]) -> bool:
    """True when the body cannot deny (pass / return True / return None only)."""

    meaningful = [
        stmt
        for stmt in body
        if not isinstance(stmt, (ast.Pass, ast.Expr))
    ]
    if not meaningful:
        return True
    if len(meaningful) == 1 and isinstance(meaningful[0], ast.Return):
        value = meaningful[0].value
        if value is None:
            return True
        if isinstance(value, ast.Constant) and value.value in {True, None}:
            return True
    return False


def _collect_definitions(
    files: Mapping[str, str],
    *,
    helper_name: str,
) -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    """Collect every function def named ``helper_name``, including nested defs.

    Nested definitions participate so module-level fail-closed helpers cannot
    authorize a callsite that binds a different nested callable of the same
    name (Unknown > false PASS).
    """

    found: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for path, source in sorted(files.items()):
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == helper_name
            ):
                found.append((path, node))
    return found


def _name_is_stored(target: ast.AST, helper_name: str) -> bool:
    if isinstance(target, ast.Name) and target.id == helper_name:
        return True
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_name_is_stored(elt, helper_name) for elt in target.elts)
    return False


def helper_name_locally_rebound_in_handler(
    source: str,
    *,
    handler_name: str,
    helper_name: str,
    call_line: int,
    trusted_definition_line: int | None = None,
) -> bool:
    """True when the helper name is rebound inside ``handler_name`` before use.

    Covers parameter shadowing, nested ``def``/``async def``, and assignment /
    annotated assignment / ``for``/``with`` stores of the helper name.

    When ``trusted_definition_line`` points at the unique nested definition that
    implementation analysis already established inside this handler, that nested
    ``def`` itself is not treated as a hostile rebound.
    """

    try:
        tree = ast.parse(source)
    except SyntaxError:
        # Unparseable handler source cannot prove the global binding is live.
        return True

    handler: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in tree.body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == handler_name
        ):
            if handler is not None:
                return True
            handler = node
    if handler is None:
        # Handler may be nested (class method) — refuse rather than mis-bind.
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == handler_name
            ):
                if handler is not None:
                    return True
                handler = node
    if handler is None:
        return True

    for arg in handler.args.args + handler.args.posonlyargs + handler.args.kwonlyargs:
        if arg.arg == helper_name:
            return True
    if handler.args.vararg is not None and handler.args.vararg.arg == helper_name:
        return True
    if handler.args.kwarg is not None and handler.args.kwarg.arg == helper_name:
        return True

    for node in ast.walk(handler):
        if node is handler:
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == helper_name:
                def_line = getattr(node, "lineno", 0) or 0
                if (
                    trusted_definition_line is not None
                    and def_line == trusted_definition_line
                ):
                    continue
                return True
            continue
        lineno = getattr(node, "lineno", None)
        if call_line > 0 and lineno is not None and lineno > call_line:
            continue
        if isinstance(node, ast.Assign):
            if any(_name_is_stored(target, helper_name) for target in node.targets):
                return True
        elif isinstance(node, ast.AnnAssign) and node.target is not None:
            if _name_is_stored(node.target, helper_name):
                return True
        elif isinstance(node, ast.AugAssign):
            if _name_is_stored(node.target, helper_name):
                return True
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            if _name_is_stored(node.target, helper_name):
                return True
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None and _name_is_stored(
                    item.optional_vars, helper_name
                ):
                    return True
        elif isinstance(node, ast.ExceptHandler) and node.name == helper_name:
            return True
        elif isinstance(node, ast.NamedExpr) and _name_is_stored(node.target, helper_name):
            return True
    return False


def _definition_source_digest(
    files: Mapping[str, str],
    *,
    path: str,
) -> str:
    source = files.get(path)
    if source is None:
        return content_digest("")
    return content_digest(source)


def _implementation_digest(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str:
    """Digest the exact callee definition shape (signature + body)."""

    payload = {
        "kind": type(node).__name__,
        "name": node.name,
        "args": ast.dump(node.args, include_attributes=False),
        "body": [ast.dump(stmt, include_attributes=False) for stmt in node.body],
        "decorator_list": [
            ast.dump(item, include_attributes=False) for item in node.decorator_list
        ],
        "returns": (
            ast.dump(node.returns, include_attributes=False)
            if node.returns is not None
            else None
        ),
    }
    return content_digest(payload)


def _evidence(
    *,
    helper_name: str,
    path: str,
    line: int,
    status: str,
    reason: str,
    files: Mapping[str, str],
    node: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
) -> BodyHelperImplementationEvidence:
    qualified = f"{path}:{helper_name}@{line}" if line > 0 else f"{path}:{helper_name}"
    source_digest = (
        _definition_source_digest(files, path=path)
        if path != "<missing>"
        else content_digest("")
    )
    impl_digest = (
        _implementation_digest(node) if node is not None else content_digest("")
    )
    evidence_id = content_digest(
        {
            "helper_name": helper_name,
            "qualified_symbol": qualified,
            "path": path,
            "line": line,
            "status": status,
            "reason": reason,
            "source_digest": source_digest,
            "implementation_digest": impl_digest,
        }
    )
    return BodyHelperImplementationEvidence(
        helper_name=helper_name,
        path=path,
        line=line,
        status=status,
        reason=reason,
        qualified_symbol=qualified,
        source_digest=source_digest,
        implementation_digest=impl_digest,
        evidence_id=f"bhe:{evidence_id[:24]}",
    )


def analyze_body_helper_implementation(
    files: Mapping[str, str],
    *,
    helper_name: str,
) -> BodyHelperImplementationEvidence:
    """Classify one profile helper's implementation for effectiveness."""

    definitions = _collect_definitions(files, helper_name=helper_name)
    if not definitions:
        return _evidence(
            helper_name=helper_name,
            path="<missing>",
            line=0,
            status="unproved",
            reason="helper_definition_missing",
            files=files,
        )
    if len(definitions) > 1:
        path, node = definitions[0]
        return _evidence(
            helper_name=helper_name,
            path=path,
            line=getattr(node, "lineno", 0) or 0,
            status="unproved",
            reason="helper_definition_shadowed",
            files=files,
            node=node,
        )
    path, node = definitions[0]
    line = getattr(node, "lineno", 0) or 0
    if _body_is_noop(list(node.body)):
        return _evidence(
            helper_name=helper_name,
            path=path,
            line=line,
            status="unproved",
            reason="helper_implementation_noop",
            files=files,
            node=node,
        )
    if _block_has_reachable_fail_closed_raise(list(node.body)):
        # #151: a reachable raise is diagnostic only — never establishes
        # authorization effectiveness. Irrelevant / inverted / probabilistic
        # denials would otherwise false-PASS under an unchanged profile.
        return _evidence(
            helper_name=helper_name,
            path=path,
            line=line,
            status="unproved",
            reason="helper_reachable_raise_insufficient",
            files=files,
            node=node,
        )
    return _evidence(
        helper_name=helper_name,
        path=path,
        line=line,
        status="unproved",
        reason="helper_implementation_unproved",
        files=files,
        node=node,
    )
