"""Source-derived effectiveness contracts for direct FastAPI route dependencies.

This module proves one deliberately narrow fact:

    normal_return(require_auth) => bearer credential present and matches token

It does not infer authorization meaning from names. The governed Protected Effect
profile already supplies that policy meaning. This extractor only discharges the
separate fail-closed effectiveness obligation for a bounded source shape.

Unsupported syntax produces no evidence. It never manufactures a negative proof
or a PASS result.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping

from ovk.core.assurance_ir import GuardEffectivenessEvidence, SemanticOrigin
from ovk.core.bundle import content_digest
from ovk.core.models import SourceRange


_EXTRACTOR_ID = "assurance.fastapi.route_dependency_effectiveness.ast_v1"
_EXTRACTOR_VERSION = "0.3.0"


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id=_EXTRACTOR_ID,
        extractor_version=_EXTRACTOR_VERSION,
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


def _leaf_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dependency_parameter_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Return parameters populated by direct Depends/Security defaults."""

    names: set[str] = set()
    positional = list(function.args.posonlyargs) + list(function.args.args)
    defaults = list(function.args.defaults)
    if defaults:
        for argument, default in zip(positional[-len(defaults):], defaults):
            if (
                isinstance(default, ast.Call)
                and _leaf_name(default.func) in {"Depends", "Security"}
                and default.args
            ):
                names.add(argument.arg)

    for argument, default in zip(
        function.args.kwonlyargs,
        function.args.kw_defaults,
    ):
        if (
            isinstance(default, ast.Call)
            and _leaf_name(default.func) in {"Depends", "Security"}
            and default.args
        ):
            names.add(argument.arg)
    return names


def _raise_only_if(statement: ast.stmt) -> ast.AST | None:
    if (
        isinstance(statement, ast.If)
        and not statement.orelse
        and len(statement.body) == 1
        and isinstance(statement.body[0], ast.Raise)
    ):
        return statement.test
    return None


def _render_token_expression(node: ast.AST) -> str | None:
    """Return a bounded server-state expression used as the comparison token."""

    if not isinstance(node, (ast.Name, ast.Attribute)):
        return None
    return ast.unparse(node)


def _missing_token_guard(test: ast.AST) -> str | None:
    """Recognize a token-is-None fail-closed predicate."""

    if (
        not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or not isinstance(test.ops[0], ast.Is)
        or len(test.comparators) != 1
    ):
        return None

    left = test.left
    right = test.comparators[0]

    def is_none(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and node.value is None

    if is_none(right):
        return _render_token_expression(left)
    if is_none(left):
        return _render_token_expression(right)
    return None


def _missing_credential_parameter(
    node: ast.AST,
    dependency_parameters: set[str],
) -> str | None:
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.Not)
        and isinstance(node.operand, ast.Name)
        and node.operand.id in dependency_parameters
    ):
        return node.operand.id

    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Is)
        and len(node.comparators) == 1
    ):
        left = node.left
        right = node.comparators[0]
        if (
            isinstance(left, ast.Name)
            and left.id in dependency_parameters
            and isinstance(right, ast.Constant)
            and right.value is None
        ):
            return left.id
        if (
            isinstance(right, ast.Name)
            and right.id in dependency_parameters
            and isinstance(left, ast.Constant)
            and left.value is None
        ):
            return right.id
    return None


def _credential_projection(
    node: ast.AST,
    dependency_parameters: set[str],
) -> tuple[str, str] | None:
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in dependency_parameters
    ):
        return node.value.id, node.attr
    return None


def _credential_mismatch_guard(
    test: ast.AST,
    dependency_parameters: set[str],
) -> tuple[str, str, str] | None:
    """Recognize missing-credential OR credential-attribute mismatch."""

    if (
        not isinstance(test, ast.BoolOp)
        or not isinstance(test.op, ast.Or)
        or len(test.values) != 2
    ):
        return None

    for missing_node, mismatch_node in (
        (test.values[0], test.values[1]),
        (test.values[1], test.values[0]),
    ):
        missing_parameter = _missing_credential_parameter(
            missing_node, dependency_parameters
        )
        if missing_parameter is None:
            continue

        if (
            not isinstance(mismatch_node, ast.Compare)
            or len(mismatch_node.ops) != 1
            or not isinstance(mismatch_node.ops[0], ast.NotEq)
            or len(mismatch_node.comparators) != 1
        ):
            continue

        left = mismatch_node.left
        right = mismatch_node.comparators[0]
        for credential_node, token_node in ((left, right), (right, left)):
            projection = _credential_projection(
                credential_node, dependency_parameters
            )
            if projection is None:
                continue
            parameter, attribute = projection
            if parameter != missing_parameter:
                continue
            token_expression = _render_token_expression(token_node)
            if token_expression is None:
                continue
            return parameter, attribute, token_expression

    return None


def _meaningful_body(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.stmt]:
    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return body


def _infer_function_evidence(
    *,
    dependency_name: str,
    path: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> GuardEffectivenessEvidence | None:
    """Infer the bounded fail-closed bearer-match contract for one function."""

    dependency_parameters = _dependency_parameter_names(function)
    if not dependency_parameters:
        return None

    body = _meaningful_body(function)
    if not body:
        return None

    missing_token: tuple[str, ast.stmt] | None = None
    credential_guard: tuple[str, str, str, ast.stmt] | None = None

    for statement in body:
        test = _raise_only_if(statement)
        if test is None:
            return None

        token = _missing_token_guard(test)
        if token is not None:
            if missing_token is not None:
                return None
            missing_token = (token, statement)
            continue

        mismatch = _credential_mismatch_guard(test, dependency_parameters)
        if mismatch is not None:
            if credential_guard is not None:
                return None
            parameter, attribute, token_expression = mismatch
            credential_guard = (
                parameter,
                attribute,
                token_expression,
                statement,
            )
            continue

        return None

    if missing_token is None or credential_guard is None:
        return None

    token_expression, token_statement = missing_token
    (
        credential_parameter,
        credential_attribute,
        compared_token_expression,
        credential_statement,
    ) = credential_guard
    if token_expression != compared_token_expression:
        return None

    token_line = int(getattr(token_statement, "lineno", 0))
    credential_line = int(getattr(credential_statement, "lineno", 0))
    if token_line <= 0 or credential_line <= token_line:
        return None

    proof_payload = {
        "kind": "fail_closed_bearer_match_v1",
        "dependency_name": dependency_name,
        "path": path,
        "function": function.name,
        "credential_parameter": credential_parameter,
        "credential_attribute": credential_attribute,
        "token_expression": token_expression,
        "syntax": ast.dump(
            function, annotate_fields=True, include_attributes=False
        ),
    }
    evidence_id = "guard-effectiveness:" + content_digest(proof_payload)[:16]
    return GuardEffectivenessEvidence(
        evidence_id=evidence_id,
        dependency_name=dependency_name,
        evidence_kind="fail_closed_bearer_match_v1",
        credential_parameter=credential_parameter,
        credential_attribute=credential_attribute,
        token_expression=token_expression,
        comparison_kind="direct_inequality",
        assumptions=[
            (
                "The governed source profile assigns authorization meaning to "
                "this dependency for the declared effect/resource."
            ),
            (
                "Normal return implies the dependency credential is present "
                "and its configured credential attribute equals the guarded "
                "server token expression."
            ),
        ],
        origin=_origin(path, function),
    )



def _parameter_defaults(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, ast.AST]]:
    """Return explicit parameter default expressions by parameter name."""

    pairs: list[tuple[str, ast.AST]] = []
    positional = list(function.args.posonlyargs) + list(function.args.args)
    defaults = list(function.args.defaults)
    if defaults:
        pairs.extend(
            (argument.arg, default)
            for argument, default in zip(
                positional[-len(defaults) :],
                defaults,
            )
        )
    pairs.extend(
        (argument.arg, default)
        for argument, default in zip(
            function.args.kwonlyargs,
            function.args.kw_defaults,
        )
        if default is not None
    )
    return pairs


def _header_none_parameters(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Return parameters whose exact default is Header(None).

    Keyword options, aliases, required Header parameters, and indirect helper
    calls remain outside this first theorem.
    """

    names: set[str] = set()
    for parameter, default in _parameter_defaults(function):
        if (
            not isinstance(default, ast.Call)
            or _leaf_name(default.func) != "Header"
            or default.keywords
            or len(default.args) != 1
            or not isinstance(default.args[0], ast.Constant)
            or default.args[0].value is not None
        ):
            continue
        names.add(parameter)
    return names


def _token_binding_assignment(
    statement: ast.stmt,
    *,
    credential_parameters: set[str],
) -> tuple[str, str] | None:
    """Recognize one local binding to a server-side token expression.

    The RHS is restricted to a name/attribute or a zero-argument call through
    an attribute expression. It must not reference the request credential.
    """

    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
    ):
        return None

    target = statement.targets[0].id
    value = statement.value
    if any(
        isinstance(node, ast.Name) and node.id in credential_parameters
        for node in ast.walk(value)
    ):
        return None

    if isinstance(value, (ast.Name, ast.Attribute)):
        return target, ast.unparse(value)

    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and not value.args
        and not value.keywords
    ):
        return target, ast.unparse(value)

    return None


def _falsey_name_guard(test: ast.AST, expected_name: str) -> bool:
    return (
        isinstance(test, ast.UnaryOp)
        and isinstance(test.op, ast.Not)
        and isinstance(test.operand, ast.Name)
        and test.operand.id == expected_name
    )


def _compare_digest_call(
    node: ast.AST,
    *,
    credential_parameter: str,
    token_alias: str,
) -> bool:
    """Recognize secrets.compare_digest(credential, token_alias), either order."""

    if (
        not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Attribute)
        or node.func.attr != "compare_digest"
        or not isinstance(node.func.value, ast.Name)
        or node.func.value.id != "secrets"
        or len(node.args) != 2
        or node.keywords
    ):
        return False

    rendered = [
        arg.id if isinstance(arg, ast.Name) else None
        for arg in node.args
    ]
    return set(rendered) == {credential_parameter, token_alias}


def _header_shared_secret_mismatch_guard(
    test: ast.AST,
    *,
    credential_parameters: set[str],
    token_alias: str,
) -> str | None:
    """Recognize missing header OR failed constant-time shared-secret match."""

    if (
        not isinstance(test, ast.BoolOp)
        or not isinstance(test.op, ast.Or)
        or len(test.values) != 2
    ):
        return None

    for missing_node, mismatch_node in (
        (test.values[0], test.values[1]),
        (test.values[1], test.values[0]),
    ):
        credential = _missing_credential_parameter(
            missing_node,
            credential_parameters,
        )
        if credential is None:
            continue
        if (
            isinstance(mismatch_node, ast.UnaryOp)
            and isinstance(mismatch_node.op, ast.Not)
            and _compare_digest_call(
                mismatch_node.operand,
                credential_parameter=credential,
                token_alias=token_alias,
            )
        ):
            return credential
    return None


def _infer_header_shared_secret_evidence(
    *,
    dependency_name: str,
    path: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> GuardEffectivenessEvidence | None:
    """Infer fail-closed effectiveness for one raw Header/shared-secret guard."""

    header_parameters = _header_none_parameters(function)
    if len(header_parameters) != 1:
        return None

    body = _meaningful_body(function)
    if len(body) != 3:
        return None

    binding = _token_binding_assignment(
        body[0],
        credential_parameters=header_parameters,
    )
    if binding is None:
        return None
    token_alias, token_expression = binding

    token_guard = _raise_only_if(body[1])
    if (
        token_guard is None
        or not _falsey_name_guard(token_guard, token_alias)
    ):
        return None

    mismatch_guard = _raise_only_if(body[2])
    if mismatch_guard is None:
        return None
    credential_parameter = _header_shared_secret_mismatch_guard(
        mismatch_guard,
        credential_parameters=header_parameters,
        token_alias=token_alias,
    )
    if credential_parameter is None:
        return None

    proof_payload = {
        "kind": "fail_closed_header_shared_secret_v1",
        "dependency_name": dependency_name,
        "path": path,
        "function": function.name,
        "credential_parameter": credential_parameter,
        "token_alias": token_alias,
        "token_expression": token_expression,
        "comparison_kind": "secrets_compare_digest",
        "syntax": ast.dump(
            function,
            annotate_fields=True,
            include_attributes=False,
        ),
    }
    evidence_id = (
        "guard-effectiveness:"
        + content_digest(proof_payload)[:16]
    )
    return GuardEffectivenessEvidence(
        evidence_id=evidence_id,
        dependency_name=dependency_name,
        evidence_kind="fail_closed_header_shared_secret_v1",
        credential_parameter=credential_parameter,
        credential_attribute=None,
        token_expression=token_expression,
        comparison_kind="secrets_compare_digest",
        assumptions=[
            (
                "The governed source profile assigns authorization meaning to "
                "this dependency for the declared effect/resource."
            ),
            (
                "Normal return implies the raw Header credential is present "
                "and secrets.compare_digest accepts it against the single "
                "server-token value bound earlier in the function."
            ),
        ],
        origin=_origin(path, function),
    )



def _has_direct_import(tree: ast.Module, module: str) -> bool:
    return any(
        isinstance(statement, ast.Import)
        and any(
            alias.name == module and alias.asname is None
            for alias in statement.names
        )
        for statement in tree.body
    )


def _has_direct_from_import(
    tree: ast.Module,
    *,
    module: str,
    name: str,
) -> bool:
    return any(
        isinstance(statement, ast.ImportFrom)
        and statement.module == module
        and statement.level == 0
        and any(
            alias.name == name and alias.asname is None
            for alias in statement.names
        )
        for statement in tree.body
    )


def _top_level_name_rebound(
    tree: ast.Module,
    name: str,
) -> bool:
    """Return whether a canonical imported name is reassigned at module scope."""

    for statement in tree.body:
        targets: list[ast.AST] = []
        if isinstance(statement, ast.Assign):
            targets.extend(statement.targets)
        elif isinstance(statement, ast.AnnAssign):
            targets.append(statement.target)
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if statement.name == name:
                return True
            continue

        for target in targets:
            if isinstance(target, ast.Name) and target.id == name:
                return True
    return False


def _canonical_apikey_dependencies_available(tree: ast.Module) -> bool:
    required = (
        _has_direct_import(tree, "hmac")
        and _has_direct_import(tree, "os")
        and _has_direct_from_import(
            tree,
            module="fastapi",
            name="Security",
        )
        and _has_direct_from_import(
            tree,
            module="fastapi.security",
            name="APIKeyHeader",
        )
    )
    if not required:
        return False
    return not any(
        _top_level_name_rebound(tree, name)
        for name in ("hmac", "os", "Security", "APIKeyHeader")
    )


def _security_apikeyheader_parameter(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    tree: ast.Module,
) -> str | None:
    """Return the unique parameter supplied by Security(APIKeyHeader(...)).

    The supported scheme must be a unique top-level binding created directly by
    APIKeyHeader with auto_error=False. This proves the parameter is populated
    from that FastAPI security scheme instead of treating an arbitrary
    Security(...) dependency as a raw credential.
    """

    if not _canonical_apikey_dependencies_available(tree):
        return None

    candidates: list[tuple[str, str]] = []
    for parameter, default in _parameter_defaults(function):
        if (
            not isinstance(default, ast.Call)
            or _leaf_name(default.func) != "Security"
            or len(default.args) != 1
            or default.keywords
            or not isinstance(default.args[0], ast.Name)
        ):
            continue
        candidates.append((parameter, default.args[0].id))

    if len(candidates) != 1:
        return None
    parameter, scheme_name = candidates[0]

    scheme_assignments: list[ast.AST] = []
    for statement in tree.body:
        target: ast.AST | None = None
        value: ast.AST | None = None
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
        ):
            target = statement.targets[0]
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            target = statement.target
            value = statement.value

        if (
            not isinstance(target, ast.Name)
            or target.id != scheme_name
            or value is None
        ):
            continue
        if (
            not isinstance(value, ast.Call)
            or _leaf_name(value.func) != "APIKeyHeader"
        ):
            return None

        keywords = {
            keyword.arg: keyword.value
            for keyword in value.keywords
            if keyword.arg is not None
        }
        if (
            value.args
            or set(keywords) != {"name", "auto_error"}
            or not isinstance(
                keywords["name"],
                (ast.Name, ast.Constant),
            )
            or (
                isinstance(keywords["name"], ast.Constant)
                and not isinstance(keywords["name"].value, str)
            )
            or not isinstance(keywords["auto_error"], ast.Constant)
            or keywords["auto_error"].value is not False
        ):
            return None
        if int(getattr(statement, "lineno", 0)) >= int(
            getattr(function, "lineno", 0)
        ):
            return None
        scheme_assignments.append(statement)

    if len(scheme_assignments) != 1:
        return None
    return parameter


def _environment_token_binding_assignment(
    statement: ast.stmt,
    *,
    credential_parameter: str,
) -> tuple[str, str] | None:
    """Recognize local = os.environ.get(SERVER_KEY_NAME).

    The environment-key expression may be a literal or source constant, but it
    must not depend on the presented credential. No fallback/default argument is
    accepted in this first theorem.
    """

    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
        or not isinstance(statement.value, ast.Call)
    ):
        return None

    call = statement.value
    if (
        not isinstance(call.func, ast.Attribute)
        or call.func.attr != "get"
        or not isinstance(call.func.value, ast.Attribute)
        or call.func.value.attr != "environ"
        or not isinstance(call.func.value.value, ast.Name)
        or call.func.value.value.id != "os"
        or len(call.args) != 1
        or call.keywords
    ):
        return None

    if any(
        isinstance(node, ast.Name) and node.id == credential_parameter
        for node in ast.walk(call)
    ):
        return None

    key = call.args[0]
    if not isinstance(key, (ast.Name, ast.Constant)):
        return None
    if isinstance(key, ast.Constant) and not isinstance(key.value, str):
        return None

    return statement.targets[0].id, ast.unparse(call)


def _hmac_compare_digest_call(
    node: ast.AST,
    *,
    credential_parameter: str,
    token_alias: str,
) -> bool:
    if (
        not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Attribute)
        or node.func.attr != "compare_digest"
        or not isinstance(node.func.value, ast.Name)
        or node.func.value.id != "hmac"
        or len(node.args) != 2
        or node.keywords
    ):
        return False

    rendered = [
        arg.id if isinstance(arg, ast.Name) else None
        for arg in node.args
    ]
    return set(rendered) == {credential_parameter, token_alias}


def _apikeyheader_mismatch_guard(
    test: ast.AST,
    *,
    credential_parameter: str,
    token_alias: str,
) -> bool:
    if (
        not isinstance(test, ast.BoolOp)
        or not isinstance(test.op, ast.Or)
        or len(test.values) != 2
    ):
        return False

    for missing_node, mismatch_node in (
        (test.values[0], test.values[1]),
        (test.values[1], test.values[0]),
    ):
        missing = _missing_credential_parameter(
            missing_node,
            {credential_parameter},
        )
        if missing != credential_parameter:
            continue
        if (
            isinstance(mismatch_node, ast.UnaryOp)
            and isinstance(mismatch_node.op, ast.Not)
            and _hmac_compare_digest_call(
                mismatch_node.operand,
                credential_parameter=credential_parameter,
                token_alias=token_alias,
            )
        ):
            return True
    return False


def _body_without_optional_none_return(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.stmt]:
    body = _meaningful_body(function)
    if body and isinstance(body[-1], ast.Return):
        value = body[-1].value
        if value is None or (
            isinstance(value, ast.Constant) and value.value is None
        ):
            body = body[:-1]
    return body


def _infer_apikeyheader_shared_secret_evidence(
    *,
    dependency_name: str,
    path: str,
    tree: ast.Module,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> GuardEffectivenessEvidence | None:
    """Infer fail-closed APIKeyHeader/environment shared-secret effectiveness."""

    credential_parameter = _security_apikeyheader_parameter(
        function,
        tree=tree,
    )
    if credential_parameter is None:
        return None

    body = _body_without_optional_none_return(function)
    if len(body) != 3:
        return None

    binding = _environment_token_binding_assignment(
        body[0],
        credential_parameter=credential_parameter,
    )
    if binding is None:
        return None
    token_alias, token_expression = binding

    token_guard = _raise_only_if(body[1])
    if (
        token_guard is None
        or not _falsey_name_guard(token_guard, token_alias)
    ):
        return None

    credential_guard = _raise_only_if(body[2])
    if (
        credential_guard is None
        or not _apikeyheader_mismatch_guard(
            credential_guard,
            credential_parameter=credential_parameter,
            token_alias=token_alias,
        )
    ):
        return None

    proof_payload = {
        "kind": "fail_closed_apikeyheader_shared_secret_v1",
        "dependency_name": dependency_name,
        "path": path,
        "function": function.name,
        "credential_parameter": credential_parameter,
        "token_alias": token_alias,
        "token_expression": token_expression,
        "comparison_kind": "hmac_compare_digest",
        "syntax": ast.dump(
            function,
            annotate_fields=True,
            include_attributes=False,
        ),
    }
    evidence_id = (
        "guard-effectiveness:"
        + content_digest(proof_payload)[:16]
    )
    return GuardEffectivenessEvidence(
        evidence_id=evidence_id,
        dependency_name=dependency_name,
        evidence_kind="fail_closed_apikeyheader_shared_secret_v1",
        credential_parameter=credential_parameter,
        credential_attribute=None,
        token_expression=token_expression,
        comparison_kind="hmac_compare_digest",
        assumptions=[
            (
                "The governed source profile assigns authorization meaning to "
                "this dependency for the declared effect/resource."
            ),
            (
                "FastAPI Security(APIKeyHeader(auto_error=False)) supplies the "
                "presented API-key header value or None to the dependency."
            ),
            (
                "Normal return implies the configured environment secret is "
                "present and hmac.compare_digest accepts the presented key "
                "against that same bound secret value."
            ),
        ],
        origin=_origin(path, function),
    )


def infer_route_dependency_effectiveness(
    *,
    parsed_trees: Mapping[str, ast.Module],
    dependency_names: Iterable[str],
) -> list[GuardEffectivenessEvidence]:
    """Infer unique source-derived effectiveness evidence for configured guards."""

    definitions: dict[
        str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]
    ] = {}
    for path, tree in sorted(parsed_trees.items()):
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                definitions.setdefault(node.name, []).append((path, node))

    evidence: list[GuardEffectivenessEvidence] = []
    for dependency_name in sorted(set(dependency_names)):
        leaf = dependency_name.rsplit(".", 1)[-1]
        candidates = definitions.get(leaf, [])
        if len(candidates) != 1:
            continue
        path, function = candidates[0]
        item = _infer_function_evidence(
            dependency_name=dependency_name,
            path=path,
            function=function,
        )
        if item is None:
            item = _infer_header_shared_secret_evidence(
                dependency_name=dependency_name,
                path=path,
                function=function,
            )
        if item is None:
            item = _infer_apikeyheader_shared_secret_evidence(
                dependency_name=dependency_name,
                path=path,
                tree=parsed_trees[path],
                function=function,
            )
        if item is not None:
            evidence.append(item)

    return sorted(evidence, key=lambda item: item.evidence_id)
