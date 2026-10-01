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

Request/state escape analysis (#156): governed state identity must not leave
the supported theorem through helper arguments, ``__dict__`` / ``vars``
mutation, unresolved method calls, or similar channels without either a
bounded interprocedural writer closure or an explicit UNKNOWN.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Literal, Mapping

from ovk.compilers.authorization.python_callee_resolution import (
    CalleeResolver,
    build_callee_resolver,
)
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
class ClosedWorldScopeProof:
    """Caller-supplied proof boundary for repository writer accounting.

    accounted_paths is the complete Python source set claimed for this analysis
    scope. source_roots map repository paths to importable module names, e.g.
    ("backend",) for backend/open_webui/... -> open_webui....
    """

    accounted_paths: tuple[str, ...]
    source_roots: tuple[str, ...]


@dataclass(frozen=True)
class ClosedWorldCondition:
    """Explicit closed-world accounting status for one analysis unit."""

    complete: bool
    accounted_paths: tuple[str, ...]
    source_roots: tuple[str, ...]
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
    control_dependent: bool = False


_BYPASS_AUTHORITY_EXTRACTOR_VERSION = "0.9.0"
_MAX_INTERPROCEDURAL_WRITER_DEPTH = 4
_STATE_DICT_ATTRS = frozenset({"__dict__", "__slots__"})

# Builtins that observe request/state without a mutation channel under the
# bounded escape theorem. ``setattr`` is handled separately as a write.
_NON_MUTATING_STATE_OBSERVERS = frozenset(
    {
        "getattr",
        "hasattr",
        "isinstance",
        "issubclass",
        "id",
        "type",
        "bool",
        "repr",
        "str",
        "len",
        "ascii",
        "hash",
    }
)


def _origin(path: str, node: ast.AST) -> SemanticOrigin:
    return SemanticOrigin(
        path=path,
        extractor_id="assurance.fastapi.bypass_authority.ast_v1",
        extractor_version=_BYPASS_AUTHORITY_EXTRACTOR_VERSION,
        source_range=SourceRange(
            path=path,
            start_line=getattr(node, "lineno", None),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", None)),
        ),
    )


@dataclass
class _RequestStateAliasEnv:
    """Track names proved to alias ``request`` or ``request.state`` (#153).

    Seeded with the literal parameter/name ``request``. Assignments such as
    ``req = request`` and ``state = request.state`` extend the supported alias
    theorem. Any other ``*.state.<field>`` mutation is still recorded so it
    cannot be omitted from closed-world accounting (Unknown > false PASS).
    """

    request_names: set[str]
    state_names: set[str]

    @classmethod
    def seed(cls, *, param_names: frozenset[str]) -> "_RequestStateAliasEnv":
        request_names = {"request"} if "request" in param_names else set()
        # Module-level walks may have no params; still recognize bare ``request``.
        if not param_names:
            request_names.add("request")
        return cls(request_names=set(request_names), state_names=set())

    def note_binding(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            # Complex targets poison nothing specific; leave env unchanged.
            return
        name = target.id
        if self._is_request_expr(value):
            self.request_names.add(name)
            self.state_names.discard(name)
            return
        if self._is_state_expr(value):
            self.state_names.add(name)
            self.request_names.discard(name)
            return
        # Rebind of a previously aliased name to an unrelated value.
        self.request_names.discard(name)
        self.state_names.discard(name)

    def poison_names(self, names: set[str]) -> None:
        for name in names:
            self.request_names.discard(name)
            self.state_names.discard(name)

    def _is_request_expr(self, value: ast.AST) -> bool:
        return isinstance(value, ast.Name) and value.id in self.request_names

    def _is_state_expr(self, value: ast.AST) -> bool:
        if isinstance(value, ast.Name) and value.id in self.state_names:
            return True
        if (
            isinstance(value, ast.Attribute)
            and value.attr == "state"
            and isinstance(value.value, ast.Name)
            and value.value.id in self.request_names
        ):
            return True
        # getattr(request, "state") / getattr(req, "state") — otherwise a later
        # ``state.field = client`` write is omitted from closed-world accounting.
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "getattr"
            and len(value.args) >= 2
            and self._is_request_expr(value.args[0])
            and isinstance(value.args[1], ast.Constant)
            and value.args[1].value == "state"
        ):
            return True
        return False

    def is_state_expr(self, value: ast.AST) -> bool:
        return self._is_state_expr(value)

    def field_from_assign_target(self, target: ast.AST) -> tuple[str | None, bool]:
        """Return ``(field, exact_or_supported_alias)`` for a store target.

        When the second element is False, the write is still counted but marked
        dynamic/unknown so closure cannot authorize while omitting it.
        """

        # request.state.field / req.state.field
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Attribute)
            and target.value.attr == "state"
            and isinstance(target.value.value, ast.Name)
        ):
            field = target.attr
            base = target.value.value.id
            if base in self.request_names:
                return field, True
            # Plausible Request-like alias (e.g. parameter ``req``) — record,
            # but do not treat as the supported exact theorem.
            return field, False

        # state.field where state aliases request.state
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id in self.state_names
        ):
            return target.attr, True

        # request.state[field] / req.state[field] / state[field]
        if isinstance(target, ast.Subscript):
            field = _constant_str_key(target.slice)
            if field is None:
                if self._container_is_state(target.value):
                    return "__dynamic__", False
                return None, False
            if self._container_is_state(target.value):
                exact = self._container_is_supported_state(target.value)
                return field, exact
            return None, False

        return None, False

    def _container_is_state(self, node: ast.AST) -> bool:
        if self._is_state_expr(node):
            return True
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "state"
            and isinstance(node.value, ast.Name)
        ):
            # Any Name.state — plausible even when Name is not proved request.
            return True
        return False

    def _container_is_supported_state(self, node: ast.AST) -> bool:
        return self._is_state_expr(node)

    def is_request_or_state_expr(self, value: ast.AST) -> bool:
        return self._is_request_expr(value) or self._is_state_expr(value)

    def call_receives_request_or_state(self, call: ast.Call) -> bool:
        for arg in call.args:
            if isinstance(arg, ast.Starred):
                if self.is_request_or_state_expr(arg.value):
                    return True
                continue
            if self.is_request_or_state_expr(arg):
                return True
        for kw in call.keywords:
            if kw.value is not None and self.is_request_or_state_expr(kw.value):
                return True
        if isinstance(call.func, ast.Attribute):
            if self.is_request_or_state_expr(call.func.value):
                return True
        return False

    def is_state_dict_surface(self, value: ast.AST) -> bool:
        """True for ``state.__dict__`` / ``vars(state)`` / ``__getattribute__`` surfaces."""

        if isinstance(value, ast.NamedExpr):
            return self.is_state_dict_surface(value.value)
        if (
            isinstance(value, ast.Attribute)
            and value.attr in _STATE_DICT_ATTRS
            and self._container_is_state(value.value)
        ):
            return True
        if not isinstance(value, ast.Call):
            return False
        if (
            isinstance(value.func, ast.Name)
            and value.func.id == "vars"
            and value.args
            and self.is_request_or_state_expr(value.args[0])
        ):
            return True
        if (
            isinstance(value.func, ast.Name)
            and value.func.id == "getattr"
            and len(value.args) >= 2
            and self._container_is_state(value.args[0])
            and isinstance(value.args[1], ast.Constant)
            and value.args[1].value in _STATE_DICT_ATTRS
        ):
            return True
        # object.__getattribute__(state, "__dict__")
        if (
            isinstance(value.func, ast.Attribute)
            and value.func.attr == "__getattribute__"
            and len(value.args) >= 2
            and isinstance(value.args[1], ast.Constant)
            and value.args[1].value in _STATE_DICT_ATTRS
            and self._container_is_state(value.args[0])
        ):
            return True
        # state.__getattribute__("__dict__")
        if (
            isinstance(value.func, ast.Attribute)
            and value.func.attr == "__getattribute__"
            and self._container_is_state(value.func.value)
            and value.args
            and isinstance(value.args[0], ast.Constant)
            and value.args[0].value in _STATE_DICT_ATTRS
        ):
            return True
        return False

    def packs_request_or_state_identity(self, value: ast.AST) -> bool:
        """True when request/state identity is packed into a container literal."""

        if isinstance(value, ast.NamedExpr):
            return self.packs_request_or_state_identity(value.value)
        if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
            for elt in value.elts:
                if isinstance(elt, ast.Starred):
                    nested = elt.value
                else:
                    nested = elt
                if self.is_request_or_state_expr(nested):
                    return True
                if self.packs_request_or_state_identity(nested):
                    return True
            return False
        if isinstance(value, ast.Dict):
            for key, val in zip(value.keys, value.values):
                for item in (key, val):
                    if item is None:
                        continue
                    if self.is_request_or_state_expr(item):
                        return True
                    if self.packs_request_or_state_identity(item):
                        return True
            return False
        return False

    def assignment_escapes_state_identity(
        self, target: ast.AST, value: ast.AST
    ) -> bool:
        """True when an assignment escapes governed identity outside Name aliasing.

        ``state = request.state`` remains the supported Name alias theorem.
        Packing into tuples/lists, aliasing ``__dict__``, or storing into
        non-Name targets is residual escape (Unknown > false PASS).
        """

        if isinstance(value, ast.NamedExpr):
            return self.assignment_escapes_state_identity(target, value.value)
        if self.is_state_dict_surface(value):
            return True
        if self.packs_request_or_state_identity(value):
            return True
        if self.is_request_or_state_expr(value) and not isinstance(target, ast.Name):
            return True
        return False

    def expression_escapes_state_identity(self, value: ast.AST) -> bool:
        """True when an expression embeds a residual state-identity escape channel."""

        if self.is_state_dict_surface(value) or self.packs_request_or_state_identity(
            value
        ):
            return True
        for node in ast.walk(value):
            if not isinstance(node, ast.NamedExpr):
                continue
            if self.is_state_dict_surface(node.value) or self.packs_request_or_state_identity(
                node.value
            ):
                return True
        return False

    def is_poison_state_store(self, target: ast.AST) -> bool:
        """True when a store mutates governed state outside the field theorem.

        Covers ``state.__dict__[…]``, ``request.state.__dict__[…]``,
        ``getattr(state, \"__dict__\")[…]``, ``vars(state)[…]``,
        ``object.__getattribute__(state, \"__dict__\")[…]``, Call-shaped
        dict surfaces such as ``operator.attrgetter(\"__dict__\")(state)[…]``,
        walrus-bound dict surfaces, and other unresolved subscript/descriptor
        forms on a proved or plausible state container.
        """

        if isinstance(target, ast.Subscript):
            base = target.value
            if isinstance(base, ast.NamedExpr):
                base = base.value
            if self.is_state_dict_surface(base):
                return True
            if isinstance(base, ast.Call) and self.call_receives_request_or_state(base):
                return True
            if (
                isinstance(base, ast.Attribute)
                and base.attr in _STATE_DICT_ATTRS
                and self._container_is_state(base.value)
            ):
                return True
            # Descriptor / unresolved subscript on proved state (non-field key
            # already handled by field_from_assign_target as __dynamic__).
            if self._is_state_expr(base) and _constant_str_key(target.slice) is None:
                return True
            return False
        if isinstance(target, ast.Attribute) and target.attr in _STATE_DICT_ATTRS:
            return self._container_is_state(target.value)
        return False


def _constant_str_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_request_state_target(
    node: ast.AST,
    *,
    aliases: _RequestStateAliasEnv | None = None,
) -> str | None:
    """Return governed field name for a store target, or None.

    Without ``aliases``, only exact ``request.state.<field>`` matches (legacy).
    With ``aliases``, plausible ``*.state.<field>`` and state-alias stores are
    included so writers cannot be omitted from closed-world accounting.
    """

    env = aliases or _RequestStateAliasEnv(request_names={"request"}, state_names=set())
    field, exact = env.field_from_assign_target(node)
    if field is None or field.startswith("__"):
        return None
    if aliases is None:
        return field if exact else None
    return field


def _is_request_state_setattr_call(
    node: ast.Call,
    *,
    aliases: _RequestStateAliasEnv | None = None,
) -> tuple[bool, bool]:
    """Return ``(is_setattr_on_state, supported_alias)``.

    ``supported_alias`` is True only for the exact/alias theorem; False means
    a plausible state setattr that must still poison closed-world UNKNOWN.
    """

    env = aliases or _RequestStateAliasEnv(request_names={"request"}, state_names=set())

    def _state_arg(arg: ast.AST) -> tuple[bool, bool]:
        if env._is_state_expr(arg):
            return True, True
        if (
            isinstance(arg, ast.Attribute)
            and arg.attr == "state"
            and isinstance(arg.value, ast.Name)
        ):
            if arg.value.id in env.request_names:
                return True, True
            return True, False
        if isinstance(arg, ast.Name) and arg.id in env.state_names:
            return True, True
        return False, False

    if isinstance(node.func, ast.Name) and node.func.id == "setattr" and len(node.args) >= 3:
        return _state_arg(node.args[0])
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "__setattr__"
        and len(node.args) >= 2
    ):
        # request.state.__setattr__(name, value) / state.__setattr__(...)
        is_state, exact = _state_arg(node.func.value)
        if is_state:
            return True, exact
        # object.__setattr__(request.state, name, value)
        if (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "object"
            and len(node.args) >= 3
        ):
            return _state_arg(node.args[0])
    return False, False


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
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "__setattr__"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id != "object"
    ):
        # state.__setattr__(name, value)
        return node.args[0], node.args[1]
    # object.__setattr__(request.state, name, value)
    return node.args[1], node.args[2]


def _function_param_names(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...]:
    names: list[str] = []
    for arg in list(fn.args.posonlyargs) + list(fn.args.args):
        if arg.arg in {"self", "cls"}:
            continue
        names.append(arg.arg)
    for arg in fn.args.kwonlyargs:
        names.append(arg.arg)
    return tuple(names)


def _bind_call_actuals(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
) -> dict[str, ast.AST] | None:
    """Map callee formals to call actuals under the ordinary-argument theorem.

    Returns None when *args/**kwargs, unexpected keywords, or arity mismatch
    make the binding unresolvable (escape → UNKNOWN).
    """

    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    if any(kw.arg is None for kw in call.keywords):
        return None
    if fn.args.vararg is not None or fn.args.kwarg is not None:
        return None

    formals = _function_param_names(fn)
    binding: dict[str, ast.AST] = {}
    if len(call.args) > len(formals):
        return None
    for index, actual in enumerate(call.args):
        binding[formals[index]] = actual
    formal_set = set(formals)
    for kw in call.keywords:
        assert kw.arg is not None
        if kw.arg not in formal_set:
            return None
        if kw.arg in binding:
            return None
        binding[kw.arg] = kw.value
    return binding


def _collect_writes_in_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    path: str,
    handler_param_names: frozenset[str],
    callee_resolver: CalleeResolver | None = None,
    seed_request_aliases: _RequestStateAliasEnv | None = None,
    seed_alias_state: AliasState | None = None,
    call_stack: frozenset[tuple[str, str]] | None = None,
    depth: int = 0,
) -> list[StateAttributeWrite]:
    """Collect state writes under statement-order alias tracking.

    Provenance for ``request.state.f = x`` survives when ``x`` is a simple
    rebinding of an HTTP param / config / literal / request.state attribute.
    Nested compound statements are visited so branch-local overwrites cannot
    disappear from closed-world accounting.

    Request/state name aliases (``req = request``, ``state = request.state``)
    participate in the supported write theorem. Other ``*.state.<field>``
    mutations are still recorded (as dynamic) so they cannot be omitted.

    Escape analysis (#156): passing request/request.state into an unresolved
    callee, unresolved ``__dict__`` / ``vars(state)`` stores, and similar
    mutation channels force dynamic wildcard writes (Unknown > false PASS)
    unless a bounded interprocedural theorem resolves the callee under
    caller-relative module-qualified identity (#160).
    """

    writes: list[StateAttributeWrite] = []
    alias_state = seed_alias_state if seed_alias_state is not None else AliasState()
    fn_params = frozenset(_function_param_names(fn))
    if seed_request_aliases is not None:
        request_aliases = seed_request_aliases
    else:
        request_aliases = _RequestStateAliasEnv.seed(param_names=fn_params)
    stack = call_stack or frozenset()
    frame = (_normalize_unit_path(path), fn.name)

    def _classify(node: ast.AST) -> ValueOriginEvidence:
        return classify_expression_origin(
            node,
            path=path,
            handler_param_names=handler_param_names,
            alias_state=alias_state,
        )

    def _record_escape(
        node: ast.AST,
        expression: str,
        *,
        control_dependent: bool,
    ) -> None:
        writes.append(
            StateAttributeWrite(
                field_name="__wildcard__",
                value_expression=expression,
                origin=_classify(node),
                dynamic=True,
                source_range=_origin(path, node).source_range,
                path=path,
                control_dependent=control_dependent,
            )
        )

    def _record_assign_target(
        target: ast.AST,
        value: ast.AST,
        statement: ast.stmt,
        *,
        dynamic: bool,
        control_dependent: bool,
    ) -> None:
        if request_aliases.is_poison_state_store(target):
            _record_escape(
                statement,
                ast.unparse(statement),
                control_dependent=control_dependent,
            )
            return
        if request_aliases.assignment_escapes_state_identity(target, value):
            _record_escape(
                statement,
                ast.unparse(statement),
                control_dependent=control_dependent,
            )
            return
        field, exact = request_aliases.field_from_assign_target(target)
        if field is None:
            return
        writes.append(
            StateAttributeWrite(
                field_name=field,
                value_expression=ast.unparse(value),
                origin=_classify(value),
                dynamic=dynamic or (not exact) or field.startswith("__"),
                source_range=_origin(path, statement).source_range,
                path=path,
                control_dependent=control_dependent,
            )
        )

    def _try_interprocedural(
        call: ast.Call,
        *,
        control_dependent: bool,
    ) -> bool:
        """Resolve a caller-relative callee that receives request/state."""

        if callee_resolver is None:
            return False
        if depth >= _MAX_INTERPROCEDURAL_WRITER_DEPTH:
            return False
        # Nested defs/params/stores shadow module bindings for Name callees.
        shadowed: set[str] = set(fn_params)
        for node in ast.walk(fn):
            if node is fn:
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                shadowed.add(node.id)
            elif isinstance(node, ast.arg):
                shadowed.add(node.arg)
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                shadowed.add(node.name)
        result = callee_resolver.resolve_call(
            call.func,
            caller_path=path,
            shadowed_names=frozenset(shadowed),
        )
        if result.callee is None:
            return False
        resolved = result.callee
        callee_frame = (_normalize_unit_path(resolved.path), resolved.node.name)
        if callee_frame in stack or callee_frame == frame:
            return False
        binding = _bind_call_actuals(resolved.node, call)
        if binding is None:
            return False
        carries_identity = any(
            request_aliases.is_request_or_state_expr(actual)
            for actual in binding.values()
        )
        if not carries_identity:
            return False

        callee_aliases = _RequestStateAliasEnv.seed(param_names=frozenset())
        callee_alias_state = AliasState()
        for formal, actual in binding.items():
            if request_aliases._is_request_expr(actual):
                callee_aliases.request_names.add(formal)
            elif request_aliases._is_state_expr(actual):
                callee_aliases.state_names.add(formal)
            # Propagate value-origin evidence through formals.
            origin = _classify(actual)
            callee_alias_state.bind(formal, origin)

        collected = _collect_writes_in_function(
            resolved.node,
            path=resolved.path,
            handler_param_names=handler_param_names,
            callee_resolver=callee_resolver,
            seed_request_aliases=callee_aliases,
            seed_alias_state=callee_alias_state,
            call_stack=stack | {frame},
            depth=depth + 1,
        )
        if control_dependent:
            collected = [
                StateAttributeWrite(
                    field_name=item.field_name,
                    value_expression=item.value_expression,
                    origin=item.origin,
                    dynamic=item.dynamic,
                    source_range=item.source_range,
                    path=item.path,
                    control_dependent=True,
                )
                for item in collected
            ]
        writes.extend(collected)
        return True

    def _call_receives_request_or_state(call: ast.Call) -> bool:
        return request_aliases.call_receives_request_or_state(call)

    def _record_dynamic_calls(
        statement: ast.stmt,
        *,
        control_dependent: bool,
    ) -> None:
        for node in ast.walk(statement):
            if not isinstance(node, ast.Call):
                continue
            is_setattr, _exact = _is_request_state_setattr_call(
                node, aliases=request_aliases
            )
            if is_setattr:
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
                        control_dependent=control_dependent,
                    )
                )
                continue
            rendered = ast.unparse(node)
            state_markers = (
                ["request.state"]
                + [f"{name}.state" for name in sorted(request_aliases.request_names)]
                + sorted(request_aliases.state_names)
            )
            if any(marker in rendered for marker in state_markers) and any(
                token in rendered
                for token in ("update(", "copy(", "__dict__", "vars(")
            ):
                _record_escape(
                    node,
                    rendered,
                    control_dependent=control_dependent,
                )
                continue
            # Escape: request/state flows into a call. Resolve local callees
            # under the bounded interprocedural theorem; otherwise UNKNOWN.
            if _call_receives_request_or_state(node):
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in _NON_MUTATING_STATE_OBSERVERS
                ):
                    continue
                if _try_interprocedural(node, control_dependent=control_dependent):
                    continue
                _record_escape(
                    node,
                    rendered,
                    control_dependent=control_dependent,
                )

    def _note_alias_bindings(statement: ast.stmt) -> None:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                request_aliases.note_binding(target, statement.value)
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            request_aliases.note_binding(statement.target, statement.value)

    def _note_named_expr_bindings(
        node: ast.AST, *, control_dependent: bool
    ) -> None:
        for child in ast.walk(node):
            if not isinstance(child, ast.NamedExpr):
                continue
            request_aliases.note_binding(child.target, child.value)
            if request_aliases.assignment_escapes_state_identity(
                child.target, child.value
            ):
                _record_escape(
                    child,
                    ast.unparse(child),
                    control_dependent=control_dependent,
                )

    def _visit_statement(
        statement: ast.stmt,
        *,
        control_dependent: bool = False,
    ) -> None:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                _record_assign_target(
                    target,
                    statement.value,
                    statement,
                    dynamic=False,
                    control_dependent=control_dependent,
                )
            # Calls on the RHS may escape request/state even when the store is
            # a simple Name alias (alias noted below; escape still recorded).
            if isinstance(statement.value, ast.Call) or any(
                isinstance(child, ast.Call) for child in ast.walk(statement.value)
            ):
                _record_dynamic_calls(
                    statement,
                    control_dependent=control_dependent,
                )
            if request_aliases.expression_escapes_state_identity(statement.value):
                _record_escape(
                    statement,
                    ast.unparse(statement),
                    control_dependent=control_dependent,
                )
            _note_named_expr_bindings(
                statement.value, control_dependent=control_dependent
            )
            _note_alias_bindings(statement)
            apply_statement_bindings(
                statement,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            return

        if isinstance(statement, ast.AnnAssign) and statement.value is not None:
            _record_assign_target(
                statement.target,
                statement.value,
                statement,
                dynamic=False,
                control_dependent=control_dependent,
            )
            if isinstance(statement.value, ast.Call) or any(
                isinstance(child, ast.Call) for child in ast.walk(statement.value)
            ):
                _record_dynamic_calls(
                    statement,
                    control_dependent=control_dependent,
                )
            if request_aliases.expression_escapes_state_identity(statement.value):
                _record_escape(
                    statement,
                    ast.unparse(statement),
                    control_dependent=control_dependent,
                )
            _note_named_expr_bindings(
                statement.value, control_dependent=control_dependent
            )
            _note_alias_bindings(statement)
            apply_statement_bindings(
                statement,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            return

        if isinstance(statement, ast.AugAssign):
            _record_assign_target(
                statement.target,
                statement.value,
                statement,
                dynamic=True,
                control_dependent=control_dependent,
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
                _visit_statement(child, control_dependent=True)
            for name in assigned_on_branches:
                alias_state.poison(name)
            request_aliases.poison_names(assigned_on_branches)
            return

        if isinstance(statement, (ast.For, ast.AsyncFor)):
            _mark_name_uses(statement.iter, alias_state)
            # ``for s in [request.state]: s.field = client`` must not authorize.
            if (
                request_aliases.is_request_or_state_expr(statement.iter)
                or request_aliases.packs_request_or_state_identity(statement.iter)
                or request_aliases.is_state_dict_surface(statement.iter)
                or request_aliases.expression_escapes_state_identity(statement.iter)
            ):
                _record_escape(
                    statement,
                    ast.unparse(statement),
                    control_dependent=True,
                )
            assigned = _collect_assigned_names_in_statements(
                list(statement.body) + list(statement.orelse)
            )
            assigned.update(_collect_assign_target_names(statement.target))
            for child in list(statement.body) + list(statement.orelse):
                _visit_statement(child, control_dependent=True)
            for name in assigned:
                alias_state.poison(name)
            request_aliases.poison_names(assigned)
            return

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            assigned = _collect_assigned_names_in_statements(list(statement.body))
            for item in statement.items:
                _mark_name_uses(item.context_expr, alias_state)
                if item.optional_vars is not None:
                    assigned.update(_collect_assign_target_names(item.optional_vars))
            for child in statement.body:
                _visit_statement(
                    child,
                    control_dependent=control_dependent,
                )
            for name in assigned:
                alias_state.poison(name)
            request_aliases.poison_names(assigned)
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
                _visit_statement(child, control_dependent=True)
            for handler in statement.handlers:
                for child in handler.body:
                    _visit_statement(child, control_dependent=True)
            for child in list(statement.orelse) + list(statement.finalbody):
                _visit_statement(child, control_dependent=True)
            for name in assigned:
                alias_state.poison(name)
            request_aliases.poison_names(assigned)
            return

        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Nested writers must be accounted; omission beside a trusted
            # literal would otherwise false-PASS closed-world authority.
            writes.extend(
                _collect_writes_in_function(
                    statement,
                    path=path,
                    handler_param_names=frozenset(),
                    callee_resolver=callee_resolver,
                    call_stack=stack | {frame},
                    depth=depth,
                )
            )
            return

        if isinstance(statement, ast.ClassDef):
            for child in statement.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    writes.extend(
                        _collect_writes_in_function(
                            child,
                            path=path,
                            handler_param_names=frozenset(),
                            callee_resolver=callee_resolver,
                            call_stack=stack | {frame},
                            depth=depth,
                        )
                    )
            return

        if isinstance(statement, ast.Return) and statement.value is not None:
            # Returning request.state escapes state identity into an unresolved
            # caller theorem → UNKNOWN. Bare ``return request`` is not itself a
            # state mutation channel under this bounded escape relation.
            if request_aliases._is_state_expr(statement.value):
                _record_escape(
                    statement,
                    ast.unparse(statement),
                    control_dependent=control_dependent,
                )
            if request_aliases.expression_escapes_state_identity(statement.value):
                _record_escape(
                    statement,
                    ast.unparse(statement),
                    control_dependent=control_dependent,
                )
            _note_named_expr_bindings(
                statement.value, control_dependent=control_dependent
            )
            _record_dynamic_calls(
                statement,
                control_dependent=control_dependent,
            )
            apply_statement_bindings(
                statement,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            return

        if isinstance(statement, ast.Expr):
            if request_aliases.expression_escapes_state_identity(statement.value):
                _record_escape(
                    statement,
                    ast.unparse(statement),
                    control_dependent=control_dependent,
                )
            _note_named_expr_bindings(
                statement.value, control_dependent=control_dependent
            )

        # Ordinary statements: setattr / escape / interprocedural calls.
        _record_dynamic_calls(
            statement,
            control_dependent=control_dependent,
        )
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
    externally_bound_function_name: str | None,
    callee_resolver: CalleeResolver | None = None,
) -> tuple[StateAttributeWrite, ...]:
    writes: list[StateAttributeWrite] = []
    # Prefer per-function alias tracking so rebinding inside a writer is proved.
    # Class methods are writers too; omitting them beside a trusted literal
    # false-PASSes closed-world authority.
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node)
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(child)
                elif isinstance(child, ast.ClassDef):
                    for nested in child.body:
                        if isinstance(nested, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            functions.append(nested)
    if functions:
        for fn in functions:
            fn_param_names = frozenset(_function_param_names(fn))
            writes.extend(
                _collect_writes_in_function(
                    fn,
                    path=path,
                    handler_param_names=(
                        fn_param_names
                        if fn.name == externally_bound_function_name
                        else frozenset()
                    ),
                    callee_resolver=callee_resolver,
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
            request_aliases = _RequestStateAliasEnv.seed(param_names=frozenset())
            for statement in module_level:
                if isinstance(statement, ast.Assign):
                    for target in statement.targets:
                        field, exact = request_aliases.field_from_assign_target(target)
                        if field is None:
                            continue
                        writes.append(
                            StateAttributeWrite(
                                field_name=field,
                                value_expression=ast.unparse(statement.value),
                                origin=classify_expression_origin(
                                    statement.value,
                                    path=path,
                                    handler_param_names=frozenset(),
                                    alias_state=alias_state,
                                ),
                                dynamic=(not exact) or field.startswith("__"),
                                source_range=_origin(path, statement).source_range,
                                path=path,
                            )
                        )
                    for target in statement.targets:
                        request_aliases.note_binding(target, statement.value)
                    apply_statement_bindings(
                        statement,
                        path=path,
                        handler_param_names=frozenset(),
                        alias_state=alias_state,
                    )
        return tuple(writes)

    # Fallback: whole-tree walk without function grouping.
    request_aliases = _RequestStateAliasEnv.seed(param_names=frozenset())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                field, exact = request_aliases.field_from_assign_target(target)
                if field is None:
                    continue
                origin = classify_expression_origin(
                    node.value,
                    path=path,
                    handler_param_names=frozenset(),
                )
                writes.append(
                    StateAttributeWrite(
                        field_name=field,
                        value_expression=ast.unparse(node.value),
                        origin=origin,
                        dynamic=(not exact) or field.startswith("__"),
                        source_range=_origin(path, node).source_range,
                        path=path,
                    )
                )
            for target in node.targets:
                request_aliases.note_binding(target, node.value)
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


def _normalize_source_root(root: str) -> str:
    normalized = _normalize_unit_path(root).strip("/")
    return "" if normalized in {"", "."} else normalized


def _path_relative_to_root(path: str, root: str) -> str | None:
    root = _normalize_source_root(root)
    if not root:
        return path
    prefix = root + "/"
    if not path.startswith(prefix):
        return None
    return path[len(prefix):]


def _module_candidates_in_manifest(
    module: str,
    available_paths: set[str],
) -> tuple[str, ...]:
    """Locate repository paths that could bind an absolute import.

    Searches the complete authenticated Python manifest for
    ``*/<module/path>.py`` and ``*/<module/path>/__init__.py`` without
    encoding conventional source-root names (backend/src). Exactly one
    candidate establishes a local binding; multiple mean ambiguity;
    none means external *unless* the import is relative or the top-level
    name already appears as a local package path in the manifest.
    """

    stem = module.replace(".", "/")
    wanted = (f"{stem}.py", f"{stem}/__init__.py")
    found: set[str] = set()
    for path in available_paths:
        for suffix in wanted:
            if path == suffix or path.endswith("/" + suffix):
                found.add(path)
                break
    return tuple(sorted(found))


def _top_level_appears_local(top: str, available_paths: set[str]) -> bool:
    """True when ``top`` already names a path segment under the manifest.

    Used so ``from app.missing import ...`` cannot be classified external
    when ``app/...`` paths are present (Unknown > false PASS).
    """

    if not top or "." in top:
        return False
    for path in available_paths:
        if path == f"{top}.py" or path.startswith(f"{top}/"):
            return True
        if f"/{top}/" in f"/{path}/" or path.endswith(f"/{top}.py"):
            return True
    return False


def _module_path_in_unit(
    module: str,
    *,
    available_paths: set[str],
    source_roots: tuple[str, ...] | None = None,
) -> str | None:
    """Resolve an absolute module name from the complete manifest.

    ``source_roots`` is retained for call-site compatibility but is not used
    by the security theorem (#155).
    """

    del source_roots  # security theorem is manifest-complete, not root-special-cased
    candidates = _module_candidates_in_manifest(module, available_paths)
    return candidates[0] if len(candidates) == 1 else None


def _import_module_name_from_importer(
    node: ast.ImportFrom,
    *,
    importer_path: str,
) -> str | None:
    """Resolve ImportFrom to an absolute module name from the importer path."""

    if not node.level or node.level <= 0:
        return node.module

    importer = _normalize_unit_path(importer_path)
    parts = importer.split("/")
    if not parts:
        return None
    if parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    else:
        parts = parts[:-1]
    if node.level - 1 > len(parts):
        return None
    if node.level > 1:
        parts = parts[: -(node.level - 1)]
    if node.module:
        parts = list(parts) + node.module.split(".")
    return ".".join(parts) if parts else None


def _import_module_name(
    node: ast.ImportFrom,
    *,
    importer_path: str,
    source_roots: tuple[str, ...] | None = None,
) -> str | None:
    """Resolve ImportFrom to an import-space module name."""

    del source_roots
    return _import_module_name_from_importer(node, importer_path=importer_path)


def _evaluate_closed_world(
    files: Mapping[str, str],
    *,
    scope_proof: ClosedWorldScopeProof | None,
) -> ClosedWorldCondition:
    """Verify the declared repository writer scope and its local imports."""

    available = {_normalize_unit_path(path) for path in files}
    accounted = tuple(sorted(available))

    if scope_proof is None:
        return ClosedWorldCondition(
            complete=False,
            accounted_paths=accounted,
            source_roots=(),
            unresolvable_imports=("scope_proof_missing",),
            reason="closed_world_scope_proof_missing",
        )

    proof_paths = {
        _normalize_unit_path(path)
        for path in scope_proof.accounted_paths
    }
    source_roots = tuple(
        sorted({_normalize_source_root(root) for root in scope_proof.source_roots})
    )
    scope_errors: list[str] = []
    if proof_paths != available:
        for missing in sorted(proof_paths - available):
            scope_errors.append(f"scope_path_missing:{missing}")
        for extra in sorted(available - proof_paths):
            scope_errors.append(f"scope_path_unaccounted:{extra}")
    if not source_roots:
        scope_errors.append("source_roots_missing")
    for path in sorted(available):
        if not any(
            _path_relative_to_root(path, root) is not None
            for root in source_roots
        ):
            scope_errors.append(f"path_outside_source_roots:{path}")

    if scope_errors:
        return ClosedWorldCondition(
            complete=False,
            accounted_paths=accounted,
            source_roots=source_roots,
            unresolvable_imports=tuple(sorted(set(scope_errors))),
            reason="closed_world_scope_proof_mismatch",
        )

    unresolvable: list[str] = []

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
                module_name = _import_module_name(
                    node,
                    importer_path=norm,
                    source_roots=source_roots,
                )
                if module_name is None:
                    unresolvable.append(f"{norm}:unresolved_relative_import")
                    continue
                candidates = _module_candidates_in_manifest(module_name, available)
                if len(candidates) == 0:
                    # Relative imports are always repository-local. Absolute
                    # imports whose top-level name already appears under the
                    # manifest are also local misses — never external.
                    relative = bool(node.level and node.level > 0)
                    top = module_name.split(".", 1)[0]
                    if relative or _top_level_appears_local(top, available):
                        kind = (
                            "unresolvable_relative_import"
                            if relative
                            else "unresolvable_local_import"
                        )
                        unresolvable.append(f"{norm}:{kind}:{module_name}")
                    # else: true external (pip/stdlib) — ignore
                    continue
                if len(candidates) > 1:
                    unresolvable.append(
                        f"{norm}:ambiguous_local_import:{module_name}"
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    candidates = _module_candidates_in_manifest(
                        alias.name, available
                    )
                    if len(candidates) == 0:
                        top = alias.name.split(".", 1)[0]
                        if _top_level_appears_local(top, available):
                            unresolvable.append(
                                f"{norm}:unresolvable_local_import:{alias.name}"
                            )
                        continue
                    if len(candidates) > 1:
                        unresolvable.append(
                            f"{norm}:ambiguous_local_import:{alias.name}"
                        )

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
    return ClosedWorldCondition(
        complete=complete,
        accounted_paths=accounted,
        source_roots=source_roots,
        unresolvable_imports=tuple(sorted(set(unresolvable))),
        reason=(
            "closed_world_complete_over_proved_scope"
            if complete
            else "closed_world_incomplete_unresolvable_imports"
        ),
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

        if any(item.control_dependent for item in field_writes):
            _emit(
                "unknown",
                "control_dependent_state_mutation",
                write_count=len(field_writes),
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
    scope_proof: ClosedWorldScopeProof | None = None,
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

    closed_world = _evaluate_closed_world(
        normalized,
        scope_proof=scope_proof,
    )

    trees: dict[str, ast.AST] = {}
    for path, source in sorted(normalized.items()):
        trees[path] = ast.parse(source, filename=path)
    callee_resolver = build_callee_resolver(trees)

    entry_tree = trees[entry]
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

    # Only the selected HTTP entry handler receives externally-bound parameter
    # semantics. Parameters of helpers/middleware in other functions remain
    # unresolved until an interprocedural caller-provenance theorem establishes
    # their origin.
    all_writes: list[StateAttributeWrite] = []
    for path, tree in sorted(trees.items()):
        all_writes.extend(
            _collect_state_writes(
                tree,
                path=path,
                externally_bound_function_name=(
                    handler.name if handler is not None and path == entry else None
                ),
                callee_resolver=callee_resolver,
            )
        )
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
    scope_proof: ClosedWorldScopeProof | None = None,
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
        scope_proof=scope_proof,
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
                        "source_roots": list(item.closed_world.source_roots),
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
