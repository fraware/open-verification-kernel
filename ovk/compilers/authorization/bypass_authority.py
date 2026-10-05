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
from dataclasses import dataclass, field as dc_field
from typing import Literal, Mapping, Sequence

from ovk.compilers.authorization.python_callee_resolution import (
    CalleeResolver,
    RequestTimeIdentitySession,
    RequestTimeIdentityState,
    begin_request_time_identity_session,
    build_callee_resolver,
    import_module_name_from_importer,
    _nullcontext_enter_arg,
)
from ovk.compilers.authorization.python_import_space import (
    module_candidates_in_manifest,
    normalize_import_roots,
    top_level_appears_local,
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
    scope. source_roots are path-accounting roots (membership only).
    python_import_roots are trusted import-space roots for the shared module
    identity theorem (#161); empty means only exact repo-root paths and
    relative imports are import-grounded.
    """

    accounted_paths: tuple[str, ...]
    source_roots: tuple[str, ...]
    python_import_roots: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClosedWorldCondition:
    """Explicit closed-world accounting status for one analysis unit."""

    complete: bool
    accounted_paths: tuple[str, ...]
    source_roots: tuple[str, ...]
    unresolvable_imports: tuple[str, ...]
    reason: str
    python_import_roots: tuple[str, ...] = ()


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


_BYPASS_AUTHORITY_EXTRACTOR_VERSION = "0.42.0"
_MAX_INTERPROCEDURAL_WRITER_DEPTH = 4
_STATE_DICT_ATTRS = frozenset({"__dict__", "__slots__"})

# Container view / adapter surfaces that project packed request/state identity
# without a Name-alias bind (Unknown > false PASS on omitted client writes).
_CONTAINER_VIEW_ATTRS = frozenset(
    {
        "values",
        "keys",
        "items",
        "get",
        "pop",
        "popitem",
        "setdefault",
        "__getitem__",
    }
)
_CONTAINER_ADAPTER_NAMES = frozenset(
    {
        "list",
        "tuple",
        "set",
        "frozenset",
        "sorted",
        "reversed",
        "iter",
        "next",
        "map",
        "filter",
        "MappingProxyType",
    }
)
# Namespace / mapping view attrs that project key→value like ``.get``.
_NS_DICT_VIEW_ATTRS = frozenset({"get", "pop", "__getitem__", "setdefault"})
# Bound mutators Name-seeded like views: ``si=keys.__setitem__`` /
# ``si=getattr(keys,"__setitem__")`` (Unknown > false PASS).
_NS_DICT_MUTATOR_ATTRS = frozenset({"__setitem__", "update", "setdefault"})
_DICT_ITER_VIEW_ATTRS = frozenset({"keys", "values", "items", "popitem"})
# operator.* / unbound projection names that yield packed request/state identity.
# Includes mutation / merge factories so Assign-RHS / packed peels share one
# path with bare ``operator.setitem`` / ``operator.ior`` (Unknown > false PASS).
_OPERATOR_PROJECTION_ATTRS = frozenset(
    {
        "getitem",
        "setitem",
        "itemgetter",
        "attrgetter",
        "methodcaller",
        "call",
        "ior",
        "or_",
        "iadd",
        "iconcat",
        "copy",
        "deepcopy",
    }
)
_OPERATOR_PROJECTION_NAMES = frozenset(
    {
        "getitem",
        "setitem",
        "itemgetter",
        "attrgetter",
        "methodcaller",
        "call",
        "ior",
        "or_",
        "iadd",
        "iconcat",
        "copy",
        "deepcopy",
    }
)
# Builtin key applicators Name-bound like ``srt=sorted`` / ``mx=max`` —
# shared with python_callee_resolution peels (Unknown > false PASS).
_KEY_APPLICATOR_NAMES = frozenset({"sorted", "max", "min", "reduce"})
_PROJECTION_DUNDER_ALIASES = {
    "__ior__": "ior",
    "__or__": "or_",
    "__iadd__": "iadd",
    "__iconcat__": "iconcat",
    "__setitem__": "setitem",
    "__getitem__": "getitem",
}


def _match_pattern_attribute_targets(pattern: ast.AST) -> list[ast.Attribute]:
    """Attribute MatchValue nodes treated as fail-closed export stores."""

    found: list[ast.Attribute] = []

    def _walk(pat: ast.AST) -> None:
        if isinstance(pat, ast.MatchValue) and isinstance(pat.value, ast.Attribute):
            found.append(pat.value)
            return
        if isinstance(pat, ast.MatchAs):
            if pat.pattern is not None:
                _walk(pat.pattern)
            return
        if isinstance(pat, ast.MatchOr):
            for alt in pat.patterns:
                _walk(alt)
            return
        if isinstance(pat, ast.MatchSequence):
            for sub in pat.patterns:
                _walk(sub)
            return
        if isinstance(pat, ast.MatchMapping):
            for sub in pat.patterns:
                _walk(sub)
            return
        if isinstance(pat, ast.MatchClass):
            for sub in pat.patterns:
                _walk(sub)
            for sub in pat.kwd_patterns:
                _walk(sub)

    _walk(pattern)
    return found


def _assign_target_has_attr_or_subscript(target: ast.AST) -> bool:
    """True when a for/with/assign target stores through Attribute or Subscript.

    Recurses through Tuple/List/Starred unpack forms so
    ``for (helpers.write_state,) in …`` observes export rebind like Assign.
    """

    if isinstance(target, (ast.Attribute, ast.Subscript)):
        return True
    if isinstance(target, ast.Starred):
        return _assign_target_has_attr_or_subscript(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_assign_target_has_attr_or_subscript(elt) for elt in target.elts)
    return False

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


@dataclass(frozen=True)
class AliasClassification:
    """Independent must/may request and state facts for one expression.

    A single name may be may-request and may-state simultaneously after a
    cross-kind CF join. Facts are transferred independently (not if/elif) so
    interprocedural formals and local rebinds preserve strength (#171 lattice).

    Expression-level IfExp / BoolOp joins use the same lattice: union of may
    facts; must only when every arm agrees on the same exact kind.
    """

    must_request: bool = False
    may_request: bool = False
    must_state: bool = False
    may_state: bool = False

    @property
    def any_alias(self) -> bool:
        return (
            self.must_request
            or self.may_request
            or self.must_state
            or self.may_state
        )

    def as_may_only(self) -> "AliasClassification":
        """Weaken must facts to may (uncertain binders / ``with`` enter results)."""

        return AliasClassification(
            must_request=False,
            may_request=self.must_request or self.may_request,
            must_state=False,
            may_state=self.must_state or self.may_state,
        )

    @staticmethod
    def join(
        left: "AliasClassification", right: "AliasClassification"
    ) -> "AliasClassification":
        """Join two expression classifications (IfExp / BoolOp arms).

        Mirrors ``join_request_state_alias_envs`` for a single binding: must is
        intersection; may is union of (must ∪ may) minus the resulting must.
        Cross-kind disagreement yields dual may — never poison.
        """

        must_request = left.must_request and right.must_request
        must_state = left.must_state and right.must_state
        may_request = (
            left.must_request
            or left.may_request
            or right.must_request
            or right.may_request
        ) and not must_request
        may_state = (
            left.must_state
            or left.may_state
            or right.must_state
            or right.may_state
        ) and not must_state
        return AliasClassification(
            must_request=must_request,
            may_request=may_request,
            must_state=must_state,
            may_state=may_state,
        )

    @staticmethod
    def join_all(
        parts: Sequence["AliasClassification"],
    ) -> "AliasClassification":
        """Fold ``join`` across one or more classifications (empty → bottom)."""

        if not parts:
            return AliasClassification()
        acc = parts[0]
        for part in parts[1:]:
            acc = AliasClassification.join(acc, part)
        return acc


@dataclass
class _RequestStateAliasEnv:
    """Track names proved to alias ``request`` or ``request.state`` (#153/#171).

    Seeded with the literal parameter/name ``request``. Assignments such as
    ``req = request`` and ``state = request.state`` extend the supported alias
    theorem. Any other ``*.state.<field>`` mutation is still recorded so it
    cannot be omitted from closed-world accounting (Unknown > false PASS).

    Control-flow join (#171) distinguishes must-alias vs may-alias:
    - write through must-alias → exact theorem
    - write through may-alias → recorded dynamic/uncertain (no positive authority)
    Feasible predecessors are forked and joined so branch-local rebinding cannot
    erase writes that remain reachable on other predecessors.

    Cross-kind disagreement (request on one predecessor, state on another) keeps
    the name in both may sets — deleting it would omit governed writes.
    """

    request_names: set[str]
    state_names: set[str]
    may_request_names: set[str] = dc_field(default_factory=set)
    may_state_names: set[str] = dc_field(default_factory=set)
    # ``from types import MappingProxyType as MPT`` / ``from operator import getitem as gi``.
    adapter_aliases: set[str] = dc_field(default_factory=set)
    # Name-bound container packs projecting adapters: ``d = {"p": Proxy}``.
    container_adapter_packs: dict[str, dict[object, tuple[str, ...]]] = dc_field(
        default_factory=dict
    )
    operator_projection_aliases: dict[str, str] = dc_field(default_factory=dict)
    # Renamed ``vars`` / ``globals`` / ``locals`` namespace projectors.
    ns_projection_aliases: set[str] = dc_field(default_factory=set)
    # Name-bound namespace projections: ``ns = types.__dict__`` / ``ns = vars(types)``.
    ns_dict_names: set[str] = dc_field(default_factory=set)
    # Name-bound static string keys: ``k = "MappingProxyType"``.
    string_constant_names: dict[str, str] = dc_field(default_factory=dict)
    # Name-bound static Constant keys (int/str/…): ``idx = 0`` / ``xk = "x"``.
    static_constant_names: dict[str, object] = dc_field(default_factory=dict)
    # Bound ns/dict views: ``g = getattr(ns, "get")`` / ``g = ns.get``.
    dict_view_products: dict[str, str] = dc_field(default_factory=dict)
    bound_view_receivers: dict[str, str] = dc_field(default_factory=dict)
    # Non-Name receivers: ``g = getattr([partial(copy.copy)], "pop")``.
    bound_view_expr_receivers: dict[str, ast.AST] = dc_field(default_factory=dict)
    nullcontext_aliases: set[str] = dc_field(
        default_factory=lambda: {"nullcontext"}
    )
    # Name-bound string lists: ``keys=["MappingProxyType"]`` for ``keys[0]``.
    sequence_string_lists: dict[str, tuple[str, ...]] = dc_field(
        default_factory=dict
    )
    # Name-bound List/Tuple/Dict literals for nested / Call key peels.
    sequence_literal_aliases: dict[str, ast.AST] = dc_field(default_factory=dict)
    # Name-bound ``ig = itemgetter("x")`` → static key payload.
    itemgetter_products: dict[str, object] = dc_field(default_factory=dict)
    # Name-bound ``mc = methodcaller("__setitem__", …)`` factory Calls.
    methodcaller_factories: dict[str, ast.Call] = dc_field(default_factory=dict)
    # Name-bound ``p = partial(copy.copy, keys)`` factory Calls.
    partial_factories: dict[str, ast.Call] = dc_field(default_factory=dict)

    @classmethod
    def seed(cls, *, param_names: frozenset[str]) -> "_RequestStateAliasEnv":
        request_names = {"request"} if "request" in param_names else set()
        # Module-level walks may have no params; still recognize bare ``request``.
        if not param_names:
            request_names.add("request")
        return cls(request_names=set(request_names), state_names=set())

    @classmethod
    def empty(cls) -> "_RequestStateAliasEnv":
        """Empty alias env for nested/interprocedural seeding (no bare request)."""

        return cls(request_names=set(), state_names=set())

    def classification_for_name(self, name: str) -> AliasClassification:
        """Must/may request/state facts currently recorded for ``name``."""

        return AliasClassification(
            must_request=name in self.request_names,
            may_request=name in self.may_request_names,
            must_state=name in self.state_names,
            may_state=name in self.may_state_names,
        )

    def note_projection_import(self, node: ast.Import | ast.ImportFrom) -> None:
        """Track renamed MappingProxyType / operator projection imports."""

        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name == "MappingProxyType":
                    self.adapter_aliases.add(local)
                elif alias.name == "nullcontext":
                    self.nullcontext_aliases.add(local)
                elif alias.name in _OPERATOR_PROJECTION_NAMES | _KEY_APPLICATOR_NAMES:
                    self.operator_projection_aliases[local] = alias.name
                elif alias.name in {"vars", "globals", "locals"}:
                    self.ns_projection_aliases.add(local)
        elif isinstance(node, ast.Import):
            return

    def _base_is_namespace_projection(
        self,
        base: ast.AST,
        *,
        getattr_aliases: frozenset[str],
    ) -> bool:
        """True for ``types.__dict__`` / ``vars(types)`` / ``getattr(..., "__dict__")``.

        Shared peel with callee resolution so copy / dict / MappingProxyType /
        packed wrappers of ``vars(builtins)`` seed ns aliases (Unknown >
        false PASS).
        """

        from ovk.compilers.authorization.python_callee_resolution import (
            _base_looks_like_namespace_mapping,
            _copy_wrapper_operand,
            _peel_call_func,
        )

        while isinstance(base, ast.NamedExpr):
            base = base.value
        copy_inner = _copy_wrapper_operand(base)
        if copy_inner is not None:
            base = _peel_call_func(copy_inner)
        if _base_looks_like_namespace_mapping(
            base,
            getattr_aliases=getattr_aliases,
            ns_mapping_names=frozenset(self.ns_dict_names),
            sequence_aliases=self.sequence_literal_aliases,
        ):
            return True
        if isinstance(base, ast.Name) and base.id in self.ns_dict_names:
            return True
        if isinstance(base, ast.Attribute) and base.attr == "__dict__":
            return True
        if isinstance(base, ast.Call):
            bfunc = base.func
            while isinstance(bfunc, ast.NamedExpr):
                bfunc = bfunc.value
            if isinstance(bfunc, ast.Name) and (
                bfunc.id in {"vars", "globals", "locals"}
                or bfunc.id in self.ns_projection_aliases
            ):
                return True
            if isinstance(bfunc, ast.Attribute) and bfunc.attr in {
                "vars",
                "globals",
                "locals",
            }:
                return True
            is_getattr = (
                isinstance(bfunc, ast.Name) and bfunc.id in getattr_aliases
            ) or (isinstance(bfunc, ast.Attribute) and bfunc.attr == "getattr")
            if (
                is_getattr
                and len(base.args) >= 2
                and isinstance(base.args[1], ast.Constant)
                and base.args[1].value == "__dict__"
            ):
                return True
        return False

    def note_projection_name_alias(
        self,
        name: str,
        value: ast.AST,
        *,
        getattr_aliases: frozenset[str] | None = None,
    ) -> None:
        """``MPT = MappingProxyType`` / ``gi = getitem`` local aliases.

        Also seeds ``Proxy = g(types, \"MappingProxyType\")`` (renamed getattr),
        ``builtins.getattr(...)``, ``vars(types)[...]``, ``getattr(..., "__dict__")``,
        renamed ``vars`` / ``.get("MappingProxyType")``, and ``types.__dict__[…]``.
        """

        g_aliases = getattr_aliases or frozenset({"getattr"})
        # Peel walrus so ``(Proxy := MappingProxyType)`` seeds adapters.
        while isinstance(value, ast.NamedExpr):
            value = value.value
        from ovk.compilers.authorization.python_callee_resolution import (
            _static_sequence_index as _static_idx_alias,
            _static_str_expr as _static_str_alias,
        )

        # BoolOp / IfExp / Name-bound ``n=("__call__" if True else "x")`` /
        # ``(0 or "__call__")`` share Constant string/int peels.
        static_s = _static_str_alias(value)
        static_i = _static_idx_alias(value)
        if static_s is not None:
            self.string_constant_names[name] = static_s
            self.static_constant_names[name] = static_s
        elif static_i is not None:
            self.string_constant_names.pop(name, None)
            self.static_constant_names[name] = static_i
            self.sequence_literal_aliases[name] = ast.Constant(value=static_i)
        elif isinstance(value, ast.Constant) and isinstance(
            value.value, (str, int, float, bytes, bool)
        ):
            if isinstance(value.value, str):
                self.string_constant_names[name] = value.value
            else:
                self.string_constant_names.pop(name, None)
            self.static_constant_names[name] = value.value
            # ``i = 0`` must seed sequence peels so ``xs.__getitem__(i)`` /
            # star indexes share bare ``0`` (Unknown > false PASS).
            if isinstance(value.value, int):
                self.sequence_literal_aliases[name] = value
        elif isinstance(value, ast.Name) and value.id in self.static_constant_names:
            self.static_constant_names[name] = self.static_constant_names[value.id]
            if value.id in self.string_constant_names:
                self.string_constant_names[name] = self.string_constant_names[
                    value.id
                ]
            else:
                self.string_constant_names.pop(name, None)
            if value.id in self.sequence_literal_aliases and isinstance(
                self.static_constant_names[value.id], int
            ):
                self.sequence_literal_aliases[name] = self.sequence_literal_aliases[
                    value.id
                ]
        else:
            # Defer Subscript / Call / container peels until helpers exist.
            self.string_constant_names.pop(name, None)
            self.static_constant_names.pop(name, None)
        # ``keys=["MappingProxyType"]`` / nested / Dict literals for peels.
        # Also ``star=(args if True else ())`` / ``star=(0 or args)`` packs.
        if isinstance(value, (ast.List, ast.Tuple, ast.Dict)):
            self.sequence_literal_aliases[name] = value
            if isinstance(value, (ast.List, ast.Tuple)):
                strs: list[str] = []
                for elt in value.elts:
                    walk = elt
                    while isinstance(walk, ast.NamedExpr):
                        walk = walk.value
                    if isinstance(walk, ast.Constant) and isinstance(
                        walk.value, str
                    ):
                        strs.append(walk.value)
                    else:
                        strs = []
                        break
                if strs:
                    self.sequence_string_lists[name] = tuple(strs)
                else:
                    self.sequence_string_lists.pop(name, None)
            else:
                self.sequence_string_lists.pop(name, None)
        elif isinstance(value, (ast.BoolOp, ast.IfExp)):
            from ovk.compilers.authorization.python_callee_resolution import (
                _sequence_pack_elts as _seq_pack_alias,
            )

            seq_elts = _seq_pack_alias(
                value,
                sequence_aliases=self.sequence_literal_aliases,
            )
            if seq_elts is not None:
                self.sequence_literal_aliases[name] = ast.Tuple(
                    elts=list(seq_elts), ctx=ast.Load()
                )
                self.sequence_string_lists.pop(name, None)
            else:
                self.sequence_literal_aliases.pop(name, None)
                self.sequence_string_lists.pop(name, None)
        elif isinstance(value, ast.Name) and value.id in self.sequence_literal_aliases:
            self.sequence_literal_aliases[name] = self.sequence_literal_aliases[
                value.id
            ]
            if value.id in self.sequence_string_lists:
                self.sequence_string_lists[name] = self.sequence_string_lists[
                    value.id
                ]
        else:
            # Defer Call / projection peels until helpers exist; clear for now.
            # Keep ``i = 0`` int Constant seeds installed above.
            self.sequence_string_lists.pop(name, None)
            if not isinstance(value, (ast.Name, ast.Call, ast.Subscript)) and not (
                isinstance(value, ast.Constant) and isinstance(value.value, int)
            ):
                self.sequence_literal_aliases.pop(name, None)
        # ``ns = types.__dict__`` / ``ns = vars(types)`` / ``ns2 = ns``: later
        # ``ns.get(...)`` / ``getattr(ns, "get")(...)`` project like the literal.
        if self._base_is_namespace_projection(value, getattr_aliases=g_aliases):
            self.ns_dict_names.add(name)
        else:
            self.ns_dict_names.discard(name)

        def _static_key_value(node: ast.AST) -> object | None:
            while isinstance(node, ast.NamedExpr):
                node = node.value
            if isinstance(node, ast.Constant):
                return node.value
            if isinstance(node, ast.Name):
                if node.id in self.static_constant_names:
                    return self.static_constant_names[node.id]
                return self.string_constant_names.get(node.id)
            # ``None or 0`` / ``0|0`` / ``int()`` star indexes share bare ``0``
            # (``*[0 or 0]`` already collapses in flatten; these do not).
            from ovk.compilers.authorization.python_callee_resolution import (
                _static_sequence_index as _static_idx_key,
            )

            idx = _static_idx_key(
                node,
                sequence_aliases=self.sequence_literal_aliases,
            )
            if idx is not None:
                return idx
            return None

        def _project_from_carrier(
            carrier: ast.AST, key: object | None
        ) -> str | None:
            while isinstance(carrier, ast.NamedExpr):
                carrier = carrier.value
            if isinstance(carrier, ast.Name):
                if carrier.id in self.sequence_literal_aliases:
                    return _project_from_carrier(
                        self.sequence_literal_aliases[carrier.id], key
                    )
                lit = self.sequence_string_lists.get(carrier.id)
                if lit is not None and isinstance(key, int) and 0 <= key < len(lit):
                    return lit[key]
                pack = self.container_adapter_packs.get(carrier.id)
                if pack is not None and key in pack:
                    for pname in pack[key]:
                        bound = self.string_constant_names.get(pname)
                        if bound is not None:
                            return bound
                        if isinstance(pname, str) and pname in {
                            "MappingProxyType",
                        } | _OPERATOR_PROJECTION_NAMES:
                            return pname
                return None
            if isinstance(carrier, (ast.List, ast.Tuple)) and isinstance(key, int):
                if 0 <= key < len(carrier.elts):
                    return _static_or_bound_key(carrier.elts[key])
                return None
            if isinstance(carrier, ast.Dict) and key is not None:
                for map_key, map_val in zip(carrier.keys, carrier.values):
                    if (
                        map_val is not None
                        and isinstance(map_key, ast.Constant)
                        and map_key.value == key
                    ):
                        return _static_or_bound_key(map_val)
                return None
            if isinstance(carrier, ast.Subscript):
                inner = _project_from_carrier(
                    carrier.value, _static_key_value(carrier.slice)
                )
                # Nested container: resolve carrier element then project key.
                # When carrier projects a str already, only accept key is None.
                if key is None:
                    return inner
                # Re-resolve via literal aliases when carrier is Name-bound nest.
                base = carrier.value
                while isinstance(base, ast.NamedExpr):
                    base = base.value
                if isinstance(base, ast.Name) and base.id in self.sequence_literal_aliases:
                    aliased = self.sequence_literal_aliases[base.id]
                    okey = _static_key_value(carrier.slice)
                    if isinstance(aliased, (ast.List, ast.Tuple)) and isinstance(
                        okey, int
                    ):
                        if 0 <= okey < len(aliased.elts):
                            return _project_from_carrier(aliased.elts[okey], key)
                    if isinstance(aliased, ast.Dict) and okey is not None:
                        for map_key, map_val in zip(aliased.keys, aliased.values):
                            if (
                                map_val is not None
                                and isinstance(map_key, ast.Constant)
                                and map_key.value == okey
                            ):
                                return _project_from_carrier(map_val, key)
                return None
            # Nested Call carriers: ``keys.get("x").get("y")`` /
            # ``itemgetter("y")(itemgetter("x")(keys))`` /
            # ``getitem(getitem(keys,"x"),"y")``.
            if isinstance(carrier, ast.Call):
                element = _call_projected_value(carrier)
                if element is None:
                    return None
                if key is None:
                    return _static_or_bound_key(element)
                return _project_from_carrier(element, key)
            return None

        def _itemgetter_key_of(call: ast.Call) -> object | None:
            func = call.func
            while isinstance(func, ast.NamedExpr):
                func = func.value
            while isinstance(func, ast.Attribute) and func.attr == "__call__":
                func = func.value
                while isinstance(func, ast.NamedExpr):
                    func = func.value
            is_ig = (
                isinstance(func, ast.Name)
                and (
                    func.id == "itemgetter"
                    or self.operator_projection_aliases.get(func.id) == "itemgetter"
                )
            ) or (isinstance(func, ast.Attribute) and func.attr == "itemgetter")
            if not is_ig and isinstance(func, ast.Call):
                # ``getattr(operator, "itemgetter")("x")``.
                g_func = func.func
                while isinstance(g_func, ast.NamedExpr):
                    g_func = g_func.value
                is_g = (
                    isinstance(g_func, ast.Name) and g_func.id in g_aliases
                ) or (
                    isinstance(g_func, ast.Attribute) and g_func.attr == "getattr"
                )
                if (
                    is_g
                    and len(func.args) >= 2
                    and isinstance(func.args[1], ast.Constant)
                    and func.args[1].value == "itemgetter"
                ):
                    is_ig = True
            if not is_ig and call.args and _is_itemgetter_factory_expr(func):
                # Packed ``[getattr(operator,"itemgetter")][0]("x")`` /
                # ``(0 or getattr(...))("x")`` / IfExp / next(iter).
                is_ig = True
            if is_ig and call.args:
                return _static_key_value(call.args[0])
            return None

        def _is_itemgetter_factory_expr(expr: ast.AST) -> bool:
            """Bare itemgetter factory (not yet applied to a key)."""

            from ovk.compilers.authorization.python_callee_resolution import (
                _shallow_packed_callee_exprs,
            )

            for cand in _shallow_packed_callee_exprs(expr):
                nested = cand
                while isinstance(nested, ast.NamedExpr):
                    nested = nested.value
                while isinstance(nested, ast.Attribute) and nested.attr == "__call__":
                    nested = nested.value
                    while isinstance(nested, ast.NamedExpr):
                        nested = nested.value
                if isinstance(nested, ast.Name) and (
                    nested.id == "itemgetter"
                    or self.operator_projection_aliases.get(nested.id)
                    == "itemgetter"
                ):
                    return True
                if isinstance(nested, ast.Attribute) and nested.attr == "itemgetter":
                    return True
                if isinstance(nested, ast.Call):
                    g_func = nested.func
                    while isinstance(g_func, ast.NamedExpr):
                        g_func = g_func.value
                    is_g = (
                        isinstance(g_func, ast.Name) and g_func.id in g_aliases
                    ) or (
                        isinstance(g_func, ast.Attribute)
                        and g_func.attr == "getattr"
                    )
                    if (
                        is_g
                        and len(nested.args) >= 2
                        and isinstance(nested.args[1], ast.Constant)
                        and nested.args[1].value == "itemgetter"
                    ):
                        return True
            return False

        def _factory_itemgetter_key(
            func: ast.AST,
            *,
            applied_args: list[ast.AST] | None = None,
        ) -> object | None:
            """itemgetter key from a Call.func that may be packed/conditional.

            Also ``[getattr(operator,"itemgetter")][0]("x")`` /
            ``(0 or getattr(...))("x")`` where packing yields the bare factory
            and the key lives on the outer Call args (Unknown > false PASS).
            """

            while isinstance(func, ast.NamedExpr):
                func = func.value
            if isinstance(func, ast.Call):
                ig_direct = _itemgetter_key_of(func)
                if ig_direct is not None:
                    return ig_direct
                # Fall through: ``next(iter([ig]))`` is a Call but not an
                # itemgetter factory — peel packing for Name-bound products.
            if isinstance(func, ast.Name) and func.id in self.itemgetter_products:
                return self.itemgetter_products[func.id]
            # Packed ``[operator.itemgetter("x")][0]`` /
            # ``(False or itemgetter("x"))`` / ``(itemgetter("x") if True else …)`` /
            # ``next(iter([ig]))`` Name-bound applied products.
            from ovk.compilers.authorization.python_callee_resolution import (
                _shallow_packed_callee_exprs,
            )

            for cand in _shallow_packed_callee_exprs(func):
                nested = cand
                while isinstance(nested, ast.NamedExpr):
                    nested = nested.value
                if isinstance(nested, ast.Call):
                    ig_key = _itemgetter_key_of(nested)
                    if ig_key is not None:
                        return ig_key
                if isinstance(nested, ast.Name) and nested.id in self.itemgetter_products:
                    return self.itemgetter_products[nested.id]
            # Packed bare factory: key from the applied outer Call.
            if applied_args and _is_itemgetter_factory_expr(func):
                return _static_key_value(applied_args[0])
            return None

        def _methodcaller_get_key(func: ast.AST) -> object | None:
            """``methodcaller("get"|"__getitem__"|…, key)`` static key, if any.

            Also Name-bound ``mc=methodcaller("pop",0)`` / star packs
            ``methodcaller(*args)`` (Unknown > false PASS).
            """

            while isinstance(func, ast.NamedExpr):
                func = func.value
            candidates: list[ast.AST] = [func]
            from ovk.compilers.authorization.python_callee_resolution import (
                _flatten_starred_args as _flat_mc_key,
                _methodcaller_static_name,
                _shallow_packed_callee_exprs,
            )

            candidates.extend(_shallow_packed_callee_exprs(func))
            if isinstance(func, ast.Name) and func.id in self.methodcaller_factories:
                candidates.append(self.methodcaller_factories[func.id])
            for cand in candidates:
                if isinstance(cand, ast.Name) and cand.id in self.methodcaller_factories:
                    cand = self.methodcaller_factories[cand.id]
                if not isinstance(cand, ast.Call):
                    continue
                mc = _methodcaller_static_name(
                    cand,
                    projection_aliases=self.operator_projection_aliases,
                    getattr_aliases=g_aliases,
                    sequence_aliases=self.sequence_literal_aliases,
                    str_resolver=lambda n: (
                        n.value
                        if isinstance(n, ast.Constant)
                        and isinstance(n.value, str)
                        else self.string_constant_names.get(n.id)
                        if isinstance(n, ast.Name)
                        else None
                    ),
                )
                flat_mc = _flat_mc_key(
                    cand.args,
                    sequence_aliases=self.sequence_literal_aliases,
                )
                if (
                    mc in {"get", "pop", "__getitem__", "setdefault"}
                    and len(flat_mc) >= 2
                ):
                    return _static_key_value(flat_mc[1])
            return None

        def _call_projected_value(node: ast.Call) -> ast.AST | None:
            """Concrete List/Dict/Constant value projected by a view/getitem Call."""

            from ovk.compilers.authorization.python_callee_resolution import (
                _attrgetter_static_name as _ag_proj_view,
                _getattr_static_name as _g_proj_view,
                _flatten_starred_args as _flat_proj_view,
                _is_partial_factory as _partial_proj_view,
                _peel_call_func as _peel_proj_view,
                _rewrite_applied_dunder_call as _rewrite_call_view,
                _shallow_packed_callee_exprs as _shallow_ag,
            )

            def _resolve_str_key(expr: ast.AST) -> str | None:
                if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
                    return expr.value
                if isinstance(expr, ast.Name):
                    return self.string_constant_names.get(expr.id)
                return None

            from ovk.compilers.authorization.python_callee_resolution import (
                _peel_transparent_callee as _peel_call_view,
            )

            rewritten_view = _rewrite_call_view(node)
            if rewritten_view is not None:
                node = rewritten_view
            func = node.func
            while isinstance(func, ast.NamedExpr):
                func = func.value
            # ``getattr(...).__call__(0)`` / packed ``[getattr][0].__call__`` /
            # Name-bound ``g.__call__(*[0])`` — peel transparent ``__call__``
            # and star packs before view projection (Unknown > false PASS).
            func = _peel_call_view(func)
            # Nested ``attrgetter("pop")(xs)(0)`` — peel applied attrgetter
            # Attribute before the outer index. Skip factories themselves
            # (``attrgetter("pop")``) so args are not misread as the carrier
            # (Unknown > false PASS).
            if (
                isinstance(func, ast.Call)
                and _ag_proj_view(
                    func,
                    projection_aliases=self.operator_projection_aliases,
                )
                is None
            ):
                inner_proj = _call_projected_value(func)
                if inner_proj is not None and not isinstance(
                    inner_proj, ast.Call
                ):
                    func = inner_proj
            # ``next(iter([getattr(xs,"pop")]))(0)`` — peel packing onto the
            # getattr Call before view projection (Unknown > false PASS).
            if not isinstance(func, ast.Attribute):
                for cand in _shallow_ag(func):
                    if not isinstance(cand, ast.Call):
                        continue
                    gv = _g_proj_view(
                        cand, getattr_aliases=frozenset(g_aliases)
                    )
                    gflat = _flat_proj_view(
                        cand.args,
                        sequence_aliases=self.sequence_literal_aliases,
                    )
                    if gv is None and len(gflat) >= 2:
                        gv = _resolve_str_key(gflat[1])
                    if (
                        gv
                        in {"get", "pop", "__getitem__", "setdefault"}
                        and gflat
                    ):
                        func = cand
                        break
            # ``partial(getattr, xs, "pop")()`` / ``partial(getattr, xs)("pop")``
            # share the getattr Attribute peel (Unknown > false PASS).
            if isinstance(func, ast.Call) and _partial_proj_view(
                func,
                getattr_aliases=frozenset(g_aliases),
            ):
                p_flat = _flat_proj_view(
                    func.args,
                    sequence_aliases=self.sequence_literal_aliases,
                )
                if p_flat:
                    head = _peel_proj_view(p_flat[0])
                    head_is_getattr = (
                        isinstance(head, ast.Name)
                        and (
                            head.id == "getattr"
                            or head.id in g_aliases
                        )
                    ) or (
                        isinstance(head, ast.Attribute)
                        and head.attr == "getattr"
                    )
                    if not head_is_getattr and isinstance(head, ast.Call):
                        head_is_getattr = (
                            _g_proj_view(
                                head, getattr_aliases=frozenset(g_aliases)
                            )
                            == "getattr"
                        )
                    combined = [*p_flat[1:], *node.args]
                    if head_is_getattr and len(combined) >= 2:
                        ag_attr = _resolve_str_key(combined[1])
                        if ag_attr in {
                            "get",
                            "pop",
                            "__getitem__",
                            "setdefault",
                        }:
                            return ast.Attribute(
                                value=combined[0],
                                attr=ag_attr,
                                ctx=ast.Load(),
                            )
            # ``itemgetter("x")(keys)`` / packed / getattr / Name-bound ``ig(keys)``.
            ig_key = _factory_itemgetter_key(func)
            if ig_key is not None and node.args:
                return _carrier_element_ast(node.args[0], ig_key)
            # ``methodcaller("get", "x")(keys)``.
            mc_key = _methodcaller_get_key(func)
            if mc_key is not None and node.args:
                return _carrier_element_ast(node.args[0], mc_key)

            proj = None
            if isinstance(func, ast.Name):
                proj = self.operator_projection_aliases.get(func.id, func.id)
            elif isinstance(func, ast.Attribute):
                proj = func.attr
            elif isinstance(func, ast.Call):
                # Packed / BoolOp / Name-attr getattr factories:
                # ``[getattr][0](…,"pop")`` / ``(0 or getattr)(…,"pop")`` /
                # ``getattr(builtins,"getattr")(…,"pop")`` / ``n="pop"``.
                g_proj = _g_proj_view(
                    func, getattr_aliases=frozenset(g_aliases)
                )
                if g_proj is None:
                    g_flat = _flat_proj_view(
                        func.args,
                        sequence_aliases=self.sequence_literal_aliases,
                    )
                    if len(g_flat) >= 2:
                        g_proj = _resolve_str_key(g_flat[1])
                if g_proj is not None:
                    proj = g_proj
            flat_apply = _flat_proj_view(
                node.args,
                sequence_aliases=self.sequence_literal_aliases,
                projection_aliases=self.operator_projection_aliases,
            )
            if proj == "getitem" and len(flat_apply) >= 2:
                return _carrier_element_ast(
                    flat_apply[0], _static_key_value(flat_apply[1])
                )
            view_attr: str | None = None
            recv: ast.AST | None = None

            def _bind_name_view(view_name: str) -> bool:
                nonlocal view_attr, recv
                view = self.dict_view_products.get(view_name)
                if view is None:
                    return False
                view_attr = view.split(".")[-1]
                recv_name = self.bound_view_receivers.get(view_name)
                if recv_name is not None:
                    recv = ast.Name(id=recv_name, ctx=ast.Load())
                else:
                    expr_recv = self.bound_view_expr_receivers.get(view_name)
                    if expr_recv is not None:
                        recv = expr_recv
                return True
            # ``attrgetter("pop")([partial…])`` ≡ getattr(carrier, "pop").
            ag_name = None
            if isinstance(func, ast.Call):
                ag_name = _ag_proj_view(
                    func,
                    projection_aliases=self.operator_projection_aliases,
                )
            if ag_name is None:
                for cand in _shallow_ag(func):
                    if isinstance(cand, ast.Call):
                        ag_name = _ag_proj_view(
                            cand,
                            projection_aliases=self.operator_projection_aliases,
                        )
                        if ag_name is not None:
                            break
            if (
                ag_name in {"get", "pop", "__getitem__", "setdefault"}
                and node.args
                and not node.keywords
            ):
                view_attr = ag_name
                recv = node.args[0]
            if view_attr is None and isinstance(func, ast.Attribute) and func.attr in {
                "get",
                "pop",
                "__getitem__",
                "setdefault",
            }:
                view_attr = func.attr
                recv = func.value
            elif view_attr is None and isinstance(func, ast.Call):
                g_view = _g_proj_view(
                    func, getattr_aliases=frozenset(g_aliases)
                )
                g_flat = _flat_proj_view(
                    func.args,
                    sequence_aliases=self.sequence_literal_aliases,
                )
                if g_view is None and len(g_flat) >= 2:
                    g_view = _resolve_str_key(g_flat[1])
                if (
                    g_view
                    in {"get", "pop", "__getitem__", "setdefault"}
                    and g_flat
                ):
                    view_attr = g_view
                    recv = g_flat[0]
            elif (
                view_attr is None
                and isinstance(func, ast.Name)
                and _bind_name_view(func.id)
            ):
                pass
            elif view_attr is None:
                # Packed / BoolOp / IfExp Name-bound views:
                # ``[g][0](*[0])`` / ``(0 or g).__call__(*[0])``.
                for cand in _shallow_ag(func):
                    nested = cand
                    while isinstance(nested, ast.NamedExpr):
                        nested = nested.value
                    if isinstance(nested, ast.Name) and _bind_name_view(
                        nested.id
                    ):
                        break
            # ``attrgetter("pop")(xs)`` selects the method — return Attribute
            # so the next Call ``(…)(0)`` peels via Attribute.pop / list0.
            if (
                ag_name is not None
                and view_attr in {"get", "pop", "__getitem__", "setdefault"}
                and recv is not None
            ):
                return ast.Attribute(
                    value=recv, attr=view_attr, ctx=ast.Load()
                )
            if (
                view_attr in {"get", "pop", "__getitem__", "setdefault"}
                and recv is not None
                and flat_apply
            ):
                return _carrier_element_ast(
                    recv, _static_key_value(flat_apply[0])
                )
            # Zero-arg list.pop() → last element so
            # ``[g].pop().__call__(*[0])`` shares ``g.__call__(*[0])`` /
            # ``next(iter([g])).__call__(*[0])`` (Unknown > false PASS).
            if view_attr == "pop" and recv is not None and not flat_apply:
                return _carrier_element_ast(recv, -1)
            return None

        def _carrier_element_ast(
            carrier: ast.AST, key: object | None
        ) -> ast.AST | None:
            """Return the element AST at ``key`` without collapsing to a str."""

            while isinstance(carrier, ast.NamedExpr):
                carrier = carrier.value
            if isinstance(carrier, ast.Name):
                if carrier.id in self.sequence_literal_aliases:
                    return _carrier_element_ast(
                        self.sequence_literal_aliases[carrier.id], key
                    )
                return None
            if isinstance(carrier, (ast.List, ast.Tuple)) and isinstance(key, int):
                if carrier.elts and -len(carrier.elts) <= key < len(carrier.elts):
                    return carrier.elts[key]
                return None
            if isinstance(carrier, ast.Dict) and key is not None:
                for map_key, map_val in zip(carrier.keys, carrier.values):
                    if (
                        map_val is not None
                        and isinstance(map_key, ast.Constant)
                        and map_key.value == key
                    ):
                        return map_val
                return None
            if isinstance(carrier, ast.Call):
                return _call_projected_value(carrier)
            if isinstance(carrier, ast.Subscript):
                return _carrier_element_ast(
                    carrier.value, _static_key_value(carrier.slice)
                )
            return None

        def _static_or_bound_key(node: ast.AST) -> str | None:
            while isinstance(node, ast.NamedExpr):
                node = node.value
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.Name):
                return self.string_constant_names.get(node.id)
            # ``keys[0]`` / ``keys[idx]`` / ``keys["x"]`` / nested ``keys[0][0]``.
            if isinstance(node, ast.Subscript):
                return _project_from_carrier(
                    node.value, _static_key_value(node.slice)
                )
            # ``keys.get("x")`` / ``keys.__getitem__(0)`` / ``keys.pop("x")`` /
            # ``operator.getitem(keys, 0)`` / ``itemgetter("x")(keys)`` /
            # ``ig = itemgetter("x"); ig(keys)`` / nested chains /
            # ``getattr(keys, "get"|"__getitem__")(...)`` /
            # packed / getattr / methodcaller("get") peels.
            if isinstance(node, ast.Call):
                func = node.func
                while isinstance(func, ast.NamedExpr):
                    func = func.value
                ig_key = _factory_itemgetter_key(func)
                if ig_key is not None and node.args:
                    return _project_from_carrier(node.args[0], ig_key)
                mc_key = _methodcaller_get_key(func)
                if mc_key is not None and node.args:
                    return _project_from_carrier(node.args[0], mc_key)
                # ``operator.getitem(keys, 0|"x")`` / nested getitem chains.
                proj = None
                if isinstance(func, ast.Name):
                    proj = self.operator_projection_aliases.get(func.id, func.id)
                elif isinstance(func, ast.Attribute):
                    proj = func.attr
                if proj == "getitem" and len(node.args) >= 2:
                    return _project_from_carrier(
                        node.args[0], _static_key_value(node.args[1])
                    )
                # Bound / getattr view: ``keys.get`` / ``getattr(keys,"get")``.
                view_attr: str | None = None
                recv: ast.AST | None = None
                if isinstance(func, ast.Attribute) and func.attr in {
                    "get",
                    "pop",
                    "__getitem__",
                    "setdefault",
                }:
                    view_attr = func.attr
                    recv = func.value
                elif isinstance(func, ast.Call):
                    g_func = func.func
                    while isinstance(g_func, ast.NamedExpr):
                        g_func = g_func.value
                    is_g = (
                        isinstance(g_func, ast.Name) and g_func.id in g_aliases
                    ) or (
                        isinstance(g_func, ast.Attribute)
                        and g_func.attr == "getattr"
                    )
                    if (
                        is_g
                        and len(func.args) >= 2
                        and isinstance(func.args[1], ast.Constant)
                        and isinstance(func.args[1].value, str)
                        and func.args[1].value
                        in {"get", "pop", "__getitem__", "setdefault"}
                    ):
                        view_attr = func.args[1].value
                        recv = func.args[0]
                elif isinstance(func, ast.Name) and func.id in self.dict_view_products:
                    view = self.dict_view_products[func.id]
                    view_attr = view.split(".")[-1]
                    recv_name = self.bound_view_receivers.get(func.id)
                    if recv_name is not None:
                        recv = ast.Name(id=recv_name, ctx=ast.Load())
                    else:
                        expr_recv = self.bound_view_expr_receivers.get(func.id)
                        if expr_recv is not None:
                            recv = expr_recv
                if (
                    view_attr in {"get", "pop", "__getitem__", "setdefault"}
                    and recv is not None
                    and node.args
                ):
                    return _project_from_carrier(
                        recv, _static_key_value(node.args[0])
                    )
            return None

        def _seed_ns_key(alias_name: str, key: str) -> None:
            if key == "MappingProxyType":
                self.adapter_aliases.add(alias_name)
            if key in _OPERATOR_PROJECTION_NAMES:
                self.operator_projection_aliases[alias_name] = key

        if isinstance(value, ast.Name):
            if value.id in _CONTAINER_ADAPTER_NAMES or value.id in self.adapter_aliases:
                if value.id == "MappingProxyType" or value.id in self.adapter_aliases:
                    self.adapter_aliases.add(name)
            if value.id in self.nullcontext_aliases:
                self.nullcontext_aliases.add(name)
            if value.id in {"vars", "globals", "locals"} or value.id in self.ns_projection_aliases:
                self.ns_projection_aliases.add(name)
            if value.id in _OPERATOR_PROJECTION_NAMES | _KEY_APPLICATOR_NAMES:
                self.operator_projection_aliases[name] = value.id
            elif value.id in self.operator_projection_aliases:
                self.operator_projection_aliases[name] = (
                    self.operator_projection_aliases[value.id]
                )
            if value.id in self.itemgetter_products:
                self.itemgetter_products[name] = self.itemgetter_products[value.id]
            else:
                self.itemgetter_products.pop(name, None)
            if value.id in self.methodcaller_factories:
                self.methodcaller_factories[name] = self.methodcaller_factories[
                    value.id
                ]
            else:
                self.methodcaller_factories.pop(name, None)
            if value.id in self.partial_factories:
                self.partial_factories[name] = self.partial_factories[value.id]
            else:
                self.partial_factories.pop(name, None)
            if value.id in self.dict_view_products:
                self.dict_view_products[name] = self.dict_view_products[value.id]
                if value.id in self.bound_view_receivers:
                    self.bound_view_receivers[name] = self.bound_view_receivers[
                        value.id
                    ]
                    self.bound_view_expr_receivers.pop(name, None)
                elif value.id in self.bound_view_expr_receivers:
                    self.bound_view_receivers.pop(name, None)
                    self.bound_view_expr_receivers[name] = (
                        self.bound_view_expr_receivers[value.id]
                    )
                else:
                    self.bound_view_receivers.pop(name, None)
                    self.bound_view_expr_receivers.pop(name, None)
            else:
                self.dict_view_products.pop(name, None)
                self.bound_view_receivers.pop(name, None)
                self.bound_view_expr_receivers.pop(name, None)
        elif isinstance(value, ast.Attribute):
            # ``g = getattr([partial(copy.copy)], "pop").__call__`` /
            # ``g = view.__call__`` — peel transparent ``__call__`` only for
            # getattr/view products (not ``type.__call__`` / ``operator.call``
            # protocol seeds — Unknown > false PASS).
            if value.attr == "__call__":
                inner = value.value
                while isinstance(inner, ast.NamedExpr):
                    inner = inner.value
                if isinstance(inner, ast.Call) or (
                    isinstance(inner, ast.Name)
                    and inner.id in self.dict_view_products
                ):
                    self.note_projection_name_alias(
                        name, inner, getattr_aliases=getattr_aliases
                    )
                    return
            if value.attr == "MappingProxyType":
                self.adapter_aliases.add(name)
            if value.attr == "nullcontext":
                self.nullcontext_aliases.add(name)
            if value.attr in {"vars", "globals", "locals"}:
                self.ns_projection_aliases.add(name)
            if value.attr in _OPERATOR_PROJECTION_NAMES | _KEY_APPLICATOR_NAMES:
                self.operator_projection_aliases[name] = value.attr
            else:
                canon = _PROJECTION_DUNDER_ALIASES.get(value.attr)
                if canon is not None and canon in _OPERATOR_PROJECTION_NAMES:
                    self.operator_projection_aliases[name] = canon
            if value.attr in _NS_DICT_VIEW_ATTRS | _DICT_ITER_VIEW_ATTRS | _NS_DICT_MUTATOR_ATTRS | {
                "fromkeys"
            }:
                # Unbound ``fk = dict.fromkeys`` shares the dict.* product tag
                # so ``with fk([Mut])`` seeds like Attribute fromkeys.
                recv = value.value
                while isinstance(recv, ast.NamedExpr):
                    recv = recv.value
                if (
                    value.attr == "fromkeys"
                    and isinstance(recv, ast.Name)
                    and recv.id == "dict"
                ) or (
                    value.attr == "fromkeys"
                    and isinstance(recv, ast.Attribute)
                    and recv.attr == "dict"
                ):
                    self.dict_view_products[name] = "dict.fromkeys"
                    self.bound_view_receivers.pop(name, None)
                    self.bound_view_expr_receivers.pop(name, None)
                elif value.attr == "fromkeys" and isinstance(recv, ast.Name):
                    self.dict_view_products[name] = "dict.fromkeys"
                    self.bound_view_receivers.pop(name, None)
                    self.bound_view_expr_receivers.pop(name, None)
                else:
                    self.dict_view_products[name] = value.attr
                    if isinstance(recv, ast.Name):
                        self.bound_view_receivers[name] = recv.id
                        self.bound_view_expr_receivers.pop(name, None)
                    else:
                        self.bound_view_receivers.pop(name, None)
                        self.bound_view_expr_receivers[name] = recv
        elif isinstance(value, ast.Subscript):
            # ``k = keys[0]`` / ``k = keys["x"]`` — seed string constants from
            # the whole Subscript before ns-key projection on the slice.
            projected = _static_or_bound_key(value)
            if projected is not None:
                self.string_constant_names[name] = projected
                if projected == "MappingProxyType":
                    self.adapter_aliases.add(name)
                if projected in _OPERATOR_PROJECTION_NAMES | _KEY_APPLICATOR_NAMES:
                    self.operator_projection_aliases[name] = projected
            key = _static_or_bound_key(value.slice)
            if key is not None and self._base_is_namespace_projection(
                value.value, getattr_aliases=g_aliases
            ):
                _seed_ns_key(name, key)
            # ``p=[partial(operator.setitem)][0]`` / list0 partial peels.
            from ovk.compilers.authorization.python_callee_resolution import (
                _is_partial_factory as _is_partial_sub,
                _peel_call_func as _peel_partial_sub,
                _shallow_packed_callee_exprs as _shallow_partial_sub,
            )

            for cand in _shallow_partial_sub(value):
                nested = _peel_partial_sub(cand)
                if isinstance(nested, ast.Call) and _is_partial_sub(
                    nested,
                    getattr_aliases=frozenset(g_aliases),
                ):
                    self.partial_factories[name] = nested
                    break
            # Do not return early: pack seeding below still applies.
        elif isinstance(value, ast.Call):
            # ``Proxy = getattr(types, "MappingProxyType")`` /
            # ``g = getattr; Proxy = g(types, …)`` / ``builtins.getattr(...)``.
            func = value.func
            while isinstance(func, ast.NamedExpr):
                func = func.value
            # ``ig = itemgetter("x")`` / ``ig = operator.itemgetter("x")`` /
            # ``ig = getattr(operator, "itemgetter")("x")`` /
            # ``ig = [getattr(operator,"itemgetter")][0]("x")`` /
            # ``ig = next(iter([getattr(...)]))("x")``.
            is_ig = (
                isinstance(func, ast.Name)
                and (
                    func.id == "itemgetter"
                    or self.operator_projection_aliases.get(func.id) == "itemgetter"
                )
            ) or (isinstance(func, ast.Attribute) and func.attr == "itemgetter")
            if not is_ig and isinstance(func, ast.Call):
                g_func = func.func
                while isinstance(g_func, ast.NamedExpr):
                    g_func = g_func.value
                is_g = (
                    isinstance(g_func, ast.Name) and g_func.id in g_aliases
                ) or (
                    isinstance(g_func, ast.Attribute) and g_func.attr == "getattr"
                )
                if (
                    is_g
                    and len(func.args) >= 2
                    and isinstance(func.args[1], ast.Constant)
                    and func.args[1].value == "itemgetter"
                ):
                    is_ig = True
            if not is_ig and value.args and _is_itemgetter_factory_expr(func):
                # Packed / BoolOp / IfExp / next(iter) bare factory apply.
                is_ig = True
            if is_ig and value.args:
                ig_key = value.args[0]
                while isinstance(ig_key, ast.NamedExpr):
                    ig_key = ig_key.value
                if isinstance(ig_key, ast.Constant):
                    self.itemgetter_products[name] = ig_key.value
                elif isinstance(ig_key, ast.Name) and ig_key.id in self.static_constant_names:
                    self.itemgetter_products[name] = self.static_constant_names[
                        ig_key.id
                    ]
                else:
                    self.itemgetter_products.pop(name, None)
            else:
                self.itemgetter_products.pop(name, None)
            # ``mc = methodcaller("__setitem__", …)`` / packed / getattr factory.
            from ovk.compilers.authorization.python_callee_resolution import (
                _methodcaller_static_name as _mc_static,
                _shallow_packed_callee_exprs as _shallow_mc,
            )

            mc_seed: ast.Call | None = None
            if _mc_static(
                value,
                projection_aliases=self.operator_projection_aliases,
                getattr_aliases=frozenset(g_aliases),
            ) is not None:
                mc_seed = value
            else:
                for cand in _shallow_mc(value.func):
                    nested = cand
                    while isinstance(nested, ast.NamedExpr):
                        nested = nested.value
                    is_mc_factory = (
                        isinstance(nested, ast.Name)
                        and (
                            nested.id == "methodcaller"
                            or self.operator_projection_aliases.get(nested.id)
                            == "methodcaller"
                        )
                    ) or (
                        isinstance(nested, ast.Attribute)
                        and nested.attr == "methodcaller"
                    )
                    if isinstance(nested, ast.Call):
                        g_n = nested.func
                        while isinstance(g_n, ast.NamedExpr):
                            g_n = g_n.value
                        is_g_n = (
                            isinstance(g_n, ast.Name) and g_n.id in g_aliases
                        ) or (
                            isinstance(g_n, ast.Attribute)
                            and g_n.attr == "getattr"
                        )
                        if (
                            is_g_n
                            and len(nested.args) >= 2
                            and isinstance(nested.args[1], ast.Constant)
                            and nested.args[1].value == "methodcaller"
                        ):
                            is_mc_factory = True
                    if is_mc_factory and value.args:
                        mc_seed = value
                        break
            # Also seed Name-bound ``ag = operator.attrgetter("__call__")`` so
            # ``ag(g)(*args)`` shares methodcaller/attrgetter applied peels.
            if mc_seed is None and isinstance(value, ast.Call):
                from ovk.compilers.authorization.python_callee_resolution import (
                    _attrgetter_static_name as _ag_seed_name,
                )

                if _ag_seed_name(
                    value,
                    projection_aliases=self.operator_projection_aliases,
                    getattr_aliases=frozenset(g_aliases),
                ) is not None:
                    mc_seed = value
            if mc_seed is not None:
                self.methodcaller_factories[name] = mc_seed
            else:
                self.methodcaller_factories.pop(name, None)
            # ``p = partial(copy.copy, keys)`` / packed / getattr partial.
            from ovk.compilers.authorization.python_callee_resolution import (
                _is_partial_factory as _is_partial_seed,
            )

            if _is_partial_seed(
                value,
                getattr_aliases=frozenset(g_aliases),
            ):
                self.partial_factories[name] = value
            else:
                partial_seed: ast.Call | None = None
                for cand in (
                    *_shallow_mc(value.func),
                    *_shallow_mc(value),
                ):
                    nested = cand
                    while isinstance(nested, ast.NamedExpr):
                        nested = nested.value
                    if isinstance(nested, ast.Call) and _is_partial_seed(
                        nested,
                        getattr_aliases=frozenset(g_aliases),
                    ):
                        partial_seed = nested
                        break
                    is_partial_name = (
                        isinstance(nested, ast.Name)
                        and (
                            nested.id == "partial"
                            or self.operator_projection_aliases.get(nested.id)
                            == "partial"
                        )
                    ) or (
                        isinstance(nested, ast.Attribute)
                        and nested.attr == "partial"
                    )
                    if is_partial_name and value.args:
                        partial_seed = value
                        break
                if partial_seed is not None:
                    self.partial_factories[name] = partial_seed
                else:
                    self.partial_factories.pop(name, None)
            is_getattr = (
                isinstance(func, ast.Name) and func.id in g_aliases
            ) or (isinstance(func, ast.Attribute) and func.attr == "getattr")
            if (
                is_getattr
                and len(value.args) >= 2
                and isinstance(value.args[1], ast.Constant)
                and isinstance(value.args[1].value, str)
            ):
                attr = value.args[1].value
                if attr == "MappingProxyType":
                    self.adapter_aliases.add(name)
                if attr == "nullcontext":
                    self.nullcontext_aliases.add(name)
                if attr in {"vars", "globals", "locals"}:
                    self.ns_projection_aliases.add(name)
                if attr in _OPERATOR_PROJECTION_NAMES | _KEY_APPLICATOR_NAMES:
                    self.operator_projection_aliases[name] = attr
                else:
                    # ``mut = getattr(operator, "__ior__")`` → ior.
                    canon = _PROJECTION_DUNDER_ALIASES.get(attr)
                    if canon is not None and canon in _OPERATOR_PROJECTION_NAMES:
                        self.operator_projection_aliases[name] = canon
                # ``g = getattr(ns, "get")`` / ``si = getattr(keys, "__setitem__")``
                # / ``g = getattr([partial(copy.copy)], "pop")`` — bound view /
                # mutator products (Unknown > false PASS).
                if attr in _NS_DICT_VIEW_ATTRS | _NS_DICT_MUTATOR_ATTRS and value.args:
                    self.dict_view_products[name] = attr
                    recv = value.args[0]
                    while isinstance(recv, ast.NamedExpr):
                        recv = recv.value
                    if isinstance(recv, ast.Name):
                        self.bound_view_receivers[name] = recv.id
                        self.bound_view_expr_receivers.pop(name, None)
                    else:
                        self.bound_view_receivers.pop(name, None)
                        self.bound_view_expr_receivers[name] = recv
            # ``Proxy = types.__dict__.get("MappingProxyType")`` /
            # ``v(types).get("MappingProxyType")`` /
            # ``getattr(types.__dict__, "get"|"__getitem__"|"pop")("MappingProxyType")`` /
            # ``getattr(ns, "setdefault").__call__("MappingProxyType")`` /
            # ``getattr(getattr(ns,"get"),"__call__")(key)`` /
            # ``g = getattr(ns,"get"); Proxy = g(key)`` /
            # Name-bound keys: ``k = "MappingProxyType"; getattr(ns,"get")(k)``.
            view_func = func
            while isinstance(view_func, ast.NamedExpr):
                view_func = view_func.value
            # Peel Attribute ``.__call__`` and ``getattr(X, "__call__")``.
            while True:
                if (
                    isinstance(view_func, ast.Attribute)
                    and view_func.attr == "__call__"
                ):
                    view_func = view_func.value
                    while isinstance(view_func, ast.NamedExpr):
                        view_func = view_func.value
                    continue
                if isinstance(view_func, ast.Call):
                    g_inner = view_func.func
                    while isinstance(g_inner, ast.NamedExpr):
                        g_inner = g_inner.value
                    is_g_call = (
                        isinstance(g_inner, ast.Name) and g_inner.id in g_aliases
                    ) or (
                        isinstance(g_inner, ast.Attribute)
                        and g_inner.attr == "getattr"
                    )
                    if (
                        is_g_call
                        and len(view_func.args) >= 2
                        and isinstance(view_func.args[1], ast.Constant)
                        and view_func.args[1].value == "__call__"
                        and view_func.args
                    ):
                        view_func = view_func.args[0]
                        while isinstance(view_func, ast.NamedExpr):
                            view_func = view_func.value
                        continue
                break

            if (
                isinstance(view_func, ast.Attribute)
                and view_func.attr in _NS_DICT_VIEW_ATTRS
                and value.args
            ):
                key = _static_or_bound_key(value.args[0])
                if key is not None and self._base_is_namespace_projection(
                    view_func.value, getattr_aliases=g_aliases
                ):
                    _seed_ns_key(name, key)
            elif isinstance(view_func, ast.Call) and value.args:
                g_func = view_func.func
                while isinstance(g_func, ast.NamedExpr):
                    g_func = g_func.value
                is_g = (
                    isinstance(g_func, ast.Name) and g_func.id in g_aliases
                ) or (isinstance(g_func, ast.Attribute) and g_func.attr == "getattr")
                if (
                    is_g
                    and len(view_func.args) >= 2
                    and isinstance(view_func.args[1], ast.Constant)
                    and view_func.args[1].value in _NS_DICT_VIEW_ATTRS
                    and view_func.args
                    and self._base_is_namespace_projection(
                        view_func.args[0], getattr_aliases=g_aliases
                    )
                ):
                    key = _static_or_bound_key(value.args[0])
                    if key is not None:
                        _seed_ns_key(name, key)
            elif isinstance(view_func, ast.Name) and value.args:
                # Name-bound ns view: ``g = ns.get; Proxy = g(key)``.
                view = self.dict_view_products.get(view_func.id)
                if view is not None and view.split(".")[-1] in _NS_DICT_VIEW_ATTRS:
                    key = _static_or_bound_key(value.args[0])
                    recv_name = self.bound_view_receivers.get(view_func.id)
                    if key is not None and recv_name is not None and (
                        recv_name in self.ns_dict_names
                        or self._base_is_namespace_projection(
                            ast.Name(id=recv_name, ctx=ast.Load()),
                            getattr_aliases=g_aliases,
                        )
                    ):
                        _seed_ns_key(name, key)
        # Name-bound adapter container packs: ``d = {"p": Proxy}``.
        pack: dict[object, tuple[str, ...]] = {}
        peeled = value
        while isinstance(peeled, ast.NamedExpr):
            peeled = peeled.value
        if isinstance(peeled, ast.Dict):
            for map_key, map_val in zip(peeled.keys, peeled.values):
                if map_val is None or not isinstance(map_key, ast.Constant):
                    continue
                names: list[str] = []
                walk = map_val
                while isinstance(walk, ast.NamedExpr):
                    walk = walk.value
                if isinstance(walk, ast.Name):
                    names.append(walk.id)
                elif isinstance(walk, ast.Attribute):
                    names.append(walk.attr)
                elif isinstance(walk, ast.Constant) and isinstance(walk.value, str):
                    names.append(walk.value)
                if names:
                    pack[map_key.value] = tuple(names)
        elif (
            isinstance(peeled, ast.Call)
            and isinstance(peeled.func, ast.Name)
            and peeled.func.id == "dict"
        ):
            for kw in peeled.keywords:
                if kw.arg is None and isinstance(kw.value, ast.Dict):
                    for map_key, map_val in zip(kw.value.keys, kw.value.values):
                        if map_val is None or not isinstance(map_key, ast.Constant):
                            continue
                        names = []
                        walk = map_val
                        while isinstance(walk, ast.NamedExpr):
                            walk = walk.value
                        if isinstance(walk, ast.Name):
                            names.append(walk.id)
                        elif isinstance(walk, ast.Attribute):
                            names.append(walk.attr)
                        elif isinstance(walk, ast.Constant) and isinstance(
                            walk.value, str
                        ):
                            names.append(walk.value)
                        if names:
                            pack[map_key.value] = tuple(names)
                elif kw.arg is not None:
                    names = []
                    walk = kw.value
                    while isinstance(walk, ast.NamedExpr):
                        walk = walk.value
                    if isinstance(walk, ast.Name):
                        names.append(walk.id)
                    elif isinstance(walk, ast.Attribute):
                        names.append(walk.attr)
                    elif isinstance(walk, ast.Constant) and isinstance(
                        walk.value, str
                    ):
                        names.append(walk.value)
                    if names:
                        pack[kw.arg] = tuple(names)
        elif isinstance(peeled, ast.Name) and peeled.id in self.container_adapter_packs:
            pack = dict(self.container_adapter_packs[peeled.id])
        if pack:
            self.container_adapter_packs[name] = pack
        elif name in self.container_adapter_packs and not isinstance(
            peeled, (ast.Dict, ast.Call, ast.Name)
        ):
            self.container_adapter_packs.pop(name, None)
        # Mid-Name carriers: ``mid=keys.get("x")`` /
        # ``mid=operator.itemgetter("x")(keys)`` / ``c=keys.copy()`` seed
        # nested Dict/List peels so ``k=mid.get("y")`` shares the inline
        # nested path (Unknown > false PASS).
        if isinstance(peeled, ast.Call):
            element = _call_projected_value(peeled)
            # Mid-bind ``p=g(0)`` after ``g=getattr([partial(copy.copy)],"pop")``
            # / ``p=srt([g.__call__],…)[0](*[0])`` — seed the projected idle
            # partial so ``c=p(keys)`` shares ``partial(copy.copy)(keys)``
            # (Unknown > false PASS).
            if isinstance(element, ast.Call):
                from ovk.compilers.authorization.python_callee_resolution import (
                    _is_partial_factory as _is_partial_projected,
                    _peel_call_func as _peel_projected_partial,
                )

                projected_partial = _peel_projected_partial(element)
                if isinstance(projected_partial, ast.Call) and _is_partial_projected(
                    projected_partial,
                    getattr_aliases=frozenset(g_aliases),
                ):
                    self.partial_factories[name] = projected_partial
            # Bound ``keys.copy()`` / ``dict.copy(keys)`` / ``copy.copy(keys)``
            # / ``copy.deepcopy(keys)`` — shallow copy of the Name-bound Dict
            # carrier (mutation on ``c`` must not rewrite ``keys`` unless they
            # still share the same AST object).
            copy_src: ast.AST | None = None
            f = peeled.func
            while isinstance(f, ast.NamedExpr):
                f = f.value

            def _resolve_call_proj(func_expr: ast.AST) -> str | None:
                from ovk.compilers.authorization.python_callee_resolution import (
                    _getattr_static_name as _g_call_proj,
                    _shallow_packed_callee_exprs as _shallow_call_proj,
                )

                for cand in _shallow_call_proj(func_expr):
                    nested = cand
                    while isinstance(nested, ast.NamedExpr):
                        nested = nested.value
                    if isinstance(nested, ast.Name):
                        proj = self.operator_projection_aliases.get(
                            nested.id, nested.id
                        )
                        if proj == "call":
                            return "call"
                    if (
                        isinstance(nested, ast.Attribute)
                        and nested.attr == "call"
                    ):
                        return "call"
                    if isinstance(nested, ast.Call):
                        if (
                            _g_call_proj(
                                nested, getattr_aliases=frozenset(g_aliases)
                            )
                            == "call"
                        ):
                            return "call"
                return None

            # ``ig([partial(copy.copy)])(keys)`` /
            # ``getattr([partial],"pop")(0)(keys)`` /
            # ``[operator.call].pop(0)(partial, keys)`` /
            # ``[operator.call][0](partial, keys)`` /
            # ``(0 or operator.call)(partial, keys)`` /
            # ``next(iter([partial(*IfExp)]))()`` /
            # ``[partial(*IfExp)].pop(0)()`` — list0 / itemgetter / getattr /
            # next(iter) peels project the callable before copy / operator.call
            # peels (Unknown > false PASS).
            for _ in range(6):
                progressed = False
                from ovk.compilers.authorization.python_callee_resolution import (
                    _is_partial_factory as _is_partial_proj,
                    _shallow_packed_callee_exprs as _shallow_proj,
                    _rewrite_applied_dunder_call as _rewrite_applied_copy,
                )

                # ``methodcaller("__call__",0)(g)(keys)`` /
                # ``ag(g)(*[0])(keys)`` / ``getattr(list,"__getitem__")([p],0)(*a)``
                # / ``sorted([g])[0](*a)`` share rewritten copy peels
                # (Unknown > false PASS).
                if isinstance(peeled, ast.Call):
                    from ovk.compilers.authorization.python_callee_resolution import (
                        _methodcaller_static_name as _mc_fp,
                        _attrgetter_static_name as _ag_fp,
                    )

                    _fp: dict[str, tuple[str, str | None]] = {}
                    for _mk, _mv in self.methodcaller_factories.items():
                        if isinstance(_mv, ast.Call):
                            _mcn = _mc_fp(
                                _mv,
                                projection_aliases=self.operator_projection_aliases,
                                getattr_aliases=frozenset(g_aliases),
                            )
                            if _mcn is not None:
                                _fp[_mk] = ("methodcaller", _mcn)
                            _agn = _ag_fp(
                                _mv,
                                projection_aliases=self.operator_projection_aliases,
                                getattr_aliases=frozenset(g_aliases),
                            )
                            if _agn is not None:
                                _fp[_mk] = ("attrgetter", _agn)
                    rewritten_copy = _rewrite_applied_copy(
                        peeled,
                        sequence_aliases=self.sequence_literal_aliases,
                        factory_products=_fp,
                        projection_aliases=self.operator_projection_aliases,
                    )
                    if rewritten_copy is None and isinstance(peeled.func, ast.Call):
                        # ``list.__getitem__([g], i)(*[0])(keys)`` — rewrite the
                        # applied getitem/pop product before the outer apply.
                        # Name-bound ``srt=sorted`` / ``mx=max`` share the same
                        # projection_aliases peel (Unknown > false PASS).
                        inner_rw = _rewrite_applied_copy(
                            peeled.func,
                            sequence_aliases=self.sequence_literal_aliases,
                            factory_products=_fp,
                            projection_aliases=self.operator_projection_aliases,
                        )
                        if inner_rw is not None:
                            rewritten_copy = ast.Call(
                                func=inner_rw,
                                args=list(peeled.args),
                                keywords=list(peeled.keywords),
                            )
                    if rewritten_copy is not None and rewritten_copy is not peeled:
                        peeled = rewritten_copy
                        f = peeled.func
                        while isinstance(f, ast.NamedExpr):
                            f = f.value
                        progressed = True
                # Peel Subscript / BoolOp / next carriers onto Attribute/Call
                # heads before Call-only projection (Unknown > false PASS).
                if not isinstance(f, ast.Call):
                    for cand in _shallow_proj(f):
                        nested = cand
                        while isinstance(nested, ast.NamedExpr):
                            nested = nested.value
                        if nested is not f and isinstance(
                            nested, (ast.Attribute, ast.Name, ast.Call)
                        ):
                            f = nested
                            progressed = True
                            break
                if isinstance(f, ast.Call):
                    for cand in _shallow_proj(f):
                        nested = cand
                        while isinstance(nested, ast.NamedExpr):
                            nested = nested.value
                        if (
                            isinstance(nested, ast.Call)
                            and _is_partial_proj(
                                nested,
                                getattr_aliases=frozenset(g_aliases),
                            )
                            and nested is not f
                        ):
                            f = nested
                            progressed = True
                            break
                    projected_fn = _call_projected_value(f)
                    if projected_fn is not None:
                        f = projected_fn
                        while isinstance(f, ast.NamedExpr):
                            f = f.value
                        progressed = True
                # ``operator.call(partial(copy.copy), keys)`` /
                # ``operator.call(getattr(...), 0)(keys)`` /
                # ``operator.call(*(args if True else ()))`` packed call.
                from ovk.compilers.authorization.python_callee_resolution import (
                    _flatten_starred_args as _flat_call_args,
                    _is_operator_call_factory as _is_op_call_proj,
                )

                # Nested ``operator.call(fn, *bound)( *outer )`` — rewrite the
                # inner factory Call first so ``(…)(keys)`` shares bare apply
                # (Unknown > false PASS).
                if isinstance(f, ast.Call) and _is_op_call_proj(
                    f,
                    projection_aliases=self.operator_projection_aliases,
                    getattr_aliases=frozenset(g_aliases),
                ):
                    flat_inner = _flat_call_args(
                        f.args,
                        sequence_aliases=self.sequence_literal_aliases,
                        projection_aliases=self.operator_projection_aliases,
                    )
                    if flat_inner:
                        inner_fn = flat_inner[0]
                        while isinstance(inner_fn, ast.NamedExpr):
                            inner_fn = inner_fn.value
                        f = ast.Call(
                            func=inner_fn,
                            args=list(flat_inner[1:]),
                            keywords=list(f.keywords),
                        )
                        peeled = ast.Call(
                            func=f,
                            args=list(peeled.args),
                            keywords=list(peeled.keywords),
                        )
                        progressed = True
                elif _resolve_call_proj(f) == "call":
                    flat_call_args = _flat_call_args(
                        peeled.args,
                        sequence_aliases=self.sequence_literal_aliases,
                        projection_aliases=self.operator_projection_aliases,
                    )
                    if len(flat_call_args) >= 2:
                        call_fn = flat_call_args[0]
                        while isinstance(call_fn, ast.NamedExpr):
                            call_fn = call_fn.value
                        peeled = ast.Call(
                            func=call_fn,
                            args=list(flat_call_args[1:]),
                            keywords=list(peeled.keywords),
                        )
                        f = peeled.func
                        while isinstance(f, ast.NamedExpr):
                            f = f.value
                        progressed = True
                # ``methodcaller("__call__", fn, keys)(operator.call)`` /
                # Name-bound ``mc=…; mc(operator.call)`` /
                # ``partial(mc)(operator.call)`` ≡ ``operator.call(fn, keys)``
                # (Unknown > false PASS).
                if isinstance(peeled, ast.Call):
                    from ovk.compilers.authorization.python_callee_resolution import (
                        _methodcaller_call_bound_args as _mc_call_bound,
                        _is_partial_factory as _is_partial_mc_call,
                        _peel_idle_partial_layers as _peel_idle_mc,
                    )

                    mc_bound_map: dict[str, ast.AST] = dict(
                        self.methodcaller_factories
                    )
                    # ``partial(mc)(operator.call)`` — recover Name-bound mc.
                    peel_func = peeled.func
                    while isinstance(peel_func, ast.NamedExpr):
                        peel_func = peel_func.value
                    if isinstance(peel_func, ast.Call) and _is_partial_mc_call(
                        peel_func,
                        getattr_aliases=frozenset(g_aliases),
                    ):
                        idle = _peel_idle_mc(
                            peel_func,
                            getattr_aliases=frozenset(g_aliases),
                            sequence_aliases=self.sequence_literal_aliases,
                            bound_partials=self.partial_factories,
                        )
                        if idle is not None:
                            head = idle[0]
                            while isinstance(head, ast.NamedExpr):
                                head = head.value
                            if isinstance(head, ast.Name) and head.id in (
                                self.methodcaller_factories
                            ):
                                peeled = ast.Call(
                                    func=self.methodcaller_factories[head.id],
                                    args=list(peeled.args),
                                    keywords=list(peeled.keywords),
                                )
                            elif isinstance(head, ast.Call):
                                peeled = ast.Call(
                                    func=head,
                                    args=list(peeled.args),
                                    keywords=list(peeled.keywords),
                                )
                    mc_bound = _mc_call_bound(
                        peeled,
                        projection_aliases=self.operator_projection_aliases,
                        getattr_aliases=frozenset(g_aliases),
                        sequence_aliases=self.sequence_literal_aliases,
                        bound_map=mc_bound_map,
                        str_resolver=lambda n: (
                            self.string_constant_names.get(n.id)
                            if isinstance(n, ast.Name)
                            else None
                        ),
                    )
                    if mc_bound is not None and peeled.args:
                        recv = peeled.args[0]
                        while isinstance(recv, ast.NamedExpr):
                            recv = recv.value
                        peeled = ast.Call(
                            func=recv,
                            args=list(mc_bound),
                            keywords=[],
                        )
                        f = peeled.func
                        while isinstance(f, ast.NamedExpr):
                            f = f.value
                        progressed = True
                if not progressed:
                    break
            # Re-project after sorted/getitem/pop rewrites so mid-bound
            # ``p=srt(...)[0](*[0])`` / ``p=g(0)`` seed idle partials
            # (Unknown > false PASS).
            if isinstance(peeled, ast.Call):
                rewritten_element = _call_projected_value(peeled)
                if rewritten_element is not None:
                    element = rewritten_element
                if isinstance(element, ast.Call):
                    from ovk.compilers.authorization.python_callee_resolution import (
                        _is_partial_factory as _is_partial_rewritten,
                        _peel_call_func as _peel_rewritten_partial,
                    )

                    projected_partial = _peel_rewritten_partial(element)
                    if isinstance(
                        projected_partial, ast.Call
                    ) and _is_partial_rewritten(
                        projected_partial,
                        getattr_aliases=frozenset(g_aliases),
                    ):
                        self.partial_factories[name] = projected_partial
            if isinstance(f, ast.Attribute) and f.attr == "copy" and not peeled.args:
                copy_src = f.value
            elif (
                isinstance(f, ast.Attribute)
                and f.attr == "copy"
                and peeled.args
                and (
                    (
                        isinstance(f.value, ast.Name)
                        and f.value.id == "dict"
                    )
                    or (
                        isinstance(f.value, ast.Attribute)
                        and f.value.attr == "dict"
                    )
                )
            ):
                copy_src = peeled.args[0]
            elif (
                isinstance(f, ast.Attribute)
                and f.attr in {"copy", "deepcopy"}
                and peeled.args
            ):
                # ``copy.copy(keys)`` / ``copy.deepcopy(keys)`` module peels.
                copy_src = peeled.args[0]
            elif isinstance(f, ast.Name):
                from ovk.compilers.authorization.python_callee_resolution import (
                    _methodcaller_static_name as _mc_name_copy,
                )

                if peeled.args:
                    proj = self.operator_projection_aliases.get(f.id, f.id)
                    if proj in {"copy", "deepcopy"}:
                        copy_src = peeled.args[0]
                    elif f.id == "dict" or proj == "dict":
                        # ``dict(keys)`` shallow-copies a mapping carrier.
                        copy_src = peeled.args[0]
                    else:
                        # ``mc = methodcaller("copy"); c = mc(keys)``.
                        bound_mc = self.methodcaller_factories.get(f.id)
                        if (
                            bound_mc is not None
                            and _mc_name_copy(
                                bound_mc,
                                projection_aliases=(
                                    self.operator_projection_aliases
                                ),
                                getattr_aliases=frozenset(g_aliases),
                            )
                            == "copy"
                        ):
                            copy_src = peeled.args[0]
                        # ``p = partial(copy.copy); c = p(keys)`` unbound
                        # partial apply (Unknown > false PASS).
                        if copy_src is None:
                            bound_partial = self.partial_factories.get(f.id)
                            if (
                                bound_partial is not None
                                and bound_partial.args
                                and len(bound_partial.args) == 1
                            ):
                                from ovk.compilers.authorization.python_callee_resolution import (
                                    _getattr_static_name as _g_unbound,
                                    _peel_call_func as _peel_unbound,
                                )

                                b0 = _peel_unbound(bound_partial.args[0])
                                is_copy = (
                                    (
                                        isinstance(b0, ast.Attribute)
                                        and b0.attr in {"copy", "deepcopy"}
                                    )
                                    or (
                                        isinstance(b0, ast.Name)
                                        and (
                                            b0.id in {"copy", "deepcopy"}
                                            or self.operator_projection_aliases.get(
                                                b0.id
                                            )
                                            in {"copy", "deepcopy"}
                                        )
                                    )
                                    or (
                                        isinstance(b0, ast.Call)
                                        and _g_unbound(
                                            b0,
                                            getattr_aliases=frozenset(g_aliases),
                                        )
                                        in {"copy", "deepcopy"}
                                    )
                                )
                                if is_copy:
                                    copy_src = peeled.args[0]
                else:
                    # ``p = partial(copy.copy, keys); c = p()`` /
                    # ``p = partial(keys.copy); c = p()``.
                    bound_partial = self.partial_factories.get(f.id)
                    if bound_partial is not None and bound_partial.args:
                        if len(bound_partial.args) >= 2:
                            copy_src = bound_partial.args[1]
                        else:
                            from ovk.compilers.authorization.python_callee_resolution import (
                                _getattr_static_name as _g_bound_copy,
                                _peel_call_func as _peel_bound_copy,
                            )

                            b0 = _peel_bound_copy(bound_partial.args[0])
                            if (
                                isinstance(b0, ast.Attribute)
                                and b0.attr == "copy"
                            ):
                                copy_src = b0.value
                            elif (
                                isinstance(b0, ast.Call)
                                and _g_bound_copy(
                                    b0,
                                    getattr_aliases=frozenset(g_aliases),
                                )
                                == "copy"
                                and b0.args
                            ):
                                # ``partial(getattr(keys,"copy"))()``.
                                copy_src = b0.args[0]
            elif isinstance(f, ast.Call):
                # ``getattr(copy,"copy")(keys)`` / ``getattr(dict,"copy")(keys)`` /
                # ``methodcaller("copy")(keys)`` / packed factory applies.
                from ovk.compilers.authorization.python_callee_resolution import (
                    _getattr_static_name as _g_static,
                    _methodcaller_static_name as _mc_copy,
                    _shallow_packed_callee_exprs as _shallow_copy,
                    _is_partial_factory as _is_partial_copy,
                )

                gcopy = _g_static(f, getattr_aliases=frozenset(g_aliases))
                if gcopy in {"copy", "deepcopy"} and peeled.args:
                    copy_src = peeled.args[0]
                elif _mc_copy(
                    f,
                    projection_aliases=self.operator_projection_aliases,
                    getattr_aliases=frozenset(g_aliases),
                ) == "copy" and peeled.args:
                    copy_src = peeled.args[0]
                elif _is_partial_copy(
                    f,
                    getattr_aliases=frozenset(g_aliases),
                ) and f.args:
                    # ``partial(copy.copy, keys)()`` /
                    # ``partial(copy.copy)(keys)`` /
                    # ``partial(*((copy.copy, keys) if True else ()))()`` /
                    # ``partial(*(0 or (copy.copy, keys)))()`` /
                    # ``partial(keys.copy)()`` /
                    # ``partial(getattr(keys,"copy"))()`` /
                    # Name-itemgetter / operator.call projected partials
                    # (Unknown > false PASS).
                    from ovk.compilers.authorization.python_callee_resolution import (
                        _flatten_starred_args as _flat_partial_copy,
                        _peel_call_func as _peel_partial_copy_args,
                    )

                    flat_f_args = _flat_partial_copy(
                        f.args,
                        sequence_aliases=self.sequence_literal_aliases,
                    )
                    if flat_f_args:
                        b0 = _peel_partial_copy_args(flat_f_args[0])
                        while isinstance(b0, ast.NamedExpr):
                            b0 = b0.value
                        is_copy_b0 = (
                            (
                                isinstance(b0, ast.Attribute)
                                and b0.attr in {"copy", "deepcopy"}
                            )
                            or (
                                isinstance(b0, ast.Name)
                                and (
                                    b0.id in {"copy", "deepcopy"}
                                    or self.operator_projection_aliases.get(
                                        b0.id
                                    )
                                    in {"copy", "deepcopy"}
                                )
                            )
                            or (
                                isinstance(b0, ast.Call)
                                and _g_static(
                                    b0, getattr_aliases=frozenset(g_aliases)
                                )
                                in {"copy", "deepcopy"}
                            )
                        )
                        if is_copy_b0:
                            if len(flat_f_args) >= 2 and not peeled.args:
                                copy_src = flat_f_args[1]
                            elif len(flat_f_args) == 1 and peeled.args:
                                copy_src = peeled.args[0]
                            elif (
                                len(flat_f_args) == 1
                                and not peeled.args
                                and isinstance(b0, ast.Attribute)
                                and b0.attr == "copy"
                            ):
                                copy_src = b0.value
                            elif (
                                len(flat_f_args) == 1
                                and not peeled.args
                                and isinstance(b0, ast.Call)
                                and _g_static(
                                    b0, getattr_aliases=frozenset(g_aliases)
                                )
                                == "copy"
                                and b0.args
                            ):
                                copy_src = b0.args[0]
                else:
                    for cand in _shallow_copy(f):
                        nested = cand
                        while isinstance(nested, ast.NamedExpr):
                            nested = nested.value
                        if (
                            isinstance(nested, ast.Attribute)
                            and nested.attr in {"copy", "deepcopy"}
                            and peeled.args
                        ):
                            copy_src = peeled.args[0]
                            break
                        if isinstance(nested, ast.Name):
                            if (
                                self.operator_projection_aliases.get(
                                    nested.id, nested.id
                                )
                                in {"copy", "deepcopy"}
                            ) and peeled.args:
                                copy_src = peeled.args[0]
                                break
                            # ``mc=methodcaller("copy"); next(iter([mc]))(keys)`` /
                            # ``p=partial(copy.copy,keys); next(iter([p]))()`` /
                            # ``p=partial(copy.copy); next(iter([p]))(keys)``.
                            bound_mc = self.methodcaller_factories.get(nested.id)
                            if (
                                bound_mc is not None
                                and peeled.args
                                and _mc_copy(
                                    bound_mc,
                                    projection_aliases=(
                                        self.operator_projection_aliases
                                    ),
                                    getattr_aliases=frozenset(g_aliases),
                                )
                                == "copy"
                            ):
                                copy_src = peeled.args[0]
                                break
                            bound_partial = self.partial_factories.get(nested.id)
                            if bound_partial is not None and bound_partial.args:
                                from ovk.compilers.authorization.python_callee_resolution import (
                                    _getattr_static_name as _g_next_partial,
                                    _peel_call_func as _peel_next_partial,
                                )

                                b0 = _peel_next_partial(bound_partial.args[0])
                                is_copy_p = (
                                    (
                                        isinstance(b0, ast.Attribute)
                                        and b0.attr in {"copy", "deepcopy"}
                                    )
                                    or (
                                        isinstance(b0, ast.Name)
                                        and (
                                            b0.id in {"copy", "deepcopy"}
                                            or self.operator_projection_aliases.get(
                                                b0.id
                                            )
                                            in {"copy", "deepcopy"}
                                        )
                                    )
                                    or (
                                        isinstance(b0, ast.Call)
                                        and _g_next_partial(
                                            b0,
                                            getattr_aliases=frozenset(g_aliases),
                                        )
                                        in {"copy", "deepcopy"}
                                    )
                                )
                                if is_copy_p:
                                    if len(bound_partial.args) >= 2 and not peeled.args:
                                        copy_src = bound_partial.args[1]
                                        break
                                    if len(bound_partial.args) == 1 and peeled.args:
                                        copy_src = peeled.args[0]
                                        break
                                    if (
                                        len(bound_partial.args) == 1
                                        and not peeled.args
                                        and isinstance(b0, ast.Attribute)
                                        and b0.attr == "copy"
                                    ):
                                        # ``p=partial(keys.copy); next(iter([p]))()``.
                                        copy_src = b0.value
                                        break
                                    if (
                                        len(bound_partial.args) == 1
                                        and not peeled.args
                                        and isinstance(b0, ast.Call)
                                        and _g_next_partial(
                                            b0,
                                            getattr_aliases=frozenset(g_aliases),
                                        )
                                        == "copy"
                                        and b0.args
                                    ):
                                        copy_src = b0.args[0]
                                        break
                        if isinstance(nested, ast.Call):
                            gn = _g_static(
                                nested, getattr_aliases=frozenset(g_aliases)
                            )
                            if gn in {"copy", "deepcopy"} and peeled.args:
                                copy_src = peeled.args[0]
                                break
                            if (
                                _mc_copy(
                                    nested,
                                    projection_aliases=(
                                        self.operator_projection_aliases
                                    ),
                                    getattr_aliases=frozenset(g_aliases),
                                )
                                == "copy"
                                and peeled.args
                            ):
                                copy_src = peeled.args[0]
                                break
                            # Inline packed ``partial(copy.copy)`` /
                            # ``partial(keys.copy)`` factory Call itself.
                            if _is_partial_copy(
                                nested,
                                getattr_aliases=frozenset(g_aliases),
                            ) and nested.args:
                                from ovk.compilers.authorization.python_callee_resolution import (
                                    _peel_call_func as _peel_inline_p,
                                )

                                b0 = _peel_inline_p(nested.args[0])
                                is_copy_inline = (
                                    (
                                        isinstance(b0, ast.Attribute)
                                        and b0.attr in {"copy", "deepcopy"}
                                    )
                                    or (
                                        isinstance(b0, ast.Name)
                                        and (
                                            b0.id in {"copy", "deepcopy"}
                                            or self.operator_projection_aliases.get(
                                                b0.id
                                            )
                                            in {"copy", "deepcopy"}
                                        )
                                    )
                                    or (
                                        isinstance(b0, ast.Call)
                                        and _g_static(
                                            b0,
                                            getattr_aliases=frozenset(g_aliases),
                                        )
                                        in {"copy", "deepcopy"}
                                    )
                                )
                                if is_copy_inline:
                                    if (
                                        len(nested.args) >= 2
                                        and not peeled.args
                                    ):
                                        copy_src = nested.args[1]
                                        break
                                    if (
                                        len(nested.args) == 1
                                        and isinstance(b0, ast.Attribute)
                                        and b0.attr == "copy"
                                        and not peeled.args
                                    ):
                                        # ``partial(keys.copy)()``.
                                        copy_src = b0.value
                                        break
                                    if len(nested.args) == 1 and peeled.args:
                                        copy_src = peeled.args[0]
                                        break
            else:
                # Packed ``[copy.copy][0](keys)`` / BoolOp / IfExp / next /
                # ``(0 or mc)(keys)`` Name-bound methodcaller|partial products.
                from ovk.compilers.authorization.python_callee_resolution import (
                    _shallow_packed_callee_exprs as _shallow_copy2,
                    _getattr_static_name as _g_static2,
                    _methodcaller_static_name as _mc_copy2,
                )

                for cand in _shallow_copy2(f):
                    nested = cand
                    while isinstance(nested, ast.NamedExpr):
                        nested = nested.value
                    if (
                        isinstance(nested, ast.Attribute)
                        and nested.attr in {"copy", "deepcopy"}
                        and peeled.args
                    ):
                        copy_src = peeled.args[0]
                        break
                    if isinstance(nested, ast.Name):
                        if (
                            nested.id in {"copy", "deepcopy"}
                            or self.operator_projection_aliases.get(nested.id)
                            in {"copy", "deepcopy"}
                        ) and peeled.args:
                            copy_src = peeled.args[0]
                            break
                        bound_mc = self.methodcaller_factories.get(nested.id)
                        if (
                            bound_mc is not None
                            and peeled.args
                            and _mc_copy2(
                                bound_mc,
                                projection_aliases=(
                                    self.operator_projection_aliases
                                ),
                                getattr_aliases=frozenset(g_aliases),
                            )
                            == "copy"
                        ):
                            copy_src = peeled.args[0]
                            break
                        bound_partial = self.partial_factories.get(nested.id)
                        if bound_partial is not None and bound_partial.args:
                            from ovk.compilers.authorization.python_callee_resolution import (
                                _getattr_static_name as _g_pack_partial,
                                _peel_call_func as _peel_pack_partial,
                            )

                            b0 = _peel_pack_partial(bound_partial.args[0])
                            is_copy_p = (
                                (
                                    isinstance(b0, ast.Attribute)
                                    and b0.attr in {"copy", "deepcopy"}
                                )
                                or (
                                    isinstance(b0, ast.Name)
                                    and (
                                        b0.id in {"copy", "deepcopy"}
                                        or self.operator_projection_aliases.get(
                                            b0.id
                                        )
                                        in {"copy", "deepcopy"}
                                    )
                                )
                                or (
                                    isinstance(b0, ast.Call)
                                    and _g_pack_partial(
                                        b0,
                                        getattr_aliases=frozenset(g_aliases),
                                    )
                                    in {"copy", "deepcopy"}
                                )
                            )
                            if is_copy_p:
                                if len(bound_partial.args) >= 2 and not peeled.args:
                                    copy_src = bound_partial.args[1]
                                    break
                                if len(bound_partial.args) == 1 and peeled.args:
                                    copy_src = peeled.args[0]
                                    break
                                if (
                                    len(bound_partial.args) == 1
                                    and not peeled.args
                                    and isinstance(b0, ast.Attribute)
                                    and b0.attr == "copy"
                                ):
                                    # ``p=partial(keys.copy); [p][0]()``.
                                    copy_src = b0.value
                                    break
                                if (
                                    len(bound_partial.args) == 1
                                    and not peeled.args
                                    and isinstance(b0, ast.Call)
                                    and _g_pack_partial(
                                        b0,
                                        getattr_aliases=frozenset(g_aliases),
                                    )
                                    == "copy"
                                    and b0.args
                                ):
                                    # ``p=partial(getattr(keys,"copy")); [p][0]()``.
                                    copy_src = b0.args[0]
                                    break
                    if isinstance(nested, ast.Call):
                        gn = _g_static2(
                            nested, getattr_aliases=frozenset(g_aliases)
                        )
                        if gn in {"copy", "deepcopy"} and peeled.args:
                            copy_src = peeled.args[0]
                            break
                        if (
                            _mc_copy2(
                                nested,
                                projection_aliases=(
                                    self.operator_projection_aliases
                                ),
                                getattr_aliases=frozenset(g_aliases),
                            )
                            == "copy"
                            and peeled.args
                        ):
                            copy_src = peeled.args[0]
                            break
                        # Packed / BoolOp / IfExp ``[partial(copy.copy)][0](keys)`` /
                        # ``(0 or partial(copy.copy))(keys)`` /
                        # ``[partial(keys.copy)][0]()`` /
                        # ``[partial(getattr(keys,"copy"))][0]()`` /
                        # ``[partial(copy.copy)].pop(0)(keys)`` (Unknown > false PASS).
                        from ovk.compilers.authorization.python_callee_resolution import (
                            _is_partial_factory as _is_partial_pack2,
                            _peel_call_func as _peel_pack2,
                        )

                        if _is_partial_pack2(
                            nested,
                            getattr_aliases=frozenset(g_aliases),
                        ) and nested.args:
                            from ovk.compilers.authorization.python_callee_resolution import (
                                _flatten_starred_args as _flat_pack2,
                            )

                            flat_nested = _flat_pack2(
                                nested.args,
                                sequence_aliases=self.sequence_literal_aliases,
                            )
                            if not flat_nested:
                                continue
                            b0 = _peel_pack2(flat_nested[0])
                            is_copy_inline = (
                                (
                                    isinstance(b0, ast.Attribute)
                                    and b0.attr in {"copy", "deepcopy"}
                                )
                                or (
                                    isinstance(b0, ast.Name)
                                    and (
                                        b0.id in {"copy", "deepcopy"}
                                        or self.operator_projection_aliases.get(
                                            b0.id
                                        )
                                        in {"copy", "deepcopy"}
                                    )
                                )
                                or (
                                    isinstance(b0, ast.Call)
                                    and _g_static2(
                                        b0,
                                        getattr_aliases=frozenset(g_aliases),
                                    )
                                    in {"copy", "deepcopy"}
                                )
                            )
                            if is_copy_inline:
                                if len(flat_nested) >= 2 and not peeled.args:
                                    copy_src = flat_nested[1]
                                    break
                                if (
                                    len(flat_nested) == 1
                                    and isinstance(b0, ast.Attribute)
                                    and b0.attr == "copy"
                                    and not peeled.args
                                ):
                                    copy_src = b0.value
                                    break
                                if (
                                    len(flat_nested) == 1
                                    and isinstance(b0, ast.Call)
                                    and _g_static2(
                                        b0,
                                        getattr_aliases=frozenset(g_aliases),
                                    )
                                    == "copy"
                                    and b0.args
                                    and not peeled.args
                                ):
                                    # ``partial(getattr(keys,"copy"))()``.
                                    copy_src = b0.args[0]
                                    break
                                if len(flat_nested) == 1 and peeled.args:
                                    copy_src = peeled.args[0]
                                    break
            if copy_src is not None:
                src = copy_src
                while isinstance(src, ast.NamedExpr):
                    src = src.value
                if isinstance(src, ast.Name) and src.id in self.sequence_literal_aliases:
                    lit = self.sequence_literal_aliases[src.id]
                    if isinstance(lit, ast.Dict):
                        # Fresh Dict AST so later mutations on ``c`` do not
                        # rewrite ``keys`` (``copy_then_mutate``).
                        element = ast.Dict(
                            keys=list(lit.keys), values=list(lit.values)
                        )
                    elif isinstance(lit, (ast.List, ast.Tuple)):
                        element = type(lit)(elts=list(lit.elts))
            if isinstance(element, (ast.Dict, ast.List, ast.Tuple)):
                self.sequence_literal_aliases[name] = element
            elif (
                isinstance(element, ast.Name)
                and element.id in self.sequence_literal_aliases
            ):
                self.sequence_literal_aliases[name] = self.sequence_literal_aliases[
                    element.id
                ]
        elif isinstance(peeled, ast.Subscript):
            element = _carrier_element_ast(
                peeled.value, _static_key_value(peeled.slice)
            )
            if isinstance(element, (ast.Dict, ast.List, ast.Tuple)):
                self.sequence_literal_aliases[name] = element
            elif (
                isinstance(element, ast.Name)
                and element.id in self.sequence_literal_aliases
            ):
                self.sequence_literal_aliases[name] = self.sequence_literal_aliases[
                    element.id
                ]
        # ``k = keys[0]`` / ``k = keys["x"]`` after packs / sequence lists exist.
        bound_key = _static_or_bound_key(value)
        if bound_key is not None:
            self.string_constant_names[name] = bound_key
            if bound_key == "MappingProxyType":
                self.adapter_aliases.add(name)
            if bound_key in _OPERATOR_PROJECTION_NAMES:
                self.operator_projection_aliases[name] = bound_key

    def snapshot(self) -> "_RequestStateAliasEnv":
        """Deep-copy alias sets for control-flow fork."""

        return _RequestStateAliasEnv(
            request_names=set(self.request_names),
            state_names=set(self.state_names),
            may_request_names=set(self.may_request_names),
            may_state_names=set(self.may_state_names),
            adapter_aliases=set(self.adapter_aliases),
            nullcontext_aliases=set(self.nullcontext_aliases),
            container_adapter_packs={
                k: dict(v) for k, v in self.container_adapter_packs.items()
            },
            operator_projection_aliases=dict(self.operator_projection_aliases),
            ns_projection_aliases=set(self.ns_projection_aliases),
            ns_dict_names=set(self.ns_dict_names),
            string_constant_names=dict(self.string_constant_names),
            static_constant_names=dict(self.static_constant_names),
            dict_view_products=dict(self.dict_view_products),
            bound_view_receivers=dict(self.bound_view_receivers),
            bound_view_expr_receivers=dict(self.bound_view_expr_receivers),
            sequence_string_lists=dict(self.sequence_string_lists),
            sequence_literal_aliases=dict(self.sequence_literal_aliases),
            itemgetter_products=dict(self.itemgetter_products),
            methodcaller_factories=dict(self.methodcaller_factories),
            partial_factories=dict(self.partial_factories),
        )

    def restore(self, other: "_RequestStateAliasEnv") -> None:
        """Replace live alias sets with a previously snapshotted predecessor."""

        self.request_names = set(other.request_names)
        self.state_names = set(other.state_names)
        self.may_request_names = set(other.may_request_names)
        self.may_state_names = set(other.may_state_names)
        self.adapter_aliases = set(other.adapter_aliases)
        self.nullcontext_aliases = set(other.nullcontext_aliases)
        self.container_adapter_packs = {
            k: dict(v) for k, v in other.container_adapter_packs.items()
        }
        self.operator_projection_aliases = dict(other.operator_projection_aliases)
        self.ns_projection_aliases = set(other.ns_projection_aliases)
        self.ns_dict_names = set(other.ns_dict_names)
        self.string_constant_names = dict(other.string_constant_names)
        self.static_constant_names = dict(other.static_constant_names)
        self.dict_view_products = dict(other.dict_view_products)
        self.bound_view_receivers = dict(other.bound_view_receivers)
        self.bound_view_expr_receivers = dict(other.bound_view_expr_receivers)
        self.sequence_string_lists = dict(other.sequence_string_lists)
        self.sequence_literal_aliases = dict(other.sequence_literal_aliases)
        self.itemgetter_products = dict(other.itemgetter_products)
        self.methodcaller_factories = dict(other.methodcaller_factories)
        self.partial_factories = dict(other.partial_factories)

    def install_join(self, states: Sequence["_RequestStateAliasEnv"]) -> None:
        """Install the sound must/may join of feasible predecessor alias envs."""

        self.restore(join_request_state_alias_envs(states))

    def classify(self, value: ast.AST) -> AliasClassification:
        """Return independent must/may request and state facts for ``value``.

        ``IfExp`` arms and ``BoolOp`` operands are classified independently and
        joined (nested forms included). Short-circuit ``and``/``or`` may yield
        any operand, so the join never promotes may→must. ``NamedExpr`` unwraps
        to its RHS so walrus forms share the same lattice. Cross-kind arms
        become dual may — not poison.
        """

        if isinstance(value, ast.NamedExpr):
            return self.classify(value.value)
        if isinstance(value, ast.IfExp):
            return AliasClassification.join(
                self.classify(value.body),
                self.classify(value.orelse),
            )
        if isinstance(value, ast.BoolOp):
            # ``flag and request.state or request`` → dual may; never drop arms.
            return AliasClassification.join_all(
                [self.classify(operand) for operand in value.values]
            )
        return AliasClassification(
            must_request=self._is_must_request_expr(value),
            may_request=self._is_may_only_request_expr(value),
            must_state=self._is_must_state_expr(value),
            may_state=self._is_may_only_state_expr(value),
        )

    def apply_classification(self, name: str, classification: AliasClassification) -> None:
        """Install ``name`` under ``classification``, preserving dual may facts."""

        self.request_names.discard(name)
        self.state_names.discard(name)
        self.may_request_names.discard(name)
        self.may_state_names.discard(name)
        if not classification.any_alias:
            return
        if classification.must_request:
            self.request_names.add(name)
        if classification.may_request:
            self.may_request_names.add(name)
        if classification.must_state:
            self.state_names.add(name)
        if classification.may_state:
            self.may_state_names.add(name)

    def note_binding(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            # Complex targets poison nothing specific; leave env unchanged.
            return
        self.apply_classification(target.id, self.classify(value))

    def poison_names(self, names: set[str]) -> None:
        for name in names:
            self.request_names.discard(name)
            self.state_names.discard(name)
            self.may_request_names.discard(name)
            self.may_state_names.discard(name)

    def all_request_names(self) -> set[str]:
        return set(self.request_names) | set(self.may_request_names)

    def all_state_names(self) -> set[str]:
        return set(self.state_names) | set(self.may_state_names)

    def _is_must_request_expr(self, value: ast.AST) -> bool:
        return isinstance(value, ast.Name) and value.id in self.request_names

    def _is_may_only_request_expr(self, value: ast.AST) -> bool:
        return (
            isinstance(value, ast.Name)
            and value.id in self.may_request_names
            and value.id not in self.request_names
        )

    def _is_request_expr(self, value: ast.AST) -> bool:
        return self._is_must_request_expr(value) or self._is_may_only_request_expr(
            value
        )

    def _is_must_state_expr(self, value: ast.AST) -> bool:
        if isinstance(value, ast.Name) and value.id in self.state_names:
            return True
        if isinstance(value, ast.Attribute) and value.attr == "state":
            # ``request.state`` and ``(request if f else request).state``.
            base = self.classify(value.value)
            if base.must_request:
                return True
            if (
                isinstance(value.value, ast.Name)
                and value.value.id in self.request_names
            ):
                return True
        # getattr(request, "state") / getattr(req if f else req, "state").
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "getattr"
            and len(value.args) >= 2
            and isinstance(value.args[1], ast.Constant)
            and value.args[1].value == "state"
        ):
            base = self.classify(value.args[0])
            if base.must_request or self._is_must_request_expr(value.args[0]):
                return True
        return False

    def _is_may_only_state_expr(self, value: ast.AST) -> bool:
        if isinstance(value, ast.Name) and value.id in self.may_state_names:
            return True
        if isinstance(value, ast.Attribute) and value.attr == "state":
            base = self.classify(value.value)
            if base.may_request and not base.must_request:
                return True
            if (
                isinstance(value.value, ast.Name)
                and value.value.id in self.may_request_names
                and value.value.id not in self.request_names
            ):
                return True
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "getattr"
            and len(value.args) >= 2
            and isinstance(value.args[1], ast.Constant)
            and value.args[1].value == "state"
        ):
            base = self.classify(value.args[0])
            if (base.may_request and not base.must_request) or (
                self._is_may_only_request_expr(value.args[0])
            ):
                return True
        # Subscript projection of packed state: ``[request.state][0]``.
        if isinstance(value, ast.Subscript):
            if self.packs_request_or_state_identity(value.value) or self._is_state_expr(
                value.value
            ):
                return True
        # Adapter/view Calls that project packed identity, e.g.
        # ``next(iter({\"a\": request.state}.values()))`` used as a write base.
        if isinstance(value, ast.Call) and self.packs_request_or_state_identity(value):
            return True
        return False

    def _is_state_expr(self, value: ast.AST) -> bool:
        return self._is_must_state_expr(value) or self._is_may_only_state_expr(value)

    def is_request_expr(self, value: ast.AST) -> bool:
        return self._is_request_expr(value)

    def is_state_expr(self, value: ast.AST) -> bool:
        return self._is_state_expr(value)

    def field_from_assign_target(self, target: ast.AST) -> tuple[str | None, bool]:
        """Return ``(field, exact_or_supported_alias)`` for a store target.

        When the second element is False, the write is still counted but marked
        dynamic/unknown so closure cannot authorize while omitting it.
        Must-alias yields exact=True; may-alias yields exact=False (#171).
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
            if base in self.may_request_names:
                return field, False
            # Plausible Request-like alias (e.g. parameter ``req``) — record,
            # but do not treat as the supported exact theorem.
            return field, False

        # state.field where state aliases request.state
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
        ):
            base = target.value.id
            if base in self.state_names:
                return target.attr, True
            if base in self.may_state_names:
                return target.attr, False

        # Expression-level state identity (IfExp / NamedExpr / nested forms):
        # ``(request.state if f else request).field = ...`` must still account.
        if isinstance(target, ast.Attribute):
            classification = self.classify(target.value)
            if classification.must_state:
                return target.attr, True
            if classification.may_state:
                return target.attr, False

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
        # Prefer classify() so IfExp / BoolOp / NamedExpr subscript stores
        # (``(request.state if f else request)["field"] = …``) match attribute
        # store accounting (Unknown > false PASS, #173).
        classification = self.classify(node)
        if classification.must_state or classification.may_state:
            return True
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
        # Exact theorem requires must-alias, not merely may-alias.
        classification = self.classify(node)
        if classification.must_state:
            return True
        return self._is_must_state_expr(node)

    def is_request_or_state_expr(self, value: ast.AST) -> bool:
        # Prefer classify so IfExp / NamedExpr dual-may identity is visible to
        # escape and interprocedural actual checks (Unknown > false PASS).
        return self.classify(value).any_alias

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
        """True when request/state identity is packed or projected via containers.

        Covers literal packing (``[request.state]``, ``{k: request.state}``) and
        sound adapter/view projections that would otherwise drop identity before
        a subscript or for-iter bind (``list({request.state})``,
        ``{\"k\": request.state}.values()``, ``next(iter(...))``).
        Unknown > false PASS.
        """

        if isinstance(value, ast.NamedExpr):
            return self.packs_request_or_state_identity(value.value)
        if isinstance(value, ast.IfExp):
            # ``request.state if f else request.state`` / list packing in arms.
            return (
                self.is_request_or_state_expr(value.body)
                or self.is_request_or_state_expr(value.orelse)
                or self.packs_request_or_state_identity(value.body)
                or self.packs_request_or_state_identity(value.orelse)
            )
        if isinstance(value, ast.BoolOp):
            return any(
                self.is_request_or_state_expr(operand)
                or self.packs_request_or_state_identity(operand)
                for operand in value.values
            )
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
        # Dict merge packing: ``({} | {\"s\": request.state})[\"s\"]``.
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
            return (
                self.is_request_or_state_expr(value.left)
                or self.is_request_or_state_expr(value.right)
                or self.packs_request_or_state_identity(value.left)
                or self.packs_request_or_state_identity(value.right)
            )
        if isinstance(value, ast.Call):
            # Dict/set view / mapping projections:
            # ``{\"k\": request.state}.values()`` / ``.get`` / ``.pop`` / ``.__getitem__``.
            if (
                isinstance(value.func, ast.Attribute)
                and value.func.attr in _CONTAINER_VIEW_ATTRS
            ):
                recv = value.func.value
                if self.is_request_or_state_expr(
                    recv
                ) or self.packs_request_or_state_identity(recv):
                    return True
                # Unbound ``dict.get(packed, key)`` / ``dict.__getitem__(packed, key)``.
                if (
                    isinstance(recv, ast.Name)
                    and recv.id == "dict"
                    and value.args
                ):
                    first = value.args[0]
                    nested = first.value if isinstance(first, ast.Starred) else first
                    if self.is_request_or_state_expr(
                        nested
                    ) or self.packs_request_or_state_identity(nested):
                        return True
            # Builtin / types adapters: ``list({request.state})``,
            # ``MappingProxyType({…})``, ``types.MappingProxyType``,
            # ``MPT = MappingProxyType`` / ``next(iter(...))``, and Call.func
            # peels ``(Proxy if c else dict)(...)`` / ``(False or Proxy)(...)`` /
            # ``(Proxy := MappingProxyType)(...)`` / ``[Proxy][0](...)``.
            func_names: list[str] = []

            def _peel_adapter_func(node: ast.AST) -> None:
                while isinstance(node, ast.NamedExpr):
                    if isinstance(node.target, ast.Name):
                        func_names.append(node.target.id)
                    node = node.value
                if isinstance(node, ast.Name):
                    func_names.append(node.id)
                    return
                if isinstance(node, ast.Attribute):
                    func_names.append(node.attr)
                    return
                if isinstance(node, ast.IfExp):
                    _peel_adapter_func(node.body)
                    _peel_adapter_func(node.orelse)
                    return
                if isinstance(node, ast.BoolOp):
                    for operand in node.values:
                        _peel_adapter_func(operand)
                    return
                if isinstance(node, ast.BinOp):
                    # ``({}|{"p": Proxy})["p"]`` dict-merge packs.
                    _peel_adapter_func(node.left)
                    _peel_adapter_func(node.right)
                    return
                if isinstance(node, ast.Subscript):
                    _peel_adapter_func(node.value)
                    if isinstance(node.slice, ast.Constant):
                        if isinstance(node.slice.value, str):
                            func_names.append(node.slice.value)
                        # Dict-keyed Call.func: ``{"p": Proxy}["p"]`` /
                        # ``{0: Proxy}[0]`` — peel matching values.
                        if isinstance(node.value, ast.Dict):
                            for map_key, map_val in zip(
                                node.value.keys, node.value.values
                            ):
                                if (
                                    map_val is not None
                                    and isinstance(map_key, ast.Constant)
                                    and map_key.value == node.slice.value
                                ):
                                    _peel_adapter_func(map_val)
                        # Name-bound dict packs: ``d = {"p": Proxy}; d["p"]``.
                        if (
                            isinstance(node.value, ast.Name)
                            and node.value.id in self.container_adapter_packs
                        ):
                            pack = self.container_adapter_packs[node.value.id]
                            for n in pack.get(node.slice.value, ()):
                                func_names.append(n)
                        # ``dict(p=Proxy)["p"]`` / ``dict(**{"e": exec})["e"]``.
                        if (
                            isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Name)
                            and node.value.func.id == "dict"
                        ):
                            for kw in node.value.keywords:
                                if kw.arg is None and isinstance(kw.value, ast.Dict):
                                    for map_key, map_val in zip(
                                        kw.value.keys, kw.value.values
                                    ):
                                        if (
                                            map_val is not None
                                            and isinstance(map_key, ast.Constant)
                                            and map_key.value == node.slice.value
                                        ):
                                            _peel_adapter_func(map_val)
                                elif kw.arg == node.slice.value:
                                    _peel_adapter_func(kw.value)
                    return
                if isinstance(node, ast.Dict):
                    for map_val in node.values:
                        if map_val is not None:
                            _peel_adapter_func(map_val)
                    return
                if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                    for elt in node.elts:
                        nested = elt.value if isinstance(elt, ast.Starred) else elt
                        _peel_adapter_func(nested)
                    return
                if isinstance(node, ast.Call):
                    # ``list(d.values())[0]`` / adapter peels of Call.func packs.
                    _peel_adapter_func(node.func)
                    for arg in node.args:
                        nested = arg.value if isinstance(arg, ast.Starred) else arg
                        _peel_adapter_func(nested)
                    for kw in node.keywords:
                        if kw.value is not None:
                            _peel_adapter_func(kw.value)

            _peel_adapter_func(value.func)
            is_adapter = any(
                n in _CONTAINER_ADAPTER_NAMES or n in self.adapter_aliases
                for n in func_names
            )
            if is_adapter:
                for arg in value.args:
                    nested = arg.value if isinstance(arg, ast.Starred) else arg
                    if self.is_request_or_state_expr(
                        nested
                    ) or self.packs_request_or_state_identity(nested):
                        return True
                for kw in value.keywords:
                    if kw.value is None:
                        continue
                    if self.is_request_or_state_expr(
                        kw.value
                    ) or self.packs_request_or_state_identity(kw.value):
                        return True
            # ``from operator import itemgetter as ig`` / bare Name projections.
            if isinstance(value.func, ast.Name) and (
                value.func.id in _OPERATOR_PROJECTION_NAMES
                or value.func.id in self.operator_projection_aliases
            ):
                for arg in value.args:
                    nested = arg.value if isinstance(arg, ast.Starred) else arg
                    if self.is_request_or_state_expr(
                        nested
                    ) or self.packs_request_or_state_identity(nested):
                        return True
            # operator.getitem / itemgetter / attrgetter / methodcaller, including
            # ``import operator as op`` aliases (attr name is decisive).
            if (
                isinstance(value.func, ast.Attribute)
                and value.func.attr in _OPERATOR_PROJECTION_ATTRS
            ):
                for arg in value.args:
                    nested = arg.value if isinstance(arg, ast.Starred) else arg
                    if self.is_request_or_state_expr(
                        nested
                    ) or self.packs_request_or_state_identity(nested):
                        return True
            # ``operator.itemgetter("s")(packed)`` / ``itemgetter("s")(packed)`` /
            # ``ig("s")(packed)`` / ``operator.methodcaller("get", "s")(packed)`` /
            # ``getattr(packed, "get")("s")``.
            if isinstance(value.func, ast.Call):
                inner = value.func
                inner_attr: str | None = None
                if isinstance(inner.func, ast.Attribute):
                    inner_attr = inner.func.attr
                elif isinstance(inner.func, ast.Name):
                    inner_attr = self.operator_projection_aliases.get(
                        inner.func.id, inner.func.id
                    )
                if inner_attr in {"itemgetter", "attrgetter", "methodcaller"}:
                    for arg in value.args:
                        nested = arg.value if isinstance(arg, ast.Starred) else arg
                        if self.is_request_or_state_expr(
                            nested
                        ) or self.packs_request_or_state_identity(nested):
                            return True
                    if inner_attr == "attrgetter":
                        for arg in value.args:
                            nested = arg.value if isinstance(arg, ast.Starred) else arg
                            if self.is_request_or_state_expr(nested) or self.classify(
                                nested
                            ).any_alias:
                                return True
                # ``getattr(packed, "get")("s")`` — view attr projected via getattr.
                getattr_name = None
                if (
                    isinstance(inner.func, ast.Name)
                    and inner.func.id == "getattr"
                    and len(inner.args) >= 2
                    and isinstance(inner.args[1], ast.Constant)
                    and isinstance(inner.args[1].value, str)
                ):
                    getattr_name = inner.args[1].value
                if getattr_name in _CONTAINER_VIEW_ATTRS and inner.args:
                    recv = inner.args[0]
                    if self.is_request_or_state_expr(
                        recv
                    ) or self.packs_request_or_state_identity(recv):
                        return True
            return False
        return False

    def call_iter_carries_request_or_state_identity(self, call: ast.Call) -> bool:
        """True when a for/async-for Call iter may yield request/state identity.

        Covers generators and adapters: ``gen([request.state])``,
        ``gen(request.state)``, ``map(f, [request.state])``. Broader than
        :meth:`packs_request_or_state_identity` because any Call receiving
        identity as an iter is residual (Unknown > false PASS).
        """

        if self.call_receives_request_or_state(call):
            return True
        if self.packs_request_or_state_identity(call):
            return True
        for arg in call.args:
            nested = arg.value if isinstance(arg, ast.Starred) else arg
            if self.packs_request_or_state_identity(nested):
                return True
        for kw in call.keywords:
            if kw.value is not None and self.packs_request_or_state_identity(kw.value):
                return True
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
            if isinstance(node, ast.NamedExpr):
                if self.is_state_dict_surface(
                    node.value
                ) or self.packs_request_or_state_identity(node.value):
                    return True
            # Comprehension / generator iters packing request.state escape the
            # Name-alias theorem (``setattr(s, …) for s in [request.state]``).
            if isinstance(
                node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
            ):
                for gen in node.generators:
                    if self.is_request_or_state_expr(
                        gen.iter
                    ) or self.packs_request_or_state_identity(gen.iter):
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


def join_request_state_alias_envs(
    states: Sequence[_RequestStateAliasEnv],
) -> _RequestStateAliasEnv:
    """Join request/state alias envs across feasible CF predecessors (#171).

    Must-alias is the intersection of must sets: a name is must-K only when
    every predecessor carries exact kind K. May-alias is the union of
    (must ∪ may) across predecessors minus the resulting must set, so a name
    that aliases on only some predecessors remains visible for dynamic write
    accounting without contributing exact closed-world authority.

    Cross-kind disagreement (request-kind on one predecessor, state-kind on
    another) keeps the name in both may sets. Dropping the conflict would omit
    governed state writes reachable through the state-kind predecessor.
    """

    if not states:
        raise ValueError("join_request_state_alias_envs requires at least one predecessor")
    must_request = set(states[0].request_names)
    must_state = set(states[0].state_names)
    may_request: set[str] = set()
    may_state: set[str] = set()
    for state in states:
        must_request &= state.request_names
        must_state &= state.state_names
        may_request |= state.request_names | state.may_request_names
        may_state |= state.state_names | state.may_state_names
    may_request -= must_request
    may_state -= must_state
    adapter_aliases: set[str] = set()
    nullcontext_aliases: set[str] = {"nullcontext"}
    container_adapter_packs: dict[str, dict[object, tuple[str, ...]]] = {}
    operator_projection_aliases: dict[str, str] = {}
    ns_projection_aliases: set[str] = set()
    ns_dict_names: set[str] = set()
    string_constant_names: dict[str, str] = {}
    static_constant_names: dict[str, object] = {}
    dict_view_products: dict[str, str] = {}
    bound_view_receivers: dict[str, str] = {}
    bound_view_expr_receivers: dict[str, ast.AST] = {}
    sequence_string_lists: dict[str, tuple[str, ...]] = {}
    sequence_literal_aliases: dict[str, ast.AST] = {}
    itemgetter_products: dict[str, object] = {}
    methodcaller_factories: dict[str, ast.Call] = {}
    partial_factories: dict[str, ast.Call] = {}
    for state in states:
        adapter_aliases |= state.adapter_aliases
        nullcontext_aliases |= state.nullcontext_aliases
        for name, pack in state.container_adapter_packs.items():
            bucket = container_adapter_packs.setdefault(name, {})
            for key, names in pack.items():
                prev = bucket.get(key, ())
                bucket[key] = tuple(dict.fromkeys([*prev, *names]))
        operator_projection_aliases.update(state.operator_projection_aliases)
        ns_projection_aliases |= state.ns_projection_aliases
        ns_dict_names |= state.ns_dict_names
        string_constant_names.update(state.string_constant_names)
        static_constant_names.update(state.static_constant_names)
        dict_view_products.update(state.dict_view_products)
        bound_view_receivers.update(state.bound_view_receivers)
        bound_view_expr_receivers.update(state.bound_view_expr_receivers)
        sequence_string_lists.update(state.sequence_string_lists)
        sequence_literal_aliases.update(state.sequence_literal_aliases)
        itemgetter_products.update(state.itemgetter_products)
        methodcaller_factories.update(state.methodcaller_factories)
        partial_factories.update(state.partial_factories)
    return _RequestStateAliasEnv(
        request_names=must_request,
        state_names=must_state,
        may_request_names=may_request,
        may_state_names=may_state,
        adapter_aliases=adapter_aliases,
        nullcontext_aliases=nullcontext_aliases,
        container_adapter_packs=container_adapter_packs,
        operator_projection_aliases=operator_projection_aliases,
        ns_projection_aliases=ns_projection_aliases,
        ns_dict_names=ns_dict_names,
        string_constant_names=string_constant_names,
        static_constant_names=static_constant_names,
        dict_view_products=dict_view_products,
        bound_view_receivers=bound_view_receivers,
        bound_view_expr_receivers=bound_view_expr_receivers,
        sequence_string_lists=sequence_string_lists,
        sequence_literal_aliases=sequence_literal_aliases,
        itemgetter_products=itemgetter_products,
        methodcaller_factories=methodcaller_factories,
        partial_factories=partial_factories,
    )


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
        # Classify covers IfExp / NamedExpr joins; must_state → exact theorem.
        classification = env.classify(arg)
        if classification.must_state:
            return True, True
        if classification.may_state:
            return True, False
        if (
            isinstance(arg, ast.Attribute)
            and arg.attr == "state"
            and isinstance(arg.value, ast.Name)
        ):
            if arg.value.id in env.request_names:
                return True, True
            if arg.value.id in env.may_request_names:
                return True, False
            return True, False
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


def _all_function_param_names(
    fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> tuple[str, ...]:
    """All parameter names including ``self``/``cls``/vararg/kwarg."""

    names: list[str] = []
    for arg in list(fn.args.posonlyargs) + list(fn.args.args):
        names.append(arg.arg)
    if fn.args.vararg is not None:
        names.append(fn.args.vararg.arg)
    for arg in fn.args.kwonlyargs:
        names.append(arg.arg)
    if fn.args.kwarg is not None:
        names.append(fn.args.kwarg.arg)
    return tuple(names)


def _free_var_names(
    fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> frozenset[str]:
    """Names loaded from an enclosing scope (late-bound closure cells)."""

    bound: set[str] = set(_all_function_param_names(fn))
    loaded: set[str] = set()

    class _Visitor(ast.NodeVisitor):
        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, ast.Load):
                loaded.add(node.id)
            elif isinstance(node.ctx, (ast.Store, ast.Del)):
                bound.add(node.id)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            bound.add(node.name)
            # Nested bodies have their own scope; do not collect here.

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            bound.add(node.name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            bound.add(node.name)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            # Nested lambda scope is independent.
            return

    if isinstance(fn, ast.Lambda):
        _Visitor().visit(fn.body)
    else:
        for stmt in fn.body:
            _Visitor().visit(stmt)
    return frozenset(name for name in loaded if name not in bound)


@dataclass(frozen=True)
class _DefaultCapture:
    """Definition-time alias + provenance summary for one omitted formal."""

    classification: AliasClassification
    origin: ValueOriginEvidence


@dataclass(frozen=True)
class _ReturnedClosure:
    """Nested callable returned from a followed frame with lexical capture.

    Free-var classifications are snapshotted at return/assign time from the
    callee's enclosing lookup (including intermediate frame locals). Call-time
    seeding joins this capture with the caller's late-bound cell stack so
    ``fn = mid(); state = request.state; fn()`` stays precise without blanket
    escape on every nested ``return poison``.
    """

    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
    free_vars: frozenset[str]
    default_captures: Mapping[str, _DefaultCapture]
    free_classifications: Mapping[str, AliasClassification]


def _capture_default_summaries(
    fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
    *,
    request_aliases: _RequestStateAliasEnv,
    classify_origin,
) -> dict[str, _DefaultCapture]:
    """Snapshot default expressions under the definition-time environment.

    Defaults evaluate once at function definition. Call sites that omit the
    formal must reuse this capture — never re-evaluate under call-time env.
    """

    captures: dict[str, _DefaultCapture] = {}
    positional = list(fn.args.posonlyargs) + list(fn.args.args)
    defaults = list(fn.args.defaults)
    if defaults:
        for arg, default_expr in zip(positional[-len(defaults) :], defaults):
            captures[arg.arg] = _DefaultCapture(
                classification=request_aliases.classify(default_expr),
                origin=classify_origin(default_expr),
            )
    for arg, default_expr in zip(fn.args.kwonlyargs, fn.args.kw_defaults):
        if default_expr is None:
            continue
        captures[arg.arg] = _DefaultCapture(
            classification=request_aliases.classify(default_expr),
            origin=classify_origin(default_expr),
        )
    return captures


def _name_carries_governed_identity(
    name: str, aliases: _RequestStateAliasEnv
) -> bool:
    return name in aliases.all_request_names() or name in aliases.all_state_names()


def _bind_call_actuals(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
) -> dict[str, ast.AST] | None:
    """Map callee formals to call actuals under the ordinary-argument theorem.

    Returns None when *args/**kwargs, unexpected keywords, or arity mismatch
    make the binding unresolvable (escape → UNKNOWN). Omitted formals with
    defaults are left absent so callers can fill definition-time captures.
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


def _match_pattern_bound_names(pattern: ast.AST) -> set[str]:
    """Names bound by a ``match`` pattern (request/state alias tracking)."""

    names: set[str] = set()
    if isinstance(pattern, ast.MatchAs):
        if pattern.name:
            names.add(pattern.name)
        if pattern.pattern is not None:
            names.update(_match_pattern_bound_names(pattern.pattern))
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name:
            names.add(pattern.name)
    elif isinstance(pattern, ast.MatchMapping):
        if pattern.rest:
            names.add(pattern.rest)
        for item in pattern.patterns:
            names.update(_match_pattern_bound_names(item))
    elif isinstance(pattern, (ast.MatchSequence, ast.MatchOr)):
        for item in pattern.patterns:
            names.update(_match_pattern_bound_names(item))
    elif isinstance(pattern, ast.MatchClass):
        for item in pattern.patterns:
            names.update(_match_pattern_bound_names(item))
        for item in pattern.kwd_patterns:
            names.update(_match_pattern_bound_names(item))
    return names


def _match_pattern_has_star(pattern: ast.AST) -> bool:
    """True when a pattern binds via ``MatchStar`` / mapping ``rest``."""

    if isinstance(pattern, ast.MatchStar):
        return True
    if isinstance(pattern, ast.MatchAs) and pattern.pattern is not None:
        return _match_pattern_has_star(pattern.pattern)
    if isinstance(pattern, ast.MatchMapping):
        if pattern.rest:
            return True
        return any(_match_pattern_has_star(item) for item in pattern.patterns)
    if isinstance(pattern, (ast.MatchSequence, ast.MatchOr)):
        return any(_match_pattern_has_star(item) for item in pattern.patterns)
    if isinstance(pattern, ast.MatchClass):
        return any(
            _match_pattern_has_star(item)
            for item in (*pattern.patterns, *pattern.kwd_patterns)
        )
    return False


def _name_classification_from_env(
    aliases: _RequestStateAliasEnv, name: str
) -> AliasClassification:
    return AliasClassification(
        must_request=name in aliases.request_names,
        may_request=name in aliases.may_request_names,
        must_state=name in aliases.state_names,
        may_state=name in aliases.may_state_names,
    )


def _uncertain_alias_flow_in_expr(
    aliases: _RequestStateAliasEnv, value: ast.AST
) -> AliasClassification:
    """May-only join of request/state identities embedded in ``value``."""

    parts: list[AliasClassification] = []
    direct = aliases.classify(value)
    if direct.any_alias:
        parts.append(direct.as_may_only())
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        for elt in value.elts:
            nested = elt.value if isinstance(elt, ast.Starred) else elt
            part = aliases.classify(nested)
            if part.any_alias:
                parts.append(part.as_may_only())
    elif isinstance(value, ast.Dict):
        for key, val in zip(value.keys, value.values):
            for item in (key, val):
                if item is None:
                    continue
                part = aliases.classify(item)
                if part.any_alias:
                    parts.append(part.as_may_only())
    elif isinstance(value, ast.Call):
        for arg in value.args:
            nested = arg.value if isinstance(arg, ast.Starred) else arg
            part = aliases.classify(nested)
            if part.any_alias:
                parts.append(part.as_may_only())
        for kw in value.keywords:
            if kw.value is None:
                continue
            part = aliases.classify(kw.value)
            if part.any_alias:
                parts.append(part.as_may_only())
    return AliasClassification.join_all(parts)


def _apply_match_pattern_alias_bindings(
    aliases: _RequestStateAliasEnv,
    pattern: ast.AST,
    matched: ast.AST,
) -> None:
    """Bind match pattern names from ``matched`` under the alias lattice.

    Subject-capturing ``case object() as x`` / ``case x`` receive
    ``classify(matched)`` instead of being poisoned (poison omitted client
    writes through ``x`` → false PASS). Structural patterns peel literal
    List/Tuple/Dict subjects and keyword-only MatchClass vs keyword Calls
    when shapes align. Positional MatchClass peels are not performed without
    ``__match_args__`` (1:1 Call-arg peel false-PASSed reordered binders).
    Unresolved nested binders are cleared; when the matched value still flows
    request/state identity, they receive a may-only join so governed writes
    stay visible.
    """

    def _bind_name(name: str | None, classification: AliasClassification) -> None:
        if not name:
            return
        aliases.apply_classification(name, classification)

    def _clear_or_flow(names: set[str], value: ast.AST) -> None:
        local_flow = _uncertain_alias_flow_in_expr(aliases, value)
        for name in names:
            _bind_name(
                name,
                local_flow if local_flow.any_alias else AliasClassification(),
            )

    def _apply(pat: ast.AST, value: ast.AST) -> None:
        if isinstance(pat, ast.MatchAs):
            # ``case x`` / ``case P as x`` capture the matched value itself.
            if pat.name:
                _bind_name(pat.name, aliases.classify(value))
            if pat.pattern is not None:
                _apply(pat.pattern, value)
            return
        if isinstance(pat, ast.MatchOr):
            arm_maps: list[dict[str, AliasClassification]] = []
            for alt in pat.patterns:
                snap = aliases.snapshot()
                _apply(alt, value)
                arm_maps.append(
                    {
                        name: _name_classification_from_env(aliases, name)
                        for name in _match_pattern_bound_names(alt)
                    }
                )
                aliases.restore(snap)
            names = set().union(*(arm.keys() for arm in arm_maps)) if arm_maps else set()
            for name in names:
                parts = [arm[name] for arm in arm_maps if name in arm]
                if not parts:
                    continue
                joined = AliasClassification.join_all(parts)
                if len(parts) != len(arm_maps):
                    joined = joined.as_may_only()
                _bind_name(name, joined)
            return
        if isinstance(pat, ast.MatchSequence):
            elts: list[ast.AST] | None = None
            if isinstance(value, (ast.List, ast.Tuple)) and not any(
                isinstance(elt, ast.Starred) for elt in value.elts
            ):
                elts = list(value.elts)
            if (
                elts is not None
                and not any(isinstance(p, ast.MatchStar) for p in pat.patterns)
                and len(pat.patterns) == len(elts)
            ):
                for sub, elt in zip(pat.patterns, elts):
                    _apply(sub, elt)
                return
            _clear_or_flow(_match_pattern_bound_names(pat), value)
            return
        if isinstance(pat, ast.MatchMapping):
            if (
                isinstance(value, ast.Dict)
                and pat.rest is None
                and all(
                    k is not None and isinstance(k, ast.Constant) for k in value.keys
                )
                and all(isinstance(k, ast.Constant) for k in pat.keys)
            ):
                value_by_key = {
                    key.value: val
                    for key, val in zip(value.keys, value.values)
                    if isinstance(key, ast.Constant)
                }
                if all(
                    isinstance(k, ast.Constant) and k.value in value_by_key
                    for k in pat.keys
                ):
                    for key, sub in zip(pat.keys, pat.patterns):
                        assert isinstance(key, ast.Constant)
                        _apply(sub, value_by_key[key.value])
                    return
            _clear_or_flow(_match_pattern_bound_names(pat), value)
            return
        if isinstance(pat, ast.MatchClass):
            if (
                isinstance(value, ast.Call)
                and not any(isinstance(arg, ast.Starred) for arg in value.args)
                and all(kw.arg is not None for kw in value.keywords)
            ):
                kw_map = {kw.arg: kw.value for kw in value.keywords if kw.arg}
                # Keyword-only patterns against keyword construction use explicit
                # attribute names — sound without ``__match_args__``.
                if (
                    pat.kwd_attrs
                    and not pat.patterns
                    and all(key in kw_map for key in pat.kwd_attrs)
                ):
                    for key, sub in zip(pat.kwd_attrs, pat.kwd_patterns):
                        _apply(sub, kw_map[key])
                    return
            # Positional / mixed class patterns require ``__match_args__`` to map
            # Call args onto attributes. Peeling Call positionals 1:1 is unsound
            # when ``__match_args__`` reorders (client write through the real
            # state binder was omitted → false PASS). May-flow Call identity
            # instead; precise ``__match_args__`` peel remains OOS.
            _clear_or_flow(_match_pattern_bound_names(pat), value)
            return
        if isinstance(pat, ast.MatchStar):
            _clear_or_flow({pat.name} if pat.name else set(), value)
            return
        _clear_or_flow(_match_pattern_bound_names(pat), value)

    _apply(pattern, matched)


def _match_pattern_irrefutable(pattern: ast.AST) -> bool:
    """True for patterns that always match (``case _`` / ``case x``)."""

    if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
        return True
    if isinstance(pattern, ast.MatchOr):
        return bool(pattern.patterns) and all(
            _match_pattern_irrefutable(item) for item in pattern.patterns
        )
    return False


def _with_as_body_mutates_names(
    body: Sequence[ast.stmt],
    bound_names: set[str],
) -> bool:
    """True when a with-as bound name is stored via attr/subscript/setattr."""

    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                if isinstance(node.value, ast.Name) and node.value.id in bound_names:
                    return True
            if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
                if isinstance(node.value, ast.Name) and node.value.id in bound_names:
                    return True
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "setattr"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in bound_names
            ):
                return True
    return False


def _match_statement_exhaustive(statement: ast.Match) -> bool:
    """Conservative exhaustiveness: final irrefutable case with no guard.

    A guarded final ``case _ if cond:`` is not exhaustive — when the guard is
    false the body does not run, so the no-match predecessor must be retained
    (#171). Unknown > false PASS.
    """

    if not statement.cases:
        return False
    final = statement.cases[-1]
    return _match_pattern_irrefutable(final.pattern) and final.guard is None


def _collect_writes_in_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    path: str,
    handler_param_names: frozenset[str],
    callee_resolver: CalleeResolver | None = None,
    seed_request_aliases: _RequestStateAliasEnv | None = None,
    seed_alias_state: AliasState | None = None,
    seed_identity_session: RequestTimeIdentitySession | None = None,
    call_stack: frozenset[tuple[str, str]] | None = None,
    depth: int = 0,
    enclosing_alias_envs: tuple[_RequestStateAliasEnv, ...] = (),
    enclosing_origin_states: tuple[AliasState, ...] = (),
    enclosing_local_classes: tuple[Mapping[str, ast.ClassDef], ...] = (),
    enclosing_callable_maps: tuple[
        tuple[
            Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef],
            Mapping[str, ast.Lambda],
            Mapping[str, Sequence[_ReturnedClosure]],
        ],
        ...,
    ] = (),
) -> tuple[list[StateAttributeWrite], list[_ReturnedClosure], bool]:
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

    Request-time callable identity (#167): the shared #166 object-alias
    identity environment is threaded statement-order through this walk so
    handler-body mutations of module exports / callable behavior invalidate
    authorizing resolve from the mutation point onward.
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
    if seed_identity_session is not None:
        identity_session: RequestTimeIdentitySession | None = seed_identity_session
    elif callee_resolver is not None:
        identity_session = begin_request_time_identity_session(
            callee_resolver, path=path, fn=fn
        )
    else:
        identity_session = None

    # Nested callables: bodies execute at call time under lexical env, not at
    # definition under an impoverished empty alias seed (#173 closure theorem).
    local_nested: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    local_lambdas: dict[str, ast.Lambda] = {}
    local_classes: dict[str, ast.ClassDef] = {}
    # Name → class name for ``b = Box()`` instance aliases (closure packing).
    instance_class_of: dict[str, str] = {}
    # Local aliases of ``getattr`` (``g = getattr``) for packed attr peel.
    getattr_aliases: set[str] = {"getattr"}
    nested_default_captures: dict[int, dict[str, _DefaultCapture]] = {}
    nested_free_vars: dict[int, frozenset[str]] = {}
    # Returned / assigned closures: Call id → closures yielded by a followed
    # callee; Name → capture summary for precise ``fn = mid(); fn()`` follow.
    call_returned_closures: dict[int, list[_ReturnedClosure]] = {}
    call_returned_unknown: set[int] = set()
    name_returned_closures: dict[str, list[_ReturnedClosure]] = {}
    name_unknown_callables: set[str] = set()
    returned_closure_captures: dict[int, Mapping[str, AliasClassification]] = {}
    frame_returned_closures: list[_ReturnedClosure] = []
    frame_returned_unknown = False
    # Async: bare Call builds a coroutine; body runs under Await / async entry.
    call_awaitable_callees: dict[
        int, ast.FunctionDef | ast.AsyncFunctionDef
    ] = {}
    name_awaitable_callees: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    # Entry frame returns escape to the unresolved FastAPI caller; nested
    # frames propagate returned closures to the call site instead.
    is_entry_frame = depth == 0 and not stack

    # Callable-Name environment forked/joined across CF (If/While/For/Try/Match)
    # so ``if c: fn = mid() else: fn = noop; fn()`` cannot drop the poison arm.
    _CallableEnv = tuple[
        dict[str, list[_ReturnedClosure]],
        dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        dict[str, ast.Lambda],
        dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        set[str],
    ]

    def _snapshot_callable_env() -> _CallableEnv:
        return (
            {key: list(value) for key, value in name_returned_closures.items()},
            dict(local_nested),
            dict(local_lambdas),
            dict(name_awaitable_callees),
            set(name_unknown_callables),
        )

    def _restore_callable_env(snap: _CallableEnv) -> None:
        returned, nested, lambdas, awaitables, unknown = snap
        name_returned_closures.clear()
        name_returned_closures.update(
            {key: list(value) for key, value in returned.items()}
        )
        local_nested.clear()
        local_nested.update(nested)
        local_lambdas.clear()
        local_lambdas.update(lambdas)
        name_awaitable_callees.clear()
        name_awaitable_callees.update(awaitables)
        name_unknown_callables.clear()
        name_unknown_callables.update(unknown)

    def _clear_callable_name(name: str) -> None:
        name_returned_closures.pop(name, None)
        name_awaitable_callees.pop(name, None)
        name_unknown_callables.discard(name)
        local_nested.pop(name, None)
        local_lambdas.pop(name, None)

    def _join_callable_envs(snaps: Sequence[_CallableEnv]) -> None:
        if not snaps:
            return
        if len(snaps) == 1:
            _restore_callable_env(snaps[0])
            return
        names: set[str] = set()
        for returned, nested, lambdas, awaitables, unknown in snaps:
            names |= (
                set(returned)
                | set(nested)
                | set(lambdas)
                | set(awaitables)
                | set(unknown)
            )
        joined_returned: dict[str, list[_ReturnedClosure]] = {}
        joined_nested: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        joined_lambdas: dict[str, ast.Lambda] = {}
        joined_awaitables: dict[
            str, ast.FunctionDef | ast.AsyncFunctionDef
        ] = {}
        joined_unknown: set[str] = set()
        for name in names:
            closures: list[_ReturnedClosure] = []
            seen: set[int] = set()
            unknown = False
            awaitable_nodes: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
            for returned, nested, lambdas, awaitables, unknowns in snaps:
                if name in unknowns:
                    unknown = True
                if name in returned:
                    for item in returned[name]:
                        if id(item.node) in seen:
                            continue
                        seen.add(id(item.node))
                        closures.append(item)
                elif name in nested:
                    node = nested[name]
                    if id(node) not in seen:
                        seen.add(id(node))
                        closures.append(_snapshot_returned_closure(node))
                elif name in lambdas:
                    node = lambdas[name]
                    if id(node) not in seen:
                        seen.add(id(node))
                        closures.append(_snapshot_returned_closure(node))
                if name in awaitables:
                    awaitable_nodes.append(awaitables[name])
            if unknown:
                joined_unknown.add(name)
            if awaitable_nodes:
                first = awaitable_nodes[0]
                if any(node is not first for node in awaitable_nodes[1:]):
                    joined_unknown.add(name)
                else:
                    joined_awaitables[name] = first
            if not closures:
                continue
            if len(closures) == 1 and name not in joined_unknown:
                node = closures[0].node
                if isinstance(node, ast.Lambda):
                    joined_lambdas[name] = node
                else:
                    joined_nested[name] = node
                joined_returned[name] = list(closures)
            else:
                joined_returned[name] = list(closures)
        _restore_callable_env(
            (
                joined_returned,
                joined_nested,
                joined_lambdas,
                joined_awaitables,
                joined_unknown,
            )
        )
        for name, closures in joined_returned.items():
            for closure in closures:
                nested_free_vars[id(closure.node)] = closure.free_vars
                nested_default_captures[id(closure.node)] = dict(
                    closure.default_captures
                )
                returned_closure_captures[id(closure.node)] = dict(
                    closure.free_classifications
                )

    def _classify(node: ast.AST) -> ValueOriginEvidence:
        return classify_expression_origin(
            node,
            path=path,
            handler_param_names=handler_param_names,
            alias_state=alias_state,
        )

    def _register_nested_callable(
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
        *,
        name: str | None,
    ) -> None:
        captures = _capture_default_summaries(
            node, request_aliases=request_aliases, classify_origin=_classify
        )
        free = _free_var_names(node)
        nested_default_captures[id(node)] = captures
        nested_free_vars[id(node)] = free
        if name is None:
            return
        _clear_callable_name(name)
        if isinstance(node, ast.Lambda):
            local_lambdas[name] = node
            local_nested.pop(name, None)
        else:
            local_nested[name] = node
            local_lambdas.pop(name, None)

    def _closure_carries_governed_identity(
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
        *,
        capture_env: Mapping[str, AliasClassification] | None = None,
    ) -> bool:
        """True when free vars / defaults carry request/state via the lexical stack.

        Nested mid-frames often do not bind the cell themselves; late-bound
        lookup must walk ``enclosing_alias_envs`` (same as call-time seeding)
        or ``return poison`` from ``mid`` omits the escape and false-PASSes.
        Optional ``capture_env`` joins return-time snapshots for returned
        closures whose cells live in intermediate frames.
        """

        free = nested_free_vars.get(id(node), _free_var_names(node))
        for name in free:
            if _lookup_enclosing_name_classification(name).any_alias:
                return True
            if capture_env is not None and capture_env.get(
                name, AliasClassification()
            ).any_alias:
                return True
            stored = returned_closure_captures.get(id(node), {})
            if stored.get(name, AliasClassification()).any_alias:
                return True
        captures = nested_default_captures.get(id(node), {})
        return any(capture.classification.any_alias for capture in captures.values())

    def _snapshot_returned_closure(
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
    ) -> _ReturnedClosure:
        free = nested_free_vars.get(id(node), _free_var_names(node))
        captures = dict(nested_default_captures.get(id(node), {}))
        classifications: dict[str, AliasClassification] = {}
        for name in free:
            classifications[name] = _lookup_enclosing_name_classification(name)
        prior = returned_closure_captures.get(id(node))
        if prior:
            for name, classification in prior.items():
                classifications[name] = AliasClassification.join(
                    classifications.get(name, AliasClassification()),
                    classification,
                )
        return _ReturnedClosure(
            node=node,
            free_vars=free,
            default_captures=captures,
            free_classifications=classifications,
        )

    def _closure_is_residual_escape(closure: _ReturnedClosure) -> bool:
        if closure.free_vars:
            return True
        return any(
            capture.classification.any_alias
            for capture in closure.default_captures.values()
        ) or _closure_carries_governed_identity(
            closure.node, capture_env=closure.free_classifications
        )

    def _install_returned_closures(
        name: str,
        closures: Sequence[_ReturnedClosure],
        *,
        unknown: bool = False,
    ) -> None:
        if not closures and not unknown:
            return
        name_awaitable_callees.pop(name, None)
        if unknown:
            name_unknown_callables.add(name)
        else:
            name_unknown_callables.discard(name)
        if not closures:
            local_nested.pop(name, None)
            local_lambdas.pop(name, None)
            name_returned_closures.pop(name, None)
            return
        name_returned_closures[name] = list(closures)
        if len(closures) == 1 and not unknown:
            node = closures[0].node
            if isinstance(node, ast.Lambda):
                local_lambdas[name] = node
                local_nested.pop(name, None)
            else:
                local_nested[name] = node
                local_lambdas.pop(name, None)
        else:
            # May-set of distinct returned callables: keep Name out of the
            # single-callee map and follow every arm at call time.
            local_nested.pop(name, None)
            local_lambdas.pop(name, None)
        for closure in closures:
            nested_free_vars[id(closure.node)] = closure.free_vars
            nested_default_captures[id(closure.node)] = dict(
                closure.default_captures
            )
            returned_closure_captures[id(closure.node)] = dict(
                closure.free_classifications
            )

    def _lookup_local_class(name: str) -> ast.ClassDef | None:
        """Resolve a local class in this frame or an enclosing lexical frame."""

        cls = local_classes.get(name)
        if cls is not None:
            return cls
        for env in reversed(enclosing_local_classes):
            cls = env.get(name)
            if cls is not None:
                return cls
        return None

    def _ensure_call_callable_products(
        call: ast.Call,
    ) -> tuple[list[_ReturnedClosure], bool]:
        """Return/cache callable products for ``call``, including ``Cls()``.

        Nested ``return Cls()`` / ``obj = Cls(); obj()`` / ``Cls()()`` must see
        governed ``__call__`` even when the constructor is not a followed
        function frame. Also peels packed constructors ``xs[0]()`` after
        match-star / container class seeds (Unknown > false PASS).
        """

        returned = list(call_returned_closures.get(id(call), []))
        unknown = id(call) in call_returned_unknown
        if returned or unknown:
            return returned, unknown
        func = call.func
        while isinstance(func, ast.NamedExpr):
            func = func.value
        cls: ast.ClassDef | None = None
        if isinstance(func, ast.Name):
            cls = _lookup_local_class(func.id)
        else:
            # Shared constructor peel: ``[Cls][0]()`` / ``xs[0]()`` after
            # star-bind seeds ``local_classes[xs] = Cls``.
            cls = _resolve_class_constructor_alias(func)
            if cls is None and isinstance(func, ast.Subscript):
                base = func.value
                while isinstance(base, ast.NamedExpr):
                    base = base.value
                if isinstance(base, ast.Name):
                    cls = _lookup_local_class(base.id)
        if cls is not None:
            method = _governed_class_method(cls, "__call__")
            if method is not None:
                closure = _snapshot_returned_closure(method)
                call_returned_closures[id(call)] = [closure]
                nested_free_vars[id(closure.node)] = closure.free_vars
                nested_default_captures[id(closure.node)] = dict(
                    closure.default_captures
                )
                returned_closure_captures[id(closure.node)] = dict(
                    closure.free_classifications
                )
                return [closure], False
        return [], False

    def _bind_call_product_to_name(name: str, call: ast.Call) -> bool:
        """Bind Name to returned closures or async awaitables from ``call``."""

        returned, unknown = _ensure_call_callable_products(call)
        if returned or unknown:
            _install_returned_closures(
                name, returned, unknown=unknown
            )
            return True
        awaitable = call_awaitable_callees.get(id(call))
        if awaitable is not None:
            name_unknown_callables.discard(name)
            name_awaitable_callees[name] = awaitable
            return True
        return False

    def _local_callable_for_name(
        name: str,
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | None:
        if name in local_nested:
            return local_nested[name]
        if name in local_lambdas:
            return local_lambdas[name]
        return None

    def _local_callables_for_name(
        name: str,
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda]:
        returned = name_returned_closures.get(name)
        if returned:
            return [item.node for item in returned]
        single = _local_callable_for_name(name)
        if single is not None:
            return [single]
        # Methods / nested frames may call outer nested defs (``return mid()``
        # from ``__enter__``) — resolve through the lexical callable stack.
        for nested, lambdas, returned_map in reversed(enclosing_callable_maps):
            if name in returned_map:
                return [item.node for item in returned_map[name]]
            if name in nested:
                return [nested[name]]
            if name in lambdas:
                return [lambdas[name]]
        return []

    def _governed_local_callables_from_expr(
        expr: ast.AST,
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda]:
        """Local nested/lambda callables with governed identity packed in ``expr``.

        Mirrors the identity-session packed-callee surface (IfExp/BoolOp/
        NamedExpr/containers/Subscript) and also resolves Names bound to
        nested defs — ``[poison][0]()`` / ``(poison if f else noop)()``.
        """

        found: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda] = []
        seen: set[int] = set()

        def _add(
            node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
        ) -> None:
            if id(node) in seen:
                return
            if not _closure_carries_governed_identity(node):
                return
            seen.add(id(node))
            found.append(node)

        def _walk(node: ast.AST) -> None:
            if isinstance(node, ast.NamedExpr):
                _walk(node.value)
                return
            if isinstance(node, ast.Lambda):
                _add(node)
                return
            if isinstance(node, ast.Name):
                for callee in _local_callables_for_name(node.id):
                    _add(callee)
                return
            if isinstance(node, ast.Call):
                for item in _ensure_call_callable_products(node)[0]:
                    _add(item.node)
                return
            if isinstance(node, ast.IfExp):
                _walk(node.body)
                _walk(node.orelse)
                return
            if isinstance(node, ast.BoolOp):
                for operand in node.values:
                    _walk(operand)
                return
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
                for elt in node.elts:
                    nested = elt.value if isinstance(elt, ast.Starred) else elt
                    _walk(nested)
                return
            if isinstance(node, ast.Dict):
                for value in node.values:
                    if value is not None:
                        _walk(value)
                return
            if isinstance(node, ast.Subscript):
                _walk(node.value)
                return

        _walk(expr)
        return found

    def _expr_packs_governed_local_callable(expr: ast.AST) -> bool:
        return bool(_governed_local_callables_from_expr(expr))

    def _bind_callable_products_to_name(name: str, value: ast.AST) -> None:
        """Install callable products from ``value`` onto ``name`` when known."""

        if isinstance(value, ast.Name):
            if value.id in name_unknown_callables:
                name_unknown_callables.add(name)
            if value.id in name_returned_closures:
                _install_returned_closures(
                    name,
                    name_returned_closures[value.id],
                    unknown=value.id in name_unknown_callables,
                )
                return
            if value.id in local_nested:
                local_nested[name] = local_nested[value.id]
                local_lambdas.pop(name, None)
                return
            if value.id in local_lambdas:
                local_lambdas[name] = local_lambdas[value.id]
                local_nested.pop(name, None)
                return
            return
        closures, unknown = _callable_products_from_expr(value)
        if closures or unknown:
            _install_returned_closures(name, closures, unknown=unknown)
            return
        if isinstance(value, ast.Call):
            _bind_call_product_to_name(name, value)

    def _apply_match_pattern_callable_bindings(
        pattern: ast.AST,
        matched: ast.AST,
    ) -> None:
        """Bind MatchAs / sequence peels to callable products from ``matched``."""

        def _apply(pat: ast.AST, value: ast.AST) -> None:
            if isinstance(pat, ast.MatchAs):
                if pat.name:
                    _bind_callable_products_to_name(pat.name, value)
                if pat.pattern is not None:
                    _apply(pat.pattern, value)
                return
            if isinstance(pat, ast.MatchSequence) and isinstance(
                value, (ast.List, ast.Tuple)
            ):
                # Literal sequence subjects peel element-wise when lengths
                # align; starred rest stays residual (container packing).
                if any(isinstance(item, ast.MatchStar) for item in pat.patterns):
                    return
                if len(pat.patterns) != len(value.elts):
                    return
                for sub_pat, elt in zip(pat.patterns, value.elts):
                    nested = elt.value if isinstance(elt, ast.Starred) else elt
                    _apply(sub_pat, nested)
                return
            if isinstance(pat, ast.MatchMapping) and isinstance(value, ast.Dict):
                value_by_key: dict[object, ast.AST] = {}
                for map_key, map_val in zip(value.keys, value.values):
                    if (
                        map_key is not None
                        and map_val is not None
                        and isinstance(map_key, ast.Constant)
                    ):
                        value_by_key[map_key.value] = map_val
                fixed_keys: set[object] = set()
                for map_key, sub_pat in zip(pat.keys, pat.patterns):
                    if not isinstance(map_key, ast.Constant):
                        continue
                    fixed_keys.add(map_key.value)
                    nested = value_by_key.get(map_key.value)
                    if nested is not None:
                        _apply(sub_pat, nested)
                if pat.rest is not None:
                    for key, map_val in value_by_key.items():
                        if key in fixed_keys:
                            continue
                        _seed_name_instance_or_class(pat.rest, map_val)
                return
            if isinstance(pat, ast.MatchOr):
                for alt in pat.patterns:
                    _apply(alt, value)

        _apply(pattern, matched)

    def _instance_class_name_from_expr(value: ast.AST) -> str | None:
        """Unique local class name packed/constructed in ``value``, if any.

        Covers ``Box()``, ``Box() if c else Box()``, ``[Box()]``, nested walrus,
        and Name instance aliases so ``xs=[Box()]; xs[0].fn()`` peels.
        """

        cls = _resolve_instance_or_class(value)
        if cls is not None:
            return cls.name
        return None

    def _resolve_class_constructor_alias(
        value: ast.AST,
    ) -> ast.ClassDef | None:
        """Peel packing to a bare class constructor (not ``Cls()`` instance).

        Shared path for ``C = [Cls][0]`` / ``dict``/``set``/``next(iter)`` /
        walrus / ``ns.get`` packs so ``C()()`` observes ``__call__`` the same
        as bare ``C = Cls`` (Unknown > false PASS).
        """

        value = value.value if isinstance(value, ast.NamedExpr) else value
        if isinstance(value, ast.Name):
            return _lookup_local_class(value.id)
        if isinstance(value, ast.Call):
            # ``Cls()`` is instance construction — not a constructor alias.
            # Adapter peels: ``next(iter([Cls]))`` / ``list([Cls])[0]`` path
            # via packing of args, not the Call itself as construction.
            func = value.func
            while isinstance(func, ast.NamedExpr):
                func = func.value
            adapter = False
            if isinstance(func, ast.Name) and func.id in _CONTAINER_ADAPTER_NAMES:
                adapter = True
            elif isinstance(func, ast.Attribute) and func.attr in {
                "get",
                "pop",
                "__getitem__",
                "values",
                "keys",
                "items",
            }:
                # ``ns.get("C")`` / ``d.values()`` / ``d["C"]`` style peels.
                if func.attr == "values":
                    return _resolve_class_constructor_alias(func.value)
                if func.attr == "keys":
                    # ``{Mut: 1}.keys()`` — class tokens live in keys.
                    recv = func.value.value if isinstance(func.value, ast.NamedExpr) else func.value
                    if isinstance(recv, ast.Dict):
                        resolved_keys: ast.ClassDef | None = None
                        for map_key in recv.keys:
                            if map_key is None:
                                continue
                            cls = _resolve_class_constructor_alias(map_key)
                            if cls is None:
                                continue
                            if resolved_keys is None:
                                resolved_keys = cls
                            elif resolved_keys is not cls:
                                return None
                        return resolved_keys
                    return _resolve_class_constructor_alias(recv)
                if func.attr == "items":
                    return _resolve_class_constructor_alias(func.value)
                resolved: ast.ClassDef | None = None
                for arg in value.args:
                    nested = arg.value if isinstance(arg, ast.Starred) else arg
                    cls = _resolve_class_constructor_alias(nested)
                    if cls is None:
                        continue
                    if resolved is None:
                        resolved = cls
                    elif resolved is not cls:
                        return None
                if (
                    func.attr == "get"
                    and len(value.args) >= 2
                    and resolved is None
                ):
                    return _resolve_class_constructor_alias(value.args[1])
                if resolved is not None:
                    return resolved
                return _resolve_class_constructor_alias(func.value)
            if adapter:
                resolved = None
                # ``map(fn, [Cls])`` / ``filter(None, [Cls])`` — peel iterable.
                arg_iter = value.args
                if (
                    isinstance(func, ast.Name)
                    and func.id in {"map", "filter"}
                    and len(value.args) >= 2
                ):
                    arg_iter = value.args[1:]
                for arg in arg_iter:
                    nested = arg.value if isinstance(arg, ast.Starred) else arg
                    cls = _resolve_class_constructor_alias(nested)
                    if cls is None:
                        continue
                    if resolved is None:
                        resolved = cls
                    elif resolved is not cls:
                        return None
                return resolved
            return None
        if isinstance(value, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            if value.generators:
                return _resolve_class_constructor_alias(value.generators[0].iter)
            return None
        if isinstance(value, ast.DictComp):
            if value.generators:
                return _resolve_class_constructor_alias(value.generators[0].iter)
            return None
        if isinstance(value, ast.IfExp):
            left = _resolve_class_constructor_alias(value.body)
            right = _resolve_class_constructor_alias(value.orelse)
            if left is not None and (right is None or left is right):
                return left
            if right is not None and left is None:
                return right
            return None
        if isinstance(value, ast.BoolOp):
            resolved = None
            for operand in value.values:
                cls = _resolve_class_constructor_alias(operand)
                if cls is None:
                    continue
                if resolved is None:
                    resolved = cls
                elif resolved is not cls:
                    return None
            return resolved
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            resolved = None
            for elt in value.elts:
                nested = elt.value if isinstance(elt, ast.Starred) else elt
                cls = _resolve_class_constructor_alias(nested)
                if cls is None:
                    continue
                if resolved is None:
                    resolved = cls
                elif resolved is not cls:
                    return None
            return resolved
        if isinstance(value, ast.Dict):
            resolved = None
            for map_val in value.values:
                if map_val is None:
                    continue
                cls = _resolve_class_constructor_alias(map_val)
                if cls is None:
                    continue
                if resolved is None:
                    resolved = cls
                elif resolved is not cls:
                    return None
            return resolved
        if isinstance(value, ast.Subscript):
            if isinstance(value.value, ast.Dict) and isinstance(
                value.slice, ast.Constant
            ):
                for map_key, map_val in zip(value.value.keys, value.value.values):
                    if (
                        map_val is not None
                        and isinstance(map_key, ast.Constant)
                        and map_key.value == value.slice.value
                    ):
                        return _resolve_class_constructor_alias(map_val)
            return _resolve_class_constructor_alias(value.value)
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.BitOr):
            left = _resolve_class_constructor_alias(value.left)
            right = _resolve_class_constructor_alias(value.right)
            return left or right
        return None

    def _seed_name_instance_or_class(
        name: str, value: ast.AST, *, observe_session: bool = True
    ) -> None:
        """Shared seed for instance carriers and class constructor aliases.

        ``observe_session`` emits the synthetic element alias into the identity
        session. Callers that bind ``name`` to the *whole* value (Assign / AnnAssign
        already observed by the session) must pass ``False``: a synthetic
        ``d = Cls`` for ``d = {"c": Cls}`` would clobber the container pack.
        """

        # Class constructor aliases first (packed ``[Cls][0]`` / bare ``Cls``).
        src_cls = _resolve_class_constructor_alias(value)
        if src_cls is not None:
            local_classes[name] = src_cls
            if identity_session is not None and observe_session:
                identity_session.observe_statement(
                    ast.Assign(
                        targets=[ast.Name(id=name, ctx=ast.Store())],
                        value=ast.Name(id=src_cls.name, ctx=ast.Load()),
                    )
                )
            # Constructor alias is not an instance carrier.
            instance_class_of.pop(name, None)
            return
        packed_cls = _instance_class_name_from_expr(value)
        if packed_cls is not None:
            instance_class_of[name] = packed_cls
        if isinstance(value, ast.Name):
            src_cls = _lookup_local_class(value.id)
            if src_cls is not None:
                local_classes[name] = src_cls
                if identity_session is not None and observe_session:
                    identity_session.observe_statement(
                        ast.Assign(
                            targets=[ast.Name(id=name, ctx=ast.Store())],
                            value=ast.Name(id=value.id, ctx=ast.Load()),
                        )
                    )

    def _seed_assign_target_instance_bindings(
        target: ast.AST, value: ast.AST, *, observe_session: bool = True
    ) -> None:
        """Seed For/with/comp targets from packed Box/class carriers."""

        value = value.value if isinstance(value, ast.NamedExpr) else value
        # ``for C in d.values()/keys()/items()`` / ``map`` / comps — peel iter.
        if isinstance(value, ast.Call):
            func = value.func
            while isinstance(func, ast.NamedExpr):
                func = func.value
            if isinstance(func, ast.Attribute) and func.attr == "items":
                # ``for k, C in {"c": Mut}.items()`` — seed value binders.
                if (
                    isinstance(target, (ast.Tuple, ast.List))
                    and len(target.elts) >= 2
                    and isinstance(func.value, ast.Dict)
                ):
                    for map_val in func.value.values:
                        if map_val is None:
                            continue
                        _seed_assign_target_instance_bindings(
                            target.elts[1], map_val, observe_session=observe_session
                        )
                    return
                _seed_assign_target_instance_bindings(
                    target, func.value, observe_session=observe_session
                )
                return
            if isinstance(func, ast.Attribute) and func.attr in {"values", "keys"}:
                recv = func.value
                if func.attr == "keys" and isinstance(recv, ast.Dict):
                    for map_key in recv.keys:
                        if map_key is None:
                            continue
                        _seed_assign_target_instance_bindings(
                            target, map_key, observe_session=observe_session
                        )
                    return
                _seed_assign_target_instance_bindings(
                    target, recv, observe_session=observe_session
                )
                return
            if isinstance(func, ast.Name) and func.id in {"map", "filter"}:
                if len(value.args) >= 2:
                    _seed_assign_target_instance_bindings(
                        target, value.args[1], observe_session=observe_session
                    )
                    return
        if isinstance(value, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            if value.generators:
                _seed_assign_target_instance_bindings(
                    target, value.generators[0].iter, observe_session=observe_session
                )
                return
        if isinstance(target, ast.Name):
            _seed_name_instance_or_class(
                target.id, value, observe_session=observe_session
            )
            return
        if isinstance(target, ast.Starred):
            _seed_assign_target_instance_bindings(
                target.value, value, observe_session=observe_session
            )
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(
                value.elts
            ):
                for elt_t, elt_v in zip(target.elts, value.elts):
                    nested_t = elt_t.value if isinstance(elt_t, ast.Starred) else elt_t
                    nested_v = elt_v.value if isinstance(elt_v, ast.Starred) else elt_v
                    _seed_assign_target_instance_bindings(
                        nested_t, nested_v, observe_session=observe_session
                    )
                return
            # ``for (x,) in [(Box(),)]`` / starred packs: peel iter class once.
            packed_cls = _instance_class_name_from_expr(value)
            if packed_cls is not None:
                for name in _collect_assign_target_names(target):
                    instance_class_of[name] = packed_cls

    def _apply_match_pattern_instance_class_bindings(
        pattern: ast.AST,
        matched: ast.AST,
    ) -> None:
        """Seed instance_class_of / local_classes through match peels."""

        def _apply(pat: ast.AST, value: ast.AST) -> None:
            if isinstance(pat, ast.MatchAs):
                if pat.name:
                    _seed_name_instance_or_class(pat.name, value)
                if pat.pattern is not None:
                    _apply(pat.pattern, value)
                return
            if isinstance(pat, ast.MatchSequence) and isinstance(
                value, (ast.List, ast.Tuple)
            ):
                has_star = any(
                    isinstance(item, ast.MatchStar) for item in pat.patterns
                )
                if has_star or len(pat.patterns) != len(value.elts):
                    # Star / length-mismatch: still peel elements into binders
                    # so ``case (*xs,): xs[0]()`` / ``case [*xs]:`` seed.
                    for elt in value.elts:
                        nested = elt.value if isinstance(elt, ast.Starred) else elt
                        ctor = _resolve_class_constructor_alias(nested)
                        inst = _instance_class_name_from_expr(nested)
                        for name in _match_pattern_bound_names(pat):
                            if ctor is not None:
                                local_classes[name] = ctor
                            elif inst is not None:
                                instance_class_of[name] = inst
                    for sub_pat, elt in zip(pat.patterns, value.elts):
                        if isinstance(sub_pat, ast.MatchStar):
                            continue
                        nested = elt.value if isinstance(elt, ast.Starred) else elt
                        _apply(sub_pat, nested)
                    return
                for sub_pat, elt in zip(pat.patterns, value.elts):
                    nested = elt.value if isinstance(elt, ast.Starred) else elt
                    _apply(sub_pat, nested)
                return
            if isinstance(pat, ast.MatchMapping) and isinstance(value, ast.Dict):
                # ``**rest`` must not abandon fixed key class peels.
                value_by_key: dict[object, ast.AST] = {}
                for map_key, map_val in zip(value.keys, value.values):
                    if (
                        map_key is not None
                        and map_val is not None
                        and isinstance(map_key, ast.Constant)
                    ):
                        value_by_key[map_key.value] = map_val
                fixed_keys: set[object] = set()
                for map_key, sub_pat in zip(pat.keys, pat.patterns):
                    if not isinstance(map_key, ast.Constant):
                        continue
                    fixed_keys.add(map_key.value)
                    nested = value_by_key.get(map_key.value)
                    if nested is not None:
                        _apply(sub_pat, nested)
                # ``case {**rest}: rest["c"]()`` — seed remaining keys /
                # ``rest["p"]`` MappingProxyType adapter packs (do not alias
                # ``rest`` itself as MappingProxyType — only the packed key).
                if pat.rest is not None:
                    rest_pack: dict[object, tuple[str, ...]] = {}
                    for key, map_val in value_by_key.items():
                        if key in fixed_keys:
                            continue
                        _seed_name_instance_or_class(pat.rest, map_val)
                        names: list[str] = []
                        walk = map_val
                        while isinstance(walk, ast.NamedExpr):
                            walk = walk.value
                        if isinstance(walk, ast.Name):
                            names.append(walk.id)
                            if walk.id in request_aliases.adapter_aliases:
                                names.append("MappingProxyType")
                        elif isinstance(walk, ast.Attribute):
                            names.append(walk.attr)
                        if names:
                            rest_pack[key] = tuple(dict.fromkeys(names))
                    if rest_pack:
                        existing = request_aliases.container_adapter_packs.get(
                            pat.rest, {}
                        )
                        merged = dict(existing)
                        for key, names in rest_pack.items():
                            prev = merged.get(key, ())
                            merged[key] = tuple(dict.fromkeys((*prev, *names)))
                        request_aliases.container_adapter_packs[pat.rest] = merged
                return
            if isinstance(pat, ast.MatchOr):
                for alt in pat.patterns:
                    _apply(alt, value)

        _apply(pattern, matched)

    def _seed_match_identity_binds(
        session: RequestTimeIdentitySession,
        pattern: ast.AST,
        matched: ast.AST,
    ) -> None:
        """Seed identity protocol/container packs through match peels.

        Match CF walks case bodies via per-statement observe (not whole-Match
        ``_scan_stmts``), so the binder seed is delegated to the scanner's shared
        element / mapping resolver (walrus, Name-bound and ``dict()`` subjects,
        ``**rest`` packs, star binders) instead of a parallel literal-only peel
        (Unknown > false PASS).
        """

        session.observe_match_binding(pattern, matched)

    def _enter_return_instance_class(
        context_expr: ast.AST, *, async_enter: bool
    ) -> str | None:
        """Class name returned by local ``__enter__`` / ``__aenter__``, if any.

        Shared constructor peel covers ``return Mut`` and pack views
        (``return {Mut: 1}.keys()`` / ``.values()``) so with-as carriers
        seed the same as Assign (Unknown > false PASS).
        """

        if not isinstance(context_expr, ast.Call) or not isinstance(
            context_expr.func, ast.Name
        ):
            return _instance_class_name_from_expr(context_expr)
        cls = _lookup_local_class(context_expr.func.id)
        if cls is None:
            return _instance_class_name_from_expr(context_expr)
        method_name = "__aenter__" if async_enter else "__enter__"
        method = _governed_class_method(cls, method_name)
        if method is None:
            return _instance_class_name_from_expr(context_expr)
        for stmt in method.body:
            if isinstance(stmt, ast.Return) and stmt.value is not None:
                packed = _instance_class_name_from_expr(stmt.value)
                if packed is not None:
                    return packed
                ctor = _resolve_class_constructor_alias(stmt.value)
                if ctor is not None:
                    return ctor.name
        return _instance_class_name_from_expr(context_expr)

    def _note_callable_name_alias(
        target: ast.AST,
        value: ast.AST,
        *,
        control_dependent: bool = False,
    ) -> None:
        if not isinstance(target, ast.Name):
            # Attribute / subscript store of a governed local callable escapes
            # the Name-resolution theorem (``h.fn = poison``; Unknown > PASS).
            if _expr_packs_governed_local_callable(value):
                _record_escape(
                    value,
                    ast.unparse(value),
                    control_dependent=control_dependent,
                )
                return
            # Only residual when a known callable product is packed into a
            # non-Name store. Ordinary BoolOp value joins (``flag or cfg``)
            # are not callable-product surfaces.
            closures, unknown = _callable_products_from_expr(value)
            if closures and (
                unknown
                or any(
                    _closure_is_residual_escape(item) for item in closures
                )
            ):
                _record_escape(
                    value,
                    ast.unparse(value),
                    control_dependent=control_dependent,
                )
            return
        if isinstance(value, ast.Name):
            # Always clear prior returned/awaitable product bindings on rebind
            # so ``fn = mid(); fn = noop; fn()`` cannot keep following poison.
            _clear_callable_name(target.id)
            # Double instance alias: ``b = Box(); c = b`` transfers class peel.
            # Class constructor alias: ``C = Cls; C()()`` observes ``__call__``.
            if value.id in instance_class_of:
                instance_class_of[target.id] = instance_class_of[value.id]
            else:
                instance_class_of.pop(target.id, None)
            src_cls = _lookup_local_class(value.id)
            if src_cls is not None:
                local_classes[target.id] = src_cls
            if value.id in getattr_aliases:
                getattr_aliases.add(target.id)
            request_aliases.note_projection_name_alias(
                target.id, value, getattr_aliases=frozenset(getattr_aliases)
            )
            if value.id in name_unknown_callables:
                name_unknown_callables.add(target.id)
            if value.id in name_returned_closures:
                _install_returned_closures(
                    target.id,
                    name_returned_closures[value.id],
                    unknown=value.id in name_unknown_callables,
                )
                return
            if value.id in local_nested:
                local_nested[target.id] = local_nested[value.id]
                local_lambdas.pop(target.id, None)
                if value.id in name_awaitable_callees:
                    name_awaitable_callees[target.id] = name_awaitable_callees[
                        value.id
                    ]
                return
            if value.id in local_lambdas:
                local_lambdas[target.id] = local_lambdas[value.id]
                local_nested.pop(target.id, None)
                return
            if value.id in name_awaitable_callees:
                name_awaitable_callees[target.id] = name_awaitable_callees[value.id]
                local_nested.pop(target.id, None)
                local_lambdas.pop(target.id, None)
                return
            # Ordinary Name rebind away from a nested callable.
            return
        if isinstance(value, ast.Lambda):
            instance_class_of.pop(target.id, None)
            _register_nested_callable(value, name=target.id)
            return
        if isinstance(value, ast.Attribute):
            request_aliases.note_projection_name_alias(
                target.id, value, getattr_aliases=frozenset(getattr_aliases)
            )
            # Property Name-bind: ``f = Box().fn; f()`` installs getter product.
            cls = _resolve_instance_or_class(value.value)
            if cls is not None:
                method = _local_class_method_for_attr(value)
                if method is not None and _method_is_property(method):
                    synthetic = ast.Call(func=value, args=[], keywords=[])
                    _follow_local_callable_node(
                        method,
                        call=synthetic,
                        control_dependent=control_dependent,
                        execute_async_body=False,
                    )
                    returned = list(call_returned_closures.get(id(synthetic), []))
                    unknown = id(synthetic) in call_returned_unknown
                    if returned or unknown:
                        _install_returned_closures(
                            target.id, returned, unknown=unknown
                        )
                        return
                    _record_escape(
                        value,
                        ast.unparse(value),
                        control_dependent=control_dependent,
                    )
                    return
                prop_getter = _class_property_getter(cls, value.attr)
                if prop_getter is not None:
                    if isinstance(prop_getter, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        synthetic = ast.Call(func=value, args=[], keywords=[])
                        _follow_local_callable_node(
                            prop_getter,
                            call=synthetic,
                            control_dependent=control_dependent,
                            execute_async_body=False,
                        )
                        returned = list(
                            call_returned_closures.get(id(synthetic), [])
                        )
                        unknown = id(synthetic) in call_returned_unknown
                        if returned or unknown:
                            _install_returned_closures(
                                target.id, returned, unknown=unknown
                            )
                            return
                    packed = _governed_local_callables_from_expr(prop_getter)
                    if packed:
                        _install_returned_closures(
                            target.id,
                            [_snapshot_returned_closure(c) for c in packed],
                            unknown=False,
                        )
                        return
                    _record_escape(
                        value,
                        ast.unparse(value),
                        control_dependent=control_dependent,
                    )
                    return
                packed = _init_packed_attr_callables(cls, value.attr)
                if packed:
                    _install_returned_closures(
                        target.id,
                        [_snapshot_returned_closure(c) for c in packed],
                        unknown=False,
                    )
                    return
                if getattr(_init_packed_attr_callables, "dynamic_escape", False):
                    _record_escape(
                        value,
                        ast.unparse(value),
                        control_dependent=control_dependent,
                    )
                    return
            instance_class_of.pop(target.id, None)
        if isinstance(value, (ast.IfExp, ast.BoolOp, ast.NamedExpr)):
            request_aliases.note_projection_name_alias(
                target.id, value, getattr_aliases=frozenset(getattr_aliases)
            )
            # Shared constructor/instance peel before callable-product join.
            _seed_name_instance_or_class(
                target.id, value, observe_session=False
            )
            packed_cls = instance_class_of.get(target.id)
            # Dual-may precise join when both arms are known nested/returned
            # closures; unknown callable arm → fail closed on later call.
            closures, unknown = _callable_products_from_expr(value)
            if (
                not closures
                and not unknown
                and _choice_expr_has_dynamic_callable_arm(value)
            ):
                # ``fn = unknown if c else other; fn()`` — no known arm, but
                # the may-set is still an unresolved callable (Unknown > PASS).
                unknown = True
            if closures or unknown:
                if packed_cls is None and target.id not in local_classes:
                    instance_class_of.pop(target.id, None)
                _install_returned_closures(
                    target.id, closures, unknown=unknown
                )
                return
            if packed_cls is not None or target.id in local_classes:
                return
        if isinstance(value, ast.Call):
            _clear_callable_name(target.id)
            # ``Proxy = getattr(types, "MappingProxyType")`` / operator peels.
            request_aliases.note_projection_name_alias(
                target.id, value, getattr_aliases=frozenset(getattr_aliases)
            )
            # Shared peel: ``b = Box()`` instances and ``C = next(iter([Cls]))``.
            _seed_name_instance_or_class(
                target.id, value, observe_session=False
            )
            if _bind_call_product_to_name(target.id, value):
                return
        else:
            # ``Proxy = vars(types)["MappingProxyType"]`` / container packs.
            request_aliases.note_projection_name_alias(
                target.id, value, getattr_aliases=frozenset(getattr_aliases)
            )
            # Shared peel: class constructor packs (``C = [Cls][0]``) and
            # instance packs (``xs = [Box()]``) — Unknown > false PASS.
            _seed_name_instance_or_class(
                target.id, value, observe_session=False
            )
        # Container packing of governed closures into a Name carrier: the
        # Name is not itself callable under the theorem → residual escape so
        # later ``bucket[0]()`` cannot omit the writer (Unknown > false PASS).
        if _expr_packs_governed_local_callable(value):
            _record_escape(
                value,
                ast.unparse(value),
                control_dependent=control_dependent,
            )
            return
        # Call/container products already handled; residual Call products that
        # were not Name-captured escape via ``_record_dynamic_calls``.

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

    def _lookup_enclosing_name_classification(name: str) -> AliasClassification:
        """Late-bound free-var lookup across the active lexical frame stack.

        Intermediate frames that do not bind ``name`` are skipped, matching
        Python closure cell resolution (``mid`` → nested ``poison`` still sees
        the handler's ``state`` cell).
        """

        classification = request_aliases.classification_for_name(name)
        if classification.any_alias:
            return classification
        for env in reversed(enclosing_alias_envs):
            classification = env.classification_for_name(name)
            if classification.any_alias:
                return classification
        return AliasClassification()

    def _lookup_enclosing_origin(name: str) -> ValueOriginEvidence | None:
        origin = alias_state.lookup(name)
        if isinstance(origin, ValueOriginEvidence):
            return origin
        for state in reversed(enclosing_origin_states):
            origin = state.lookup(name)
            if isinstance(origin, ValueOriginEvidence):
                return origin
        return None

    def _seed_callee_lexical_env(
        callee: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
        *,
        binding: Mapping[str, ast.AST],
    ) -> tuple[_RequestStateAliasEnv, AliasState]:
        """Build call-time alias + origin env: actuals, free vars, defaults."""

        callee_aliases = _RequestStateAliasEnv.empty()
        callee_alias_state = AliasState()
        for formal, actual in binding.items():
            # Preserve must/may strength independently (no may→must).
            classification = request_aliases.classify(actual)
            callee_aliases.apply_classification(formal, classification)
            callee_alias_state.bind(formal, _classify(actual))

        captures = nested_default_captures.get(id(callee))
        if captures is None:
            captures = _capture_default_summaries(
                callee, request_aliases=request_aliases, classify_origin=_classify
            )
        for formal, capture in captures.items():
            if formal in binding:
                continue
            # Omitted formal → definition-time default capture (not call-time).
            callee_aliases.apply_classification(formal, capture.classification)
            callee_alias_state.bind(formal, capture.origin)

        free = nested_free_vars.get(id(callee), _free_var_names(callee))
        capture_env = returned_closure_captures.get(id(callee), {})
        for name in free:
            # Late-bound free vars: prefer call-time enclosing cells when they
            # carry identity (same-frame rebind after ``fn = mid()``). Otherwise
            # reuse return-time capture for intermediate-frame cells
            # (``local_state`` bound inside ``mid`` then returned). Never join
            # with bottom — ``AliasClassification.join`` would weaken must→may.
            call_time = _lookup_enclosing_name_classification(name)
            captured = capture_env.get(name, AliasClassification())
            if call_time.any_alias:
                classification = call_time
            elif captured.any_alias:
                classification = captured
            else:
                classification = call_time
            if classification.any_alias:
                callee_aliases.apply_classification(name, classification)
            origin = _lookup_enclosing_origin(name)
            if origin is not None:
                callee_alias_state.bind(name, origin)
        return callee_aliases, callee_alias_state

    def _follow_function_callee(
        callee_node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        callee_path: str,
        call: ast.Call,
        control_dependent: bool,
        is_local_nested: bool,
        execute_async_body: bool = False,
    ) -> bool:
        # Bare Call of async def builds a coroutine; body runs only under
        # Await / AsyncWith / AsyncFor entry (Unknown > false PASS still
        # forbids treating that coro product as a no-op escape when stored
        # outside Name awaitable capture — see call_awaitable_callees).
        if isinstance(callee_node, ast.AsyncFunctionDef) and not execute_async_body:
            call_awaitable_callees[id(call)] = callee_node
            return True

        callee_frame = (_normalize_unit_path(callee_path), callee_node.name)
        if callee_frame in stack or callee_frame == frame:
            return False
        binding = _bind_call_actuals(callee_node, call)
        if binding is None:
            return False

        captures = nested_default_captures.get(id(callee_node), {})
        free = nested_free_vars.get(id(callee_node), _free_var_names(callee_node))
        capture_env = returned_closure_captures.get(id(callee_node), {})
        explicit_identity = any(
            request_aliases.is_request_or_state_expr(actual)
            for actual in binding.values()
        )
        free_identity = any(
            _lookup_enclosing_name_classification(name).any_alias
            or capture_env.get(name, AliasClassification()).any_alias
            for name in free
        )
        default_identity = any(
            captures[formal].classification.any_alias
            for formal in captures
            if formal not in binding
        )
        # Local nested helpers: follow within depth even without an explicit
        # governed actual (False UNKNOWN > omitted closure writers).
        if not (
            explicit_identity or free_identity or default_identity or is_local_nested
        ):
            return False

        callee_aliases, callee_alias_state = _seed_callee_lexical_env(
            callee_node, binding=binding
        )
        callee_identity = None
        if callee_resolver is not None:
            # Same-path nested: thread the live request-time session so local
            # resolve continues to see sibling nested defs.
            if (
                is_local_nested
                and identity_session is not None
                and _normalize_unit_path(callee_path) == _normalize_unit_path(path)
            ):
                callee_identity = identity_session
            else:
                callee_identity = begin_request_time_identity_session(
                    callee_resolver, path=callee_path, fn=callee_node
                )

        collected, returned, returned_unknown = _collect_writes_in_function(
            callee_node,
            path=callee_path,
            handler_param_names=handler_param_names,
            callee_resolver=callee_resolver,
            seed_request_aliases=callee_aliases,
            seed_alias_state=callee_alias_state,
            seed_identity_session=callee_identity,
            call_stack=stack | {frame},
            depth=depth + 1,
            enclosing_alias_envs=enclosing_alias_envs + (request_aliases.snapshot(),),
            enclosing_origin_states=enclosing_origin_states + (alias_state.snapshot(),),
            enclosing_local_classes=enclosing_local_classes
            + (dict(local_classes),),
            enclosing_callable_maps=enclosing_callable_maps
            + (
                (
                    dict(local_nested),
                    dict(local_lambdas),
                    {key: list(value) for key, value in name_returned_closures.items()},
                ),
            ),
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
        if returned:
            call_returned_closures[id(call)] = list(returned)
            for closure in returned:
                nested_free_vars[id(closure.node)] = closure.free_vars
                nested_default_captures[id(closure.node)] = dict(
                    closure.default_captures
                )
                returned_closure_captures[id(closure.node)] = dict(
                    closure.free_classifications
                )
        if returned_unknown:
            call_returned_unknown.add(id(call))
        return True

    def _follow_lambda_callee(
        lambda_node: ast.Lambda,
        *,
        call: ast.Call,
        control_dependent: bool,
    ) -> bool:
        """Account setattr / dynamic calls in a lambda body under lexical env."""

        if call.args or call.keywords:
            # Only the zero-arg / fully-defaulted ordinary theorem is modeled.
            if any(isinstance(arg, ast.Starred) for arg in call.args):
                return False
            if any(kw.arg is None for kw in call.keywords):
                return False
        # Lambdas have expression bodies: seed env then observe the body.
        binding: dict[str, ast.AST] = {}
        formals = [
            arg.arg
            for arg in list(lambda_node.args.posonlyargs) + list(lambda_node.args.args)
        ] + [arg.arg for arg in lambda_node.args.kwonlyargs]
        if len(call.args) > len(
            [a for a in list(lambda_node.args.posonlyargs) + list(lambda_node.args.args)]
        ):
            return False
        positional = list(lambda_node.args.posonlyargs) + list(lambda_node.args.args)
        for index, actual in enumerate(call.args):
            binding[positional[index].arg] = actual
        for kw in call.keywords:
            if kw.arg is None or kw.arg in binding or kw.arg not in formals:
                return False
            binding[kw.arg] = kw.value

        # Temporarily install lexical env for body observation.
        saved_aliases = request_aliases.snapshot()
        saved_origins = alias_state.snapshot()
        seeded_aliases, seeded_origins = _seed_callee_lexical_env(
            lambda_node, binding=binding
        )
        request_aliases.restore(seeded_aliases)
        alias_state.restore(seeded_origins)
        try:
            _observe_executed_expression(
                lambda_node.body, control_dependent=control_dependent
            )
        finally:
            request_aliases.restore(saved_aliases)
            alias_state.restore(saved_origins)
        return True

    def _follow_local_callable_node(
        callee: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
        *,
        call: ast.Call,
        control_dependent: bool,
        execute_async_body: bool = False,
    ) -> bool:
        if isinstance(callee, ast.Lambda):
            return _follow_lambda_callee(
                callee, call=call, control_dependent=control_dependent
            )
        return _follow_function_callee(
            callee,
            callee_path=path,
            call=call,
            control_dependent=control_dependent,
            is_local_nested=True,
            execute_async_body=execute_async_body,
        )

    def _getattr_packed_attr_callables(
        call_func: ast.AST,
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda]:
        """``getattr(Box(), \"fn\")`` / ``g(Box(), \"fn\")`` init/property peel."""

        if not isinstance(call_func, ast.Call):
            return []
        if (
            not isinstance(call_func.func, ast.Name)
            or call_func.func.id not in getattr_aliases
        ):
            return []
        if len(call_func.args) < 2:
            return []
        name_arg = call_func.args[1]
        if not isinstance(name_arg, ast.Constant) or not isinstance(name_arg.value, str):
            return []
        cls = _resolve_instance_or_class(call_func.args[0])
        if cls is None:
            return []
        packed = _init_packed_attr_callables(cls, name_arg.value)
        if packed:
            return packed
        # Property + getattr: ``getattr(Box(), \"fn\")`` where ``fn`` is @property.
        prop_getter = _class_property_getter(cls, name_arg.value)
        if prop_getter is None:
            return []
        if isinstance(prop_getter, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return [prop_getter]
        return _governed_local_callables_from_expr(prop_getter)

    def _getattr_dynamic_escape(call_func: ast.AST) -> bool:
        """True when ``getattr(obj, dynamic)`` may select a packed governed attr."""

        if not isinstance(call_func, ast.Call):
            return False
        if (
            not isinstance(call_func.func, ast.Name)
            or call_func.func.id not in getattr_aliases
        ):
            return False
        if len(call_func.args) < 2:
            return False
        name_arg = call_func.args[1]
        if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
            return False
        # Dynamic attr name on a resolved instance/class — fail closed.
        return _resolve_instance_or_class(call_func.args[0]) is not None

    def _getattr_local_callable(
        call_func: ast.AST,
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | None:
        """``getattr(obj, \"poison\")`` / ``getattr(fn, \"__call__\")`` → local callable."""

        if not isinstance(call_func, ast.Call):
            return None
        if (
            not isinstance(call_func.func, ast.Name)
            or call_func.func.id not in getattr_aliases
        ):
            return None
        if len(call_func.args) < 2:
            return None
        name_arg = call_func.args[1]
        if not isinstance(name_arg, ast.Constant) or not isinstance(name_arg.value, str):
            return None
        attr_name = name_arg.value
        # ``getattr(fn, \"__call__\")`` when ``fn`` is a represented local /
        # returned closure Name (parity with ``fn.__call__()``).
        if attr_name == "__call__" and isinstance(call_func.args[0], ast.Name):
            callees = _local_callables_for_name(call_func.args[0].id)
            if callees:
                return callees[0]
        packed = _getattr_packed_attr_callables(call_func)
        if packed:
            return packed[0]
        return _local_callable_for_name(attr_name)

    def _local_class_method_for_attr(
        attr_expr: ast.Attribute,
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        """Resolve ``Cls.method`` / ``Cls().method`` / instance alias methods.

        Peels trailing ``.__call__`` so ``Mut.make.__call__`` resolves ``make``
        (Unknown > false PASS).
        """

        while isinstance(attr_expr, ast.Attribute) and attr_expr.attr == "__call__":
            inner = attr_expr.value
            while isinstance(inner, ast.NamedExpr):
                inner = inner.value
            if isinstance(inner, ast.Attribute):
                attr_expr = inner
                continue
            # ``getattr(Mut, "make").__call__()`` → reconstruct ``Mut.make``.
            if isinstance(inner, ast.Call) and len(inner.args) >= 2:
                g_func = inner.func
                while isinstance(g_func, ast.NamedExpr):
                    g_func = g_func.value
                is_getattr = (
                    isinstance(g_func, ast.Name) and g_func.id == "getattr"
                ) or (isinstance(g_func, ast.Attribute) and g_func.attr == "getattr")
                name_arg = inner.args[1]
                while isinstance(name_arg, ast.NamedExpr):
                    name_arg = name_arg.value
                if (
                    is_getattr
                    and isinstance(name_arg, ast.Constant)
                    and isinstance(name_arg.value, str)
                    and name_arg.value != "__call__"
                ):
                    attr_expr = ast.Attribute(
                        value=inner.args[0],
                        attr=name_arg.value,
                        ctx=ast.Load(),
                    )
                    continue
            break

        cls = _resolve_instance_or_class(attr_expr.value)
        if cls is None:
            return None
        visited: set[int] = set()

        def _lookup(class_node: ast.ClassDef) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
            if id(class_node) in visited:
                return None
            visited.add(id(class_node))
            for child in class_node.body:
                if (
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name == attr_expr.attr
                ):
                    return child
            for base in class_node.bases:
                if isinstance(base, ast.Name):
                    base_cls = _lookup_local_class(base.id)
                    if base_cls is not None:
                        found = _lookup(base_cls)
                        if found is not None:
                            return found
            return None

        return _lookup(cls)

    def _class_property_getter(
        cls: ast.ClassDef,
        attr_name: str,
    ) -> ast.AST | None:
        """Return getter expr for ``@property`` / ``fn = property(_fn)``.

        Walks Name bases so ``Child(Base)`` inherits ``@property`` packs
        (Unknown > false PASS on ``Child().fn()``).
        """

        visited: set[int] = set()

        def _lookup(class_node: ast.ClassDef) -> ast.AST | None:
            if id(class_node) in visited:
                return None
            visited.add(id(class_node))
            for child in class_node.body:
                if (
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name == attr_name
                    and _method_is_property(child)
                ):
                    return child
                if isinstance(child, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == attr_name for t in child.targets
                ):
                    if (
                        isinstance(child.value, ast.Call)
                        and isinstance(child.value.func, ast.Name)
                        and child.value.func.id in {"property", "cached_property"}
                        and child.value.args
                    ):
                        return child.value.args[0]
            for base in class_node.bases:
                if isinstance(base, ast.Name):
                    base_cls = _lookup_local_class(base.id)
                    if base_cls is not None:
                        found = _lookup(base_cls)
                        if found is not None:
                            return found
            return None

        return _lookup(cls)

    def _method_is_property(
        method: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """True when ``method`` is decorated with ``property`` / ``cached_property``."""

        for deco in method.decorator_list:
            if isinstance(deco, ast.Name) and deco.id in {
                "property",
                "cached_property",
            }:
                return True
            if (
                isinstance(deco, ast.Attribute)
                and deco.attr in {"property", "cached_property"}
            ):
                return True
        return False

    def _collect_packed_attr_callables_from_stmts(
        stmts: Sequence[ast.stmt],
        attr_name: str,
        *,
        allow_class_body: bool = False,
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda]:
        """Governed callables packed onto ``self.<attr>`` / class ``<attr>``.

        Observes Assign/AnnAssign, setattr / object.__setattr__, ``__dict__``
        stores, and CF nesting in ``__init__`` / ``__new__`` / class body.
        Dynamic packing channels that cannot be peeled precisely contribute a
        residual escape via the caller (Unknown > false PASS).
        """

        found: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda] = []
        seen: set[int] = set()
        dynamic_pack = False

        def _add(
            node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
        ) -> None:
            if id(node) in seen:
                return
            seen.add(id(node))
            found.append(node)

        def _add_from_value(value: ast.AST) -> None:
            nonlocal dynamic_pack
            for callee in _governed_local_callables_from_expr(value):
                _add(callee)
            if isinstance(value, ast.Name):
                for callee in _local_callables_for_name(value.id):
                    _add(callee)
            closures, unknown = _callable_products_from_expr(value)
            for item in closures:
                _add(item.node)
            if unknown and not closures:
                dynamic_pack = True
            # ``self.fn = mid()`` / lambda without free-var peel still packs.
            if isinstance(value, (ast.Call, ast.Lambda)) and not found:
                dynamic_pack = True

        def _is_self_attr_target(target: ast.AST) -> bool:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.attr == attr_name
            ):
                # ``self.fn`` / ``obj.fn`` in ``__init__`` / ``__new__``.
                # Class-body packing uses bare Name targets separately.
                return True
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Attribute)
                and target.value.attr == "__dict__"
                and isinstance(target.value.value, ast.Name)
                and isinstance(target.slice, ast.Constant)
                and target.slice.value == attr_name
            ):
                return True
            return False

        def _walk_stmts(body: Sequence[ast.stmt]) -> None:
            nonlocal dynamic_pack
            for stmt in body:
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if _is_self_attr_target(target):
                            _add_from_value(stmt.value)
                        elif allow_class_body and isinstance(target, ast.Name) and target.id == attr_name:
                            _add_from_value(stmt.value)
                    continue
                if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                    if _is_self_attr_target(stmt.target):
                        _add_from_value(stmt.value)
                    elif (
                        allow_class_body
                        and isinstance(stmt.target, ast.Name)
                        and stmt.target.id == attr_name
                    ):
                        _add_from_value(stmt.value)
                    continue
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    call = stmt.value
                    # setattr(self, "fn", poison) / object.__setattr__(self, …)
                    setattr_parts = None
                    if isinstance(call.func, ast.Name) and call.func.id == "setattr":
                        if len(call.args) >= 3:
                            setattr_parts = (call.args[0], call.args[1], call.args[2])
                    elif (
                        isinstance(call.func, ast.Attribute)
                        and call.func.attr == "__setattr__"
                    ):
                        if (
                            isinstance(call.func.value, ast.Name)
                            and call.func.value.id == "object"
                            and len(call.args) >= 3
                        ):
                            setattr_parts = (call.args[0], call.args[1], call.args[2])
                        elif len(call.args) >= 2:
                            setattr_parts = (call.func.value, call.args[0], call.args[1])
                    if setattr_parts is not None:
                        obj, name_expr, packed_value = setattr_parts
                        if (
                            isinstance(obj, ast.Name)
                            and isinstance(name_expr, ast.Constant)
                            and name_expr.value == attr_name
                        ):
                            _add_from_value(packed_value)
                        elif isinstance(obj, ast.Name) and not isinstance(
                            name_expr, ast.Constant
                        ):
                            # Dynamic attr name on instance — fail closed.
                            dynamic_pack = True
                    continue
                if isinstance(stmt, (ast.If, ast.While)):
                    _walk_stmts(stmt.body)
                    _walk_stmts(stmt.orelse)
                    continue
                if isinstance(stmt, (ast.For, ast.AsyncFor)):
                    _walk_stmts(stmt.body)
                    _walk_stmts(stmt.orelse)
                    continue
                if isinstance(stmt, (ast.With, ast.AsyncWith)):
                    _walk_stmts(stmt.body)
                    continue
                if isinstance(stmt, ast.Try):
                    _walk_stmts(stmt.body)
                    for handler in stmt.handlers:
                        _walk_stmts(handler.body)
                    _walk_stmts(stmt.orelse)
                    _walk_stmts(stmt.finalbody)
                    continue
                if isinstance(stmt, ast.Match):
                    for case in stmt.cases:
                        _walk_stmts(case.body)
                    continue

        _walk_stmts(stmts)
        if dynamic_pack and not found:
            # Signal residual via sentinel: caller treats non-empty or escape.
            # Use a synthetic empty Lambda marker is avoided; return a fake
            # governed pack by recording escape at call sites when this is set.
            # Represent as packing unknown by returning a non-empty list of a
            # dummy — instead, stash on the class via side channel below.
            pass
        # Stash dynamic-pack flag on the function attribute for callers.
        _collect_packed_attr_callables_from_stmts.dynamic = dynamic_pack  # type: ignore[attr-defined]
        return found

    def _init_packed_attr_callables(
        cls: ast.ClassDef,
        attr_name: str,
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda]:
        """Callables packed onto ``self.<attr>`` / class ``<attr>``.

        Covers ``__init__`` / ``__new__`` / class-body packing including CF,
        setattr / object.__setattr__, ``__dict__`` stores, and inherited
        ``__init__`` / ``__new__`` on Name bases (``Child(Base).fn()``) (#173).
        """

        found: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda] = []
        seen: set[int] = set()
        dynamic = False
        visited_classes: set[int] = set()

        def _merge(
            items: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda],
        ) -> None:
            for item in items:
                if id(item) in seen:
                    continue
                seen.add(id(item))
                found.append(item)

        def _collect_on_class(class_node: ast.ClassDef) -> None:
            nonlocal dynamic
            if id(class_node) in visited_classes:
                return
            visited_classes.add(id(class_node))
            # Class-body ``fn = poison`` / ``fn = property(_fn)`` packing.
            _merge(
                _collect_packed_attr_callables_from_stmts(
                    class_node.body, attr_name, allow_class_body=True
                )
            )
            dynamic = dynamic or bool(
                getattr(_collect_packed_attr_callables_from_stmts, "dynamic", False)
            )
            for child in class_node.body:
                if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if child.name not in {"__init__", "__new__"}:
                    continue
                _merge(
                    _collect_packed_attr_callables_from_stmts(
                        child.body, attr_name, allow_class_body=False
                    )
                )
                dynamic = dynamic or bool(
                    getattr(_collect_packed_attr_callables_from_stmts, "dynamic", False)
                )
                for nested in child.body:
                    if isinstance(nested, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        local_nested.setdefault(nested.name, nested)
            # Property descriptor assigned in class body: ``fn = property(_fn)``.
            for child in class_node.body:
                if not isinstance(child, ast.Assign):
                    continue
                if not any(
                    isinstance(t, ast.Name) and t.id == attr_name for t in child.targets
                ):
                    continue
                if (
                    isinstance(child.value, ast.Call)
                    and isinstance(child.value.func, ast.Name)
                    and child.value.func.id in {"property", "cached_property"}
                    and child.value.args
                ):
                    getter = child.value.args[0]
                    for callee in _governed_local_callables_from_expr(getter):
                        if id(callee) not in seen:
                            seen.add(id(callee))
                            found.append(callee)
                    if isinstance(getter, ast.Name):
                        for callee in _local_callables_for_name(getter.id):
                            if id(callee) not in seen:
                                seen.add(id(callee))
                                found.append(callee)
            # Inherited ``__init__`` / ``__new__`` packing on Name bases.
            for base in class_node.bases:
                if isinstance(base, ast.Name):
                    base_cls = _lookup_local_class(base.id)
                    if base_cls is not None:
                        _collect_on_class(base_cls)
                    else:
                        dynamic = True
                else:
                    dynamic = True

        _collect_on_class(cls)
        if dynamic and not found:
            # Fail closed: unpeeled dynamic pack on this attr.
            _init_packed_attr_callables.dynamic_escape = True  # type: ignore[attr-defined]
        else:
            _init_packed_attr_callables.dynamic_escape = False  # type: ignore[attr-defined]
        return found

    def _resolve_instance_or_class(
        receiver: ast.AST,
    ) -> ast.ClassDef | None:
        """Resolve ``Box`` / ``Box()`` / ``b`` / ``[Box()][0]`` / IfExp packs."""

        if isinstance(receiver, ast.NamedExpr):
            return _resolve_instance_or_class(receiver.value)
        if isinstance(receiver, ast.Name):
            cls = _lookup_local_class(receiver.id)
            if cls is not None:
                return cls
            cname = instance_class_of.get(receiver.id)
            if cname is not None:
                return _lookup_local_class(cname)
            return None
        if isinstance(receiver, ast.Call):
            if isinstance(receiver.func, ast.Name):
                return _lookup_local_class(receiver.func.id)
            # Packed / Attribute class construction receivers stay unresolved
            # here; construction observation is handled in identity scanning.
            return None
        if isinstance(receiver, ast.IfExp):
            left = _resolve_instance_or_class(receiver.body)
            right = _resolve_instance_or_class(receiver.orelse)
            if left is not None and (right is None or left is right):
                return left
            if right is not None and left is None:
                return right
            if left is not None and right is not None and left is not right:
                # Divergent instance packs — fail closed via dynamic escape.
                _init_packed_attr_callables.dynamic_escape = True  # type: ignore[attr-defined]
            return left or right
        if isinstance(receiver, ast.BoolOp):
            resolved: ast.ClassDef | None = None
            for operand in receiver.values:
                cls = _resolve_instance_or_class(operand)
                if cls is None:
                    continue
                if resolved is None:
                    resolved = cls
                elif resolved is not cls:
                    _init_packed_attr_callables.dynamic_escape = True  # type: ignore[attr-defined]
            return resolved
        if isinstance(receiver, (ast.List, ast.Tuple, ast.Set)):
            resolved = None
            for elt in receiver.elts:
                nested = elt.value if isinstance(elt, ast.Starred) else elt
                cls = _resolve_instance_or_class(nested)
                if cls is None:
                    continue
                if resolved is None:
                    resolved = cls
                elif resolved is not cls:
                    _init_packed_attr_callables.dynamic_escape = True  # type: ignore[attr-defined]
            return resolved
        if isinstance(receiver, ast.Subscript):
            return _resolve_instance_or_class(receiver.value)
        if isinstance(receiver, ast.Dict):
            resolved = None
            for value in receiver.values:
                if value is None:
                    continue
                cls = _resolve_instance_or_class(value)
                if cls is None:
                    continue
                if resolved is None:
                    resolved = cls
                elif resolved is not cls:
                    _init_packed_attr_callables.dynamic_escape = True  # type: ignore[attr-defined]
            return resolved
        return None

    def _governed_class_method(
        cls: ast.ClassDef,
        method_name: str,
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        for child in cls.body:
            if (
                isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name == method_name
            ):
                # Protocol / callable entry points may return nested governed
                # closures without free vars of their own (``def __enter__`` /
                # ``def __call__`` factories). Always follow these methods on
                # local classes; empty bodies remain no-ops.
                if method_name in {"__call__", "__enter__", "__aenter__"}:
                    return child
                if _closure_carries_governed_identity(child) or bool(
                    nested_free_vars.get(id(child), _free_var_names(child))
                ):
                    return child
                # Nested governed defs inside the method still force follow.
                for nested in ast.walk(child):
                    if nested is child:
                        continue
                    if isinstance(
                        nested, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                    ) and (
                        _closure_carries_governed_identity(nested)
                        or bool(
                            nested_free_vars.get(
                                id(nested), _free_var_names(nested)
                            )
                        )
                    ):
                        return child
                return None
        return None

    def _choice_expr_has_dynamic_callable_arm(expr: ast.AST) -> bool:
        """True when an IfExp/BoolOp arm may evaluate to an unresolved callable."""

        def _arm_dynamic(node: ast.AST) -> bool:
            if isinstance(node, ast.NamedExpr):
                return _arm_dynamic(node.value)
            if isinstance(node, ast.IfExp):
                return _arm_dynamic(node.body) or _arm_dynamic(node.orelse)
            if isinstance(node, ast.BoolOp):
                return any(_arm_dynamic(operand) for operand in node.values)
            if isinstance(node, (ast.Lambda,)):
                return False
            if isinstance(node, ast.Name):
                if _local_callables_for_name(node.id):
                    return False
                if node.id in name_unknown_callables:
                    return True
                return True
            if isinstance(node, ast.Call):
                if call_returned_closures.get(id(node)) or id(node) in call_returned_unknown:
                    return id(node) in call_returned_unknown
                if isinstance(node.func, ast.Name) and _local_callables_for_name(
                    node.func.id
                ):
                    return False
                return True
            if isinstance(
                node,
                (
                    ast.Constant,
                    ast.FormattedValue,
                    ast.JoinedStr,
                    ast.List,
                    ast.Tuple,
                    ast.Set,
                    ast.Dict,
                ),
            ):
                return False
            return True

        if isinstance(expr, ast.NamedExpr):
            return _choice_expr_has_dynamic_callable_arm(expr.value)
        if isinstance(expr, (ast.IfExp, ast.BoolOp)):
            return _arm_dynamic(expr)
        return False

    def _callable_products_from_expr(
        expr: ast.AST,
    ) -> tuple[list[_ReturnedClosure], bool]:
        """Collect known nested/returned callable products from ``expr``.

        Returns ``(closures, unknown_callable_arm)``. IfExp/BoolOp arms are
        dual-may joined. An unresolved callable arm sets the unknown flag so
        later ``fn()`` fails closed (Unknown > false PASS) and is never omitted.
        """

        found: list[_ReturnedClosure] = []
        seen: set[int] = set()
        unknown = False
        # Unresolved choice arms only fail closed when another arm already
        # produced a known callable (``mid() if c else unknown``). Plain
        # ``flag or settings.ALLOW`` must not become a callable-product escape.
        pending_unknown_arm = False

        def _add(closure: _ReturnedClosure) -> None:
            if id(closure.node) in seen:
                return
            seen.add(id(closure.node))
            found.append(closure)

        def _walk(node: ast.AST, *, in_choice: bool = False) -> None:
            nonlocal unknown, pending_unknown_arm
            if isinstance(node, ast.NamedExpr):
                _walk(node.value, in_choice=in_choice)
                return
            if isinstance(node, ast.IfExp):
                # Choice arms are callable-product positions for dual-may join.
                _walk(node.body, in_choice=True)
                _walk(node.orelse, in_choice=True)
                return
            if isinstance(node, ast.BoolOp):
                for operand in node.values:
                    _walk(operand, in_choice=True)
                return
            if isinstance(node, ast.Lambda):
                _register_nested_callable(node, name=None)
                _add(_snapshot_returned_closure(node))
                return
            if isinstance(node, ast.Name):
                callees = _local_callables_for_name(node.id)
                if callees:
                    for callee in callees:
                        _add(_snapshot_returned_closure(callee))
                    if node.id in name_unknown_callables:
                        unknown = True
                    return
                if node.id in name_unknown_callables:
                    unknown = True
                    return
                if in_choice:
                    pending_unknown_arm = True
                return
            if isinstance(node, ast.Call):
                returned, call_unknown = _ensure_call_callable_products(node)
                for item in returned:
                    _add(item)
                if call_unknown or id(node) in call_returned_unknown:
                    unknown = True
                    return
                if returned:
                    return
                if isinstance(node.func, ast.Name):
                    # Followed local with no callable product (e.g. returns int).
                    if _local_callables_for_name(node.func.id):
                        return
                if in_choice:
                    pending_unknown_arm = True
                return
            if isinstance(
                node,
                (
                    ast.Constant,
                    ast.FormattedValue,
                    ast.JoinedStr,
                    ast.List,
                    ast.Tuple,
                    ast.Set,
                    ast.Dict,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            ):
                # Non-callable literals / containers are not unknown arms;
                # packing escapes are handled separately.
                return
            # Attribute / Subscript / other dynamic surfaces in choice arms.
            if in_choice:
                pending_unknown_arm = True

        _walk(expr)
        if pending_unknown_arm and found:
            unknown = True
        return found, unknown

    def _returned_closures_from_expr(
        expr: ast.AST,
    ) -> list[_ReturnedClosure]:
        """Name/Lambda nested callables and governed ``Cls().__call__`` products."""

        closures, _unknown = _callable_products_from_expr(expr)
        return closures

    def _follow_local_class_protocol_methods(
        expr: ast.AST,
        *,
        method_names: Sequence[str],
        control_dependent: bool,
        execute_async_body: bool,
    ) -> tuple[list[_ReturnedClosure], bool]:
        """Follow governed local class protocol methods; return enter products.

        ``with CM() as fn`` / ``async with CM() as fn`` bind ``__enter__`` /
        ``__aenter__`` return values. Returned governed closures must install
        on the ``as`` name (Unknown > false PASS).
        """

        if not isinstance(expr, ast.Call) or not isinstance(expr.func, ast.Name):
            return [], False
        cls = _lookup_local_class(expr.func.id)
        if cls is None:
            return [], False
        products: list[_ReturnedClosure] = []
        unknown = False
        seen: set[int] = set()
        for method_name in method_names:
            method = _governed_class_method(cls, method_name)
            if method is None:
                continue
            synthetic = ast.Call(
                func=ast.Attribute(
                    value=expr,
                    attr=method_name,
                    ctx=ast.Load(),
                ),
                args=[],
                keywords=[],
            )
            if _follow_local_callable_node(
                method,
                call=synthetic,
                control_dependent=control_dependent,
                execute_async_body=execute_async_body,
            ):
                for item in call_returned_closures.get(id(synthetic), []):
                    if id(item.node) in seen:
                        continue
                    seen.add(id(item.node))
                    products.append(item)
                if id(synthetic) in call_returned_unknown:
                    unknown = True
        return products, unknown

    def _try_interprocedural(
        call: ast.Call,
        *,
        control_dependent: bool,
        execute_async_body: bool = False,
    ) -> bool:
        """Resolve a callee under bounded lexical + actual identity theorems."""

        if depth >= _MAX_INTERPROCEDURAL_WRITER_DEPTH:
            return False

        # Local nested / lambda Name callees (closure theorem).
        if isinstance(call.func, ast.Name):
            name_callees = _local_callables_for_name(call.func.id)
            if name_callees:
                followed_any = False
                for callee in name_callees:
                    if _follow_local_callable_node(
                        callee,
                        call=call,
                        control_dependent=control_dependent,
                        execute_async_body=execute_async_body,
                    ):
                        followed_any = True
                return followed_any
            # Higher-order builtins: ``map(poison, …)`` / ``filter(poison, …)``
            # invoke the first argument as a callee (identity session parity).
            if call.func.id in {"map", "filter"} and call.args:
                first = call.args[0]
                packed = _governed_local_callables_from_expr(first)
                if packed:
                    synthetic = ast.Call(
                        func=first,
                        args=list(call.args[1:]),
                        keywords=list(call.keywords),
                    )
                    followed_any = False
                    for callee in packed:
                        if _follow_local_callable_node(
                            callee,
                            call=synthetic,
                            control_dependent=control_dependent,
                            execute_async_body=execute_async_body,
                        ):
                            followed_any = True
                    return followed_any

        # Packed constructor peels (non-Name): ``[Cls][0]()`` / ``xs[0]()``
        # after match-star / container seeds. Bare ``Cls()`` stays on the
        # identity / Name theorem so ``with CM() as …`` enter products remain.
        if not isinstance(call.func, ast.Name):
            ctor_cls = _resolve_class_constructor_alias(call.func)
            if ctor_cls is None and isinstance(call.func, ast.Subscript):
                base = call.func.value
                while isinstance(base, ast.NamedExpr):
                    base = base.value
                if isinstance(base, ast.Name):
                    ctor_cls = _lookup_local_class(base.id)
            if ctor_cls is not None:
                followed_any = False
                for proto in ("__new__", "__init__", "__call__"):
                    method = _governed_class_method(ctor_cls, proto)
                    if method is None:
                        continue
                    if _follow_local_callable_node(
                        method,
                        call=call,
                        control_dependent=control_dependent,
                        execute_async_body=execute_async_body,
                    ):
                        followed_any = True
                if followed_any:
                    return True
                _record_escape(
                    call,
                    ast.unparse(call),
                    control_dependent=control_dependent,
                )
                return True

        # Chained call products: ``outer()()`` / ``Cls()()`` where the inner
        # Call yielded a nested callable or governed ``__call__``.
        if isinstance(call.func, ast.Call):
            returned, _chained_unknown = _ensure_call_callable_products(call.func)
            if returned:
                followed_any = False
                for item in returned:
                    if _follow_local_callable_node(
                        item.node,
                        call=call,
                        control_dependent=control_dependent,
                        execute_async_body=execute_async_body,
                    ):
                        followed_any = True
                return followed_any

        # Attribute method: class-nested ``Box().poison()`` where ``poison``
        # closed over outer governed cells and was registered at class body.
        # Also ``fn.__call__()`` when ``fn`` is a represented local / returned
        # closure Name (direct ``fn()`` theorem parity).
        # Local class factories (``Cls.make()`` / ``Cls().run()``) always
        # follow — methods may return nested governed closures with no free
        # vars of their own (classmethod/staticmethod factories).
        if isinstance(call.func, ast.Attribute):
            if (
                call.func.attr == "__call__"
                and isinstance(call.func.value, ast.Name)
            ):
                name_callees = _local_callables_for_name(call.func.value.id)
                if name_callees:
                    followed_any = False
                    for callee in name_callees:
                        if _follow_local_callable_node(
                            callee,
                            call=call,
                            control_dependent=control_dependent,
                            execute_async_body=execute_async_body,
                        ):
                            followed_any = True
                    return followed_any
            class_method = _local_class_method_for_attr(call.func)
            if class_method is not None:
                if _method_is_property(class_method):
                    # ``@property`` / ``cached_property``: Call invokes the
                    # getter's returned callable product, not the getter alone.
                    _follow_local_callable_node(
                        class_method,
                        call=call,
                        control_dependent=control_dependent,
                        execute_async_body=execute_async_body,
                    )
                    returned = list(call_returned_closures.get(id(call), []))
                    unknown = id(call) in call_returned_unknown
                    followed_any = False
                    for item in returned:
                        if _follow_local_callable_node(
                            item.node,
                            call=call,
                            control_dependent=control_dependent,
                            execute_async_body=execute_async_body,
                        ):
                            followed_any = True
                    if followed_any:
                        return True
                    if unknown or returned:
                        _record_escape(
                            call,
                            ast.unparse(call),
                            control_dependent=control_dependent,
                        )
                        return True
                    # Property with no modeled product — fail closed.
                    _record_escape(
                        call,
                        ast.unparse(call),
                        control_dependent=control_dependent,
                    )
                    return True
                return _follow_local_callable_node(
                    class_method,
                    call=call,
                    control_dependent=control_dependent,
                    execute_async_body=execute_async_body,
                )
            # ``Box().fn()`` / ``b.fn()`` / ``(b:=Box()).fn()`` where
            # ``__init__`` / ``__new__`` / class body packed ``self.fn``.
            init_cls = _resolve_instance_or_class(call.func.value)
            if init_cls is not None:
                # ``@property`` / ``fn = property(_fn)``: invoke getter product.
                prop_getter = _class_property_getter(init_cls, call.func.attr)
                if prop_getter is not None:
                    getters: list[
                        ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
                    ] = []
                    if isinstance(
                        prop_getter, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                    ):
                        getters.append(prop_getter)
                    elif isinstance(prop_getter, ast.Name):
                        getters.extend(_local_callables_for_name(prop_getter.id))
                    else:
                        getters.extend(
                            _governed_local_callables_from_expr(prop_getter)
                        )
                    followed_getter = False
                    for getter in getters:
                        if _follow_local_callable_node(
                            getter,
                            call=call,
                            control_dependent=control_dependent,
                            execute_async_body=execute_async_body,
                        ):
                            followed_getter = True
                    returned = list(call_returned_closures.get(id(call), []))
                    unknown = id(call) in call_returned_unknown
                    followed_any = False
                    for item in returned:
                        if _follow_local_callable_node(
                            item.node,
                            call=call,
                            control_dependent=control_dependent,
                            execute_async_body=execute_async_body,
                        ):
                            followed_any = True
                    if followed_any:
                        return True
                    if followed_getter or unknown or returned or getters:
                        _record_escape(
                            call,
                            ast.unparse(call),
                            control_dependent=control_dependent,
                        )
                        return True
                packed = _init_packed_attr_callables(init_cls, call.func.attr)
                if packed:
                    followed_any = False
                    for callee in packed:
                        if _follow_local_callable_node(
                            callee,
                            call=call,
                            control_dependent=control_dependent,
                            execute_async_body=execute_async_body,
                        ):
                            followed_any = True
                    # Getter-like packs may only return a nested poison.
                    returned = list(call_returned_closures.get(id(call), []))
                    for item in returned:
                        if _follow_local_callable_node(
                            item.node,
                            call=call,
                            control_dependent=control_dependent,
                            execute_async_body=execute_async_body,
                        ):
                            followed_any = True
                    if followed_any or returned or id(call) in call_returned_unknown:
                        if not followed_any:
                            _record_escape(
                                call,
                                ast.unparse(call),
                                control_dependent=control_dependent,
                            )
                        return True
                if getattr(_init_packed_attr_callables, "dynamic_escape", False):
                    _record_escape(
                        call,
                        ast.unparse(call),
                        control_dependent=control_dependent,
                    )
                    return True
            callee = _local_callable_for_name(call.func.attr)
            if callee is not None and _closure_carries_governed_identity(callee):
                return _follow_local_callable_node(
                    callee,
                    call=call,
                    control_dependent=control_dependent,
                    execute_async_body=execute_async_body,
                )

        # ``getattr(box, \"poison\")()`` / ``getattr(Box(), \"fn\")()`` /
        # property + getattr (``getattr(Box(), \"fn\")()`` where ``fn`` is
        # ``@property`` returning a governed closure).
        if (
            isinstance(call.func, ast.Call)
            and isinstance(call.func.func, ast.Name)
            and call.func.func.id in getattr_aliases
            and len(call.func.args) >= 2
            and isinstance(call.func.args[1], ast.Constant)
            and isinstance(call.func.args[1].value, str)
        ):
            getattr_cls = _resolve_instance_or_class(call.func.args[0])
            attr_name = call.func.args[1].value
            if getattr_cls is not None:
                prop_getter = _class_property_getter(getattr_cls, attr_name)
                if prop_getter is not None:
                    getters: list[
                        ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
                    ] = []
                    if isinstance(
                        prop_getter,
                        (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda),
                    ):
                        getters.append(prop_getter)
                    elif isinstance(prop_getter, ast.Name):
                        getters.extend(_local_callables_for_name(prop_getter.id))
                    else:
                        getters.extend(
                            _governed_local_callables_from_expr(prop_getter)
                        )
                    followed_getter = False
                    for getter in getters:
                        if _follow_local_callable_node(
                            getter,
                            call=call,
                            control_dependent=control_dependent,
                            execute_async_body=execute_async_body,
                        ):
                            followed_getter = True
                    returned = list(call_returned_closures.get(id(call), []))
                    unknown = id(call) in call_returned_unknown
                    followed_any = False
                    for item in returned:
                        if _follow_local_callable_node(
                            item.node,
                            call=call,
                            control_dependent=control_dependent,
                            execute_async_body=execute_async_body,
                        ):
                            followed_any = True
                    if followed_any:
                        return True
                    if followed_getter or unknown or returned or getters:
                        _record_escape(
                            call,
                            ast.unparse(call),
                            control_dependent=control_dependent,
                        )
                        return True
        getattr_packed = _getattr_packed_attr_callables(call.func)
        if getattr_packed:
            followed_any = False
            for callee in getattr_packed:
                if _follow_local_callable_node(
                    callee,
                    call=call,
                    control_dependent=control_dependent,
                    execute_async_body=execute_async_body,
                ):
                    followed_any = True
            returned = list(call_returned_closures.get(id(call), []))
            for item in returned:
                if _follow_local_callable_node(
                    item.node,
                    call=call,
                    control_dependent=control_dependent,
                    execute_async_body=execute_async_body,
                ):
                    followed_any = True
            if followed_any or returned or id(call) in call_returned_unknown:
                if not followed_any:
                    _record_escape(
                        call,
                        ast.unparse(call),
                        control_dependent=control_dependent,
                    )
                return True
            if getattr(_init_packed_attr_callables, "dynamic_escape", False):
                _record_escape(
                    call,
                    ast.unparse(call),
                    control_dependent=control_dependent,
                )
                return True
        getattr_callee = _getattr_local_callable(call.func)
        if getattr_callee is not None and _closure_carries_governed_identity(
            getattr_callee
        ):
            return _follow_local_callable_node(
                getattr_callee,
                call=call,
                control_dependent=control_dependent,
                execute_async_body=execute_async_body,
            )
        # ``getattr(Box(), n)()`` with dynamic attr name — fail closed.
        if _getattr_dynamic_escape(call.func):
            _record_escape(
                call,
                ast.unparse(call),
                control_dependent=control_dependent,
            )
            return True

        # Packed Call.func: IfExp/BoolOp/NamedExpr/containers/Subscript of
        # local governed closures (``(poison if f else noop)()``, ``[poison][0]()``).
        if not isinstance(call.func, ast.Name):
            packed = _governed_local_callables_from_expr(call.func)
            if packed:
                followed_any = False
                for callee in packed:
                    if _follow_local_callable_node(
                        callee,
                        call=call,
                        control_dependent=control_dependent,
                        execute_async_body=execute_async_body,
                    ):
                        followed_any = True
                if followed_any:
                    return True

        if callee_resolver is None:
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
        result = (
            identity_session.resolve_call(
                call.func,
                shadowed_names=frozenset(shadowed),
            )
            if identity_session is not None
            else callee_resolver.resolve_call(
                call.func,
                caller_path=path,
                shadowed_names=frozenset(shadowed),
            )
        )
        if result.callee is None:
            return False
        resolved = result.callee
        is_local_nested = (
            _normalize_unit_path(resolved.path) == _normalize_unit_path(path)
            and (
                resolved.node.name in local_nested
                or id(resolved.node) in nested_free_vars
            )
        )
        return _follow_function_callee(
            resolved.node,
            callee_path=resolved.path,
            call=call,
            control_dependent=control_dependent,
            is_local_nested=is_local_nested,
            execute_async_body=execute_async_body,
        )

    def _call_receives_request_or_state(call: ast.Call) -> bool:
        return request_aliases.call_receives_request_or_state(call)

    def _await_operand_calls(root: ast.AST) -> set[int]:
        """Call nodes whose bodies execute because they are Await operands."""

        executing: set[int] = set()
        for node in ast.walk(root):
            if not isinstance(node, ast.Await):
                continue
            value: ast.AST = node.value
            while isinstance(value, ast.NamedExpr):
                value = value.value
            if isinstance(value, ast.Call):
                executing.add(id(value))
        return executing

    def _expr_name_captures_call_product(expr: ast.AST, call: ast.Call) -> bool:
        """True when ``call`` is a Name-bound callable product inside ``expr``.

        Covers direct ``fn = mid()`` and dual-may ``fn = mid() if c else noop`` /
        BoolOp joins. Container packing (``box = [mid()]``) is intentionally
        excluded so packing stays residual escape.
        """

        if expr is call:
            return True
        if isinstance(expr, ast.NamedExpr):
            return _expr_name_captures_call_product(expr.value, call)
        if isinstance(expr, ast.IfExp):
            return _expr_name_captures_call_product(
                expr.body, call
            ) or _expr_name_captures_call_product(expr.orelse, call)
        if isinstance(expr, ast.BoolOp):
            return any(
                _expr_name_captures_call_product(operand, call)
                for operand in expr.values
            )
        return False

    def _call_has_name_or_discard_capture(
        statement: ast.stmt, call: ast.Call
    ) -> bool:
        """True when Call product is Name-bound or discarded as a bare Expr."""

        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) for target in statement.targets
        ):
            if _expr_name_captures_call_product(statement.value, call):
                return True
        if (
            isinstance(statement, ast.AnnAssign)
            and statement.value is not None
            and isinstance(statement.target, ast.Name)
            and _expr_name_captures_call_product(statement.value, call)
        ):
            return True
        if isinstance(statement, ast.Expr) and statement.value is call:
            return True
        for node in ast.walk(statement):
            if (
                isinstance(node, ast.NamedExpr)
                and isinstance(node.target, ast.Name)
                and _expr_name_captures_call_product(node.value, call)
            ):
                return True
        return False

    def _follow_awaitable_name(
        name: str,
        *,
        control_dependent: bool,
    ) -> bool:
        callee = name_awaitable_callees.get(name)
        if callee is None:
            return False
        synthetic = ast.Call(func=ast.Name(id=name, ctx=ast.Load()), args=[], keywords=[])
        return _follow_function_callee(
            callee,
            callee_path=path,
            call=synthetic,
            control_dependent=control_dependent,
            is_local_nested=True,
            execute_async_body=True,
        )

    def _record_dynamic_calls(
        statement: ast.stmt,
        *,
        control_dependent: bool,
        async_entry: bool = False,
    ) -> None:
        await_calls = _await_operand_calls(statement)
        # ``await coro`` where ``coro = poison()`` bound an async awaitable.
        for node in ast.walk(statement):
            if not isinstance(node, ast.Await):
                continue
            value: ast.AST = node.value
            while isinstance(value, ast.NamedExpr):
                if isinstance(value.target, ast.Name) and isinstance(
                    value.value, ast.Call
                ):
                    _bind_call_product_to_name(value.target.id, value.value)
                value = value.value
            if isinstance(value, ast.Name):
                _follow_awaitable_name(
                    value.id, control_dependent=control_dependent
                )
        # Innermost Calls first so ``bucket.append(mid())`` sees mid's returned
        # closures before the outer higher-order escape check.
        call_nodes = [
            node for node in ast.walk(statement) if isinstance(node, ast.Call)
        ]
        for node in reversed(call_nodes):
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
                + [
                    f"{name}.state"
                    for name in sorted(request_aliases.all_request_names())
                ]
                + sorted(request_aliases.all_state_names())
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
            # Also follow zero-arg nested closures / default-capture callees
            # that carry governed identity via free vars (no syntactic actual).
            # Packed/Attribute/getattr Call.func shapes that resolve to governed
            # local callables participate in the same theorem (#173 closure).
            packed_func_callees = (
                []
                if isinstance(node.func, ast.Name)
                else _governed_local_callables_from_expr(node.func)
            )
            chained_func_callees = (
                _ensure_call_callable_products(node.func)[0]
                if isinstance(node.func, ast.Call)
                else []
            )
            attr_governed = False
            if isinstance(node.func, ast.Attribute):
                if (
                    node.func.attr == "__call__"
                    and isinstance(node.func.value, ast.Name)
                    and bool(_local_callables_for_name(node.func.value.id))
                ):
                    attr_governed = True
                elif _local_class_method_for_attr(node.func) is not None:
                    attr_governed = True
                else:
                    # ``Box().fn()`` / instance alias / walrus where packing
                    # observed on ``__init__`` / ``__new__`` / class body.
                    init_cls = _resolve_instance_or_class(node.func.value)
                    if init_cls is not None and (
                        _init_packed_attr_callables(init_cls, node.func.attr)
                        or getattr(
                            _init_packed_attr_callables, "dynamic_escape", False
                        )
                        or _class_property_getter(init_cls, node.func.attr) is not None
                    ):
                        attr_governed = True
                    else:
                        attr_callee = _local_callable_for_name(node.func.attr)
                        attr_governed = (
                            attr_callee is not None
                            and _closure_carries_governed_identity(attr_callee)
                        )
            getattr_packed = _getattr_packed_attr_callables(node.func)
            getattr_callee = _getattr_local_callable(node.func)
            # ``getattr(obj, "missing", poison)()`` — default may be the callee.
            getattr_default_governed = False
            if (
                isinstance(node.func, ast.Call)
                and isinstance(node.func.func, ast.Name)
                and node.func.func.id in getattr_aliases
                and len(node.func.args) >= 3
            ):
                default_expr = node.func.args[2]
                if _expr_packs_governed_local_callable(default_expr) or (
                    isinstance(default_expr, ast.Name)
                    and bool(_local_callables_for_name(default_expr.id))
                ):
                    getattr_default_governed = True
                else:
                    # Unresolved default callable product — fail closed.
                    getattr_default_governed = True
            getattr_governed = (
                bool(getattr_packed)
                or (
                    getattr_callee is not None
                    and _closure_carries_governed_identity(getattr_callee)
                )
                or getattr_default_governed
                or _getattr_dynamic_escape(node.func)
            )
            unknown_name_callable = (
                isinstance(node.func, ast.Name)
                and node.func.id in name_unknown_callables
            )
            # Packed class construction peels: ``xs[0]()`` after match-star seeds.
            packed_ctor = False
            if not isinstance(node.func, ast.Name):
                ctor_peel = _resolve_class_constructor_alias(node.func)
                if ctor_peel is None and isinstance(node.func, ast.Subscript):
                    base = node.func.value
                    while isinstance(base, ast.NamedExpr):
                        base = base.value
                    if isinstance(base, ast.Name):
                        ctor_peel = _lookup_local_class(base.id)
                packed_ctor = ctor_peel is not None
            local_closure_call = (
                (
                    isinstance(node.func, ast.Name)
                    and (
                        bool(_local_callables_for_name(node.func.id))
                        or node.func.id in name_awaitable_callees
                        or unknown_name_callable
                    )
                )
                or bool(packed_func_callees)
                or bool(chained_func_callees)
                or attr_governed
                or getattr_governed
                or packed_ctor
            )
            # Higher-order: governed local callable flows as an actual into an
            # unresolved callee (``bucket.append(poison)``, ``mc(poison)``).
            higher_order_governed = any(
                _expr_packs_governed_local_callable(arg)
                for arg in node.args
                if not isinstance(arg, ast.Starred)
            ) or any(
                kw.value is not None and _expr_packs_governed_local_callable(kw.value)
                for kw in node.keywords
                if kw.arg is not None
            ) or any(
                any(
                    _closure_is_residual_escape(item)
                    for item in _ensure_call_callable_products(arg)[0]
                )
                for arg in node.args
                if isinstance(arg, ast.Call)
            )
            execute_async_body = async_entry or id(node) in await_calls
            if (
                _call_receives_request_or_state(node)
                or local_closure_call
                or higher_order_governed
            ):
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in _NON_MUTATING_STATE_OBSERVERS
                ):
                    continue
                if _try_interprocedural(
                    node,
                    control_dependent=control_dependent,
                    execute_async_body=execute_async_body,
                ):
                    # Returned free-var closures must Name-bind or discard;
                    # attribute/arg/container surfaces stay residual escapes.
                    returned = call_returned_closures.get(id(node), [])
                    if (
                        (returned or id(node) in call_returned_unknown)
                        and not _call_has_name_or_discard_capture(statement, node)
                    ):
                        if id(node) in call_returned_unknown or any(
                            _closure_is_residual_escape(item) for item in returned
                        ):
                            _record_escape(
                                node,
                                rendered,
                                control_dependent=control_dependent,
                            )
                    elif (
                        id(node) in call_awaitable_callees
                        and not execute_async_body
                        and not _call_has_name_or_discard_capture(statement, node)
                    ):
                        # Async coro product escapes outside Name awaitable
                        # capture (``bucket.append(poison())``).
                        _record_escape(
                            node,
                            rendered,
                            control_dependent=control_dependent,
                        )
                    # Unknown callable arm bound to Name: fail closed on call.
                    if unknown_name_callable or (
                        isinstance(node.func, ast.Call)
                        and id(node.func) in call_returned_unknown
                    ):
                        _record_escape(
                            node,
                            rendered,
                            control_dependent=control_dependent,
                        )
                    continue
                if local_closure_call or higher_order_governed:
                    # Represented local closure call / higher-order escape →
                    # UNKNOWN (Unknown > false PASS).
                    _record_escape(
                        node,
                        rendered,
                        control_dependent=control_dependent,
                    )
                    continue
                _record_escape(
                    node,
                    rendered,
                    control_dependent=control_dependent,
                )

    # Pop Call → projected value AST, captured before the key is deleted.
    _pending_pop_values: dict[int, ast.AST] = {}

    def _rewrite_sequence_dict(
        name: str,
        *,
        set_key: object | None = None,
        set_val: ast.AST | None = None,
        del_key: object | None = None,
    ) -> ast.AST | None:
        """Apply setitem/pop to a Name-bound Dict key carrier in place.

        Updates every Name that currently aliases the same Dict AST so
        ``c=keys; c["z"]=c.pop("x"); keys.get("z")`` shares one rewrite
        (Unknown > false PASS). Returns the deleted value AST when ``del_key``
        is set.
        """

        lit = request_aliases.sequence_literal_aliases.get(name)
        if not isinstance(lit, ast.Dict):
            request_aliases.sequence_literal_aliases.pop(name, None)
            request_aliases.sequence_string_lists.pop(name, None)
            request_aliases.container_adapter_packs.pop(name, None)
            return None
        keys: list[ast.AST | None] = []
        vals: list[ast.AST | None] = []
        deleted: ast.AST | None = None
        for map_key, map_val in zip(lit.keys, lit.values):
            if (
                del_key is not None
                and isinstance(map_key, ast.Constant)
                and map_key.value == del_key
            ):
                deleted = map_val
                continue
            if (
                set_key is not None
                and isinstance(map_key, ast.Constant)
                and map_key.value == set_key
            ):
                continue
            keys.append(map_key)
            vals.append(map_val)
        if set_key is not None and set_val is not None:
            # ``keys["z"]=keys.pop("x")`` — use captured pop value when present.
            if isinstance(set_val, ast.Call):
                pending = _pending_pop_values.pop(id(set_val), None)
                if pending is not None:
                    set_val = pending
            keys.append(ast.Constant(value=set_key))
            vals.append(set_val)
        new_lit = ast.Dict(keys=keys, values=vals)
        aliased_names = [
            n
            for n, existing in request_aliases.sequence_literal_aliases.items()
            if existing is lit or n == name
        ]
        if name not in aliased_names:
            aliased_names.append(name)
        for n in aliased_names:
            request_aliases.sequence_literal_aliases[n] = new_lit
            request_aliases.note_projection_name_alias(
                n,
                new_lit,
                getattr_aliases=frozenset(getattr_aliases),
            )
        # Nested mutate: ``inner=keys["x"]; inner["y"]=…`` — update parent
        # Dict carriers whose values still point at the old nested lit.
        for n, existing in list(request_aliases.sequence_literal_aliases.items()):
            if not isinstance(existing, ast.Dict) or existing is new_lit:
                continue
            if not any(v is lit for v in existing.values):
                continue
            request_aliases.sequence_literal_aliases[n] = ast.Dict(
                keys=list(existing.keys),
                values=[new_lit if v is lit else v for v in existing.values],
            )
            request_aliases.note_projection_name_alias(
                n,
                request_aliases.sequence_literal_aliases[n],
                getattr_aliases=frozenset(getattr_aliases),
            )
        return deleted

    def _static_key_for_mutation(node: ast.AST) -> object | None:
        while isinstance(node, ast.NamedExpr):
            node = node.value
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in request_aliases.static_constant_names:
                return request_aliases.static_constant_names[node.id]
            return request_aliases.string_constant_names.get(node.id)
        return None

    def _note_alias_bindings(
        statement: ast.stmt, *, control_dependent: bool = False
    ) -> None:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                # Subscript stores mutate Name-bound key carriers.
                # Walrus bases ``(c := copy(keys))["z"] = …`` seed ``c`` first.
                if isinstance(target, ast.Subscript):
                    base = target.value
                    if isinstance(base, ast.NamedExpr) and isinstance(
                        base.target, ast.Name
                    ):
                        request_aliases.note_binding(base.target, base.value)
                        _note_callable_name_alias(
                            base.target,
                            base.value,
                            control_dependent=control_dependent,
                        )
                        request_aliases.note_projection_name_alias(
                            base.target.id,
                            base.value,
                            getattr_aliases=frozenset(getattr_aliases),
                        )
                        base = base.target
                    else:
                        while isinstance(base, ast.NamedExpr):
                            base = base.value
                    if isinstance(base, ast.Name):
                        key = _static_key_for_mutation(target.slice)
                        set_val = statement.value
                        # ``keys["z"]=keys.pop("x")`` — use captured pop value.
                        if isinstance(set_val, ast.Call):
                            pending = _pending_pop_values.pop(id(set_val), None)
                            if pending is not None:
                                set_val = pending
                        _rewrite_sequence_dict(
                            base.id, set_key=key, set_val=set_val
                        )
                request_aliases.note_binding(target, statement.value)
                _note_callable_name_alias(
                    target, statement.value, control_dependent=control_dependent
                )
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            if isinstance(statement.target, ast.Subscript):
                base = statement.target.value
                if isinstance(base, ast.NamedExpr) and isinstance(
                    base.target, ast.Name
                ):
                    request_aliases.note_binding(base.target, base.value)
                    _note_callable_name_alias(
                        base.target,
                        base.value,
                        control_dependent=control_dependent,
                    )
                    request_aliases.note_projection_name_alias(
                        base.target.id,
                        base.value,
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    base = base.target
                else:
                    while isinstance(base, ast.NamedExpr):
                        base = base.value
                if isinstance(base, ast.Name):
                    key = _static_key_for_mutation(statement.target.slice)
                    set_val = statement.value
                    if isinstance(set_val, ast.Call):
                        pending = _pending_pop_values.pop(id(set_val), None)
                        if pending is not None:
                            set_val = pending
                    _rewrite_sequence_dict(
                        base.id, set_key=key, set_val=set_val
                    )
            request_aliases.note_binding(statement.target, statement.value)
            _note_callable_name_alias(
                statement.target,
                statement.value,
                control_dependent=control_dependent,
            )

    def _note_named_expr_bindings(
        node: ast.AST, *, control_dependent: bool
    ) -> None:
        for child in ast.walk(node):
            if not isinstance(child, ast.NamedExpr):
                continue
            request_aliases.note_binding(child.target, child.value)
            _note_callable_name_alias(
                child.target, child.value, control_dependent=control_dependent
            )
            if request_aliases.assignment_escapes_state_identity(
                child.target, child.value
            ):
                _record_escape(
                    child,
                    ast.unparse(child),
                    control_dependent=control_dependent,
                )
            # Value-origin: walrus is outside the simple-rebinding calculus.
            if isinstance(child.target, ast.Name):
                alias_state.poison(child.target.id)

    def _observe_executed_expression(
        expr: ast.AST,
        *,
        control_dependent: bool,
        async_entry: bool = False,
    ) -> None:
        """Shared PE effect observer for every executed expression (#173).

        Owns value-origin / name-use accounting, request/state alias + walrus
        accounting, request/state call/mutation accounting (``_record_dynamic_calls``
        equivalent), and request-time module/callable identity mutation
        accounting via ``identity_session.observe_expression``. Control-flow
        structure stays in the CF walker; expression effects must not diverge
        between PE writer traversal and the identity scanner.
        """

        _mark_name_uses(expr, alias_state)
        _note_named_expr_bindings(expr, control_dependent=control_dependent)
        if request_aliases.expression_escapes_state_identity(expr):
            _record_escape(
                expr,
                ast.unparse(expr),
                control_dependent=control_dependent,
            )
        # Mutating views on Name-bound key carriers: ``keys.pop("x")`` /
        # ``keys.__setitem__(…)`` / ``operator.setitem`` / ``keys.update`` /
        # ``keys |= …`` rewrite Dict peels (Unknown > false PASS).
        # Capture pops first so ``keys |= {"z": keys.pop("x")}`` /
        # ``keys.update({"z": keys.pop("x")})`` see the deleted value
        # (ast.walk visits parents before children).
        for child in ast.walk(expr):
            if not isinstance(child, ast.Call):
                continue
            func = child.func
            while isinstance(func, ast.NamedExpr):
                func = func.value
            if not isinstance(func, ast.Attribute) or func.attr != "pop":
                continue
            base = func.value
            while isinstance(base, ast.NamedExpr):
                base = base.value
            if isinstance(base, ast.Name) and child.args:
                deleted = _rewrite_sequence_dict(
                    base.id, del_key=_static_key_for_mutation(child.args[0])
                )
                if deleted is not None:
                    _pending_pop_values[id(child)] = deleted
        for child in ast.walk(expr):
            if isinstance(child, ast.AugAssign) and isinstance(
                child.op, (ast.BitOr, ast.Add)
            ):
                target = child.target
                while isinstance(target, ast.NamedExpr):
                    target = target.value
                if isinstance(target, ast.Name):
                    # ``keys |= {"z": keys.pop("x")}`` — merge when RHS is a
                    # static Dict; otherwise drop peels (fail closed).
                    rhs = child.value
                    while isinstance(rhs, ast.NamedExpr):
                        rhs = rhs.value
                    if isinstance(rhs, ast.Dict):
                        for map_key, map_val in zip(rhs.keys, rhs.values):
                            if (
                                map_val is None
                                or not isinstance(map_key, ast.Constant)
                            ):
                                continue
                            set_val = map_val
                            if isinstance(set_val, ast.Call):
                                pending = _pending_pop_values.get(id(set_val))
                                if pending is not None:
                                    set_val = pending
                            _rewrite_sequence_dict(
                                target.id,
                                set_key=map_key.value,
                                set_val=set_val,
                            )
                    else:
                        request_aliases.sequence_literal_aliases.pop(
                            target.id, None
                        )
                        request_aliases.sequence_string_lists.pop(target.id, None)
                        request_aliases.container_adapter_packs.pop(
                            target.id, None
                        )
                continue
            if not isinstance(child, ast.Call):
                continue
            func = child.func
            while isinstance(func, ast.NamedExpr):
                func = func.value
            # ``operator.call(p, *([args].pop(0)))`` /
            # ``partial(operator.call, p)(*([args].pop(0)))`` /
            # ``methodcaller("__call__", *([args].pop(0)))(operator.setitem)`` /
            # packed methodcaller("__call__", p, keys)(operator.call) —
            # rewrite onto the underlying setitem Call (Unknown > false PASS).
            from ovk.compilers.authorization.python_callee_resolution import (
                _attrgetter_static_name as _ag_si_fp,
                _flatten_starred_args as _flat_call_si,
                _is_partial_factory as _is_partial_call_si,
                _methodcaller_call_bound_args as _mc_call_si,
                _methodcaller_static_name,
                _methodcaller_static_name as _mc_si_fp,
                _peel_call_func as _peel_call_si,
                _projection_factory_name,
                _rewrite_applied_dunder_call as _rewrite_si_applied,
                _shallow_packed_callee_exprs,
            )

            # ``getattr(list,"__getitem__")([partial(op.call,p)],0)(*star)`` /
            # ``getattr([partial],"__getitem__")(0)(*star)`` /
            # ``getattr(c,"pop")()(*star)`` share list0 / partial peels.
            _si_fp: dict[str, tuple[str, str | None]] = {}
            for _mk, _mv in request_aliases.methodcaller_factories.items():
                if isinstance(_mv, ast.Call):
                    _mcn = _mc_si_fp(
                        _mv,
                        projection_aliases=(
                            request_aliases.operator_projection_aliases
                        ),
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    if _mcn is not None:
                        _si_fp[_mk] = ("methodcaller", _mcn)
                    _agn = _ag_si_fp(
                        _mv,
                        projection_aliases=(
                            request_aliases.operator_projection_aliases
                        ),
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    if _agn is not None:
                        _si_fp[_mk] = ("attrgetter", _agn)
            for _ in range(4):
                if not isinstance(child, ast.Call):
                    break
                rewritten_si = _rewrite_si_applied(
                    child,
                    sequence_aliases=request_aliases.sequence_literal_aliases,
                    factory_products=_si_fp,
                )
                if rewritten_si is None and isinstance(child.func, ast.Call):
                    inner_si = _rewrite_si_applied(
                        child.func,
                        sequence_aliases=request_aliases.sequence_literal_aliases,
                        factory_products=_si_fp,
                    )
                    if inner_si is not None:
                        rewritten_si = ast.Call(
                            func=inner_si,
                            args=list(child.args),
                            keywords=list(child.keywords),
                        )
                if rewritten_si is None or rewritten_si is child:
                    break
                child = rewritten_si
            func = child.func
            while isinstance(func, ast.NamedExpr):
                func = func.value

            # ``partial(operator.call, p)(*star)`` ≡ ``operator.call(p, *star)``
            # including Name-bound ``poc=…`` / packed ``[partial(…)][0]``
            # (Unknown > false PASS).
            call_factory: ast.AST = func
            if isinstance(func, ast.Name):
                bound_call_p = request_aliases.partial_factories.get(func.id)
                if bound_call_p is not None:
                    call_factory = bound_call_p
            else:
                # ``[partial(operator.call, p)][0]`` / ``.pop(0)`` /
                # ``next(iter([partial(operator.call, p)]))`` share the
                # packed factory apply (Unknown > false PASS).
                for cand in _shallow_packed_callee_exprs(func):
                    nested = cand
                    while isinstance(nested, ast.NamedExpr):
                        nested = nested.value
                    if isinstance(nested, ast.Name):
                        bound_call_p = request_aliases.partial_factories.get(
                            nested.id
                        )
                        if bound_call_p is not None:
                            call_factory = bound_call_p
                            break
                    if isinstance(nested, ast.Call) and _is_partial_call_si(
                        nested,
                        getattr_aliases=frozenset(getattr_aliases),
                    ):
                        call_factory = nested
                        break
            if isinstance(call_factory, ast.Call) and _is_partial_call_si(
                call_factory,
                getattr_aliases=frozenset(getattr_aliases),
            ):
                p_flat = _flat_call_si(
                    call_factory.args,
                    sequence_aliases=request_aliases.sequence_literal_aliases,
                    projection_aliases=(
                        request_aliases.operator_projection_aliases
                    ),
                )
                if p_flat:
                    head = _peel_call_si(p_flat[0])
                    head_is_call = (
                        (
                            isinstance(head, ast.Name)
                            and (
                                head.id == "call"
                                or request_aliases.operator_projection_aliases.get(
                                    head.id
                                )
                                == "call"
                            )
                        )
                        or (
                            isinstance(head, ast.Attribute) and head.attr == "call"
                        )
                    )
                    if head_is_call:
                        applied = _flat_call_si(
                            child.args,
                            sequence_aliases=(
                                request_aliases.sequence_literal_aliases
                            ),
                            projection_aliases=(
                                request_aliases.operator_projection_aliases
                            ),
                        )
                        child = ast.Call(
                            func=head,
                            args=[*p_flat[1:], *applied],
                            keywords=list(child.keywords),
                        )
                        func = child.func
                        while isinstance(func, ast.NamedExpr):
                            func = func.value
            call_proj = _projection_factory_name(
                child,
                projection_aliases=request_aliases.operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
            )
            if call_proj is None:
                for cand in _shallow_packed_callee_exprs(func):
                    nested = cand
                    while isinstance(nested, ast.NamedExpr):
                        nested = nested.value
                    if isinstance(nested, ast.Name):
                        call_proj = request_aliases.operator_projection_aliases.get(
                            nested.id, nested.id
                        )
                    elif isinstance(nested, ast.Attribute):
                        call_proj = _PROJECTION_DUNDER_ALIASES.get(
                            nested.attr, nested.attr
                        )
                    if call_proj == "call":
                        break
                    call_proj = None
            if call_proj == "call":
                flat_call = _flat_call_si(
                    child.args,
                    sequence_aliases=request_aliases.sequence_literal_aliases,
                    projection_aliases=(
                        request_aliases.operator_projection_aliases
                    ),
                )
                if len(flat_call) >= 2:
                    child = ast.Call(
                        func=flat_call[0],
                        args=list(flat_call[1:]),
                        keywords=list(child.keywords),
                    )
                    func = child.func
                    while isinstance(func, ast.NamedExpr):
                        func = func.value
            mc_bound = _mc_call_si(
                child,
                projection_aliases=request_aliases.operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
                sequence_aliases=request_aliases.sequence_literal_aliases,
                bound_map=request_aliases.methodcaller_factories,
                str_resolver=lambda n: (
                    request_aliases.string_constant_names.get(n.id)
                    if isinstance(n, ast.Name)
                    else None
                ),
            )
            if mc_bound is not None and child.args:
                recv = child.args[0]
                while isinstance(recv, ast.NamedExpr):
                    recv = recv.value
                child = ast.Call(
                    func=recv,
                    args=list(mc_bound),
                    keywords=[],
                )
                func = child.func
                while isinstance(func, ast.NamedExpr):
                    func = func.value
            # ``operator.setitem(keys, "z", val)`` / getattr setitem /
            # packed ``[operator.setitem][0]`` / Name-bound /
            # ``operator.ior(keys, {…})`` / ``operator.__ior__`` /
            # ``methodcaller("__setitem__", …)(keys)``.
            proj = _projection_factory_name(
                child,
                projection_aliases=request_aliases.operator_projection_aliases,
                getattr_aliases=frozenset(getattr_aliases),
            )
            if proj is None:
                if isinstance(func, ast.Name):
                    proj = request_aliases.operator_projection_aliases.get(
                        func.id, func.id
                    )
                elif isinstance(func, ast.Attribute):
                    proj = _PROJECTION_DUNDER_ALIASES.get(func.attr, func.attr)
                elif isinstance(func, ast.Call):
                    g_func = func.func
                    while isinstance(g_func, ast.NamedExpr):
                        g_func = g_func.value
                    is_g = (
                        isinstance(g_func, ast.Name)
                        and g_func.id in getattr_aliases
                    ) or (
                        isinstance(g_func, ast.Attribute)
                        and g_func.attr == "getattr"
                    )
                    if (
                        is_g
                        and len(func.args) >= 2
                        and isinstance(func.args[1], ast.Constant)
                        and isinstance(func.args[1].value, str)
                    ):
                        raw = func.args[1].value
                        proj = _PROJECTION_DUNDER_ALIASES.get(raw, raw)
                if proj is None:
                    for cand in _shallow_packed_callee_exprs(func):
                        nested = cand
                        while isinstance(nested, ast.NamedExpr):
                            nested = nested.value
                        if isinstance(nested, ast.Name):
                            proj = request_aliases.operator_projection_aliases.get(
                                nested.id, nested.id
                            )
                        elif isinstance(nested, ast.Attribute):
                            proj = _PROJECTION_DUNDER_ALIASES.get(
                                nested.attr, nested.attr
                            )
                        if proj in {"setitem", "ior", "or_"}:
                            break
                        proj = None
            # ``operator.setitem(keys, k, v)`` / ``getattr(keys,"__setitem__")(k, v)`` /
            # ``partial(operator.setitem, keys, k)(v)`` / packed partial peels /
            # ``p(*args)`` with ``args=(keys,k,v)`` (Unknown > false PASS).
            from ovk.compilers.authorization.python_callee_resolution import (
                _flatten_starred_args as _flat_setitem_args,
            )

            child_args = _flat_setitem_args(
                child.args,
                sequence_aliases=request_aliases.sequence_literal_aliases,
                projection_aliases=(
                    request_aliases.operator_projection_aliases
                ),
            )
            set_base: ast.AST | None = None
            set_key_node: ast.AST | None = None
            set_val_node: ast.AST | None = None
            if proj == "setitem" and len(child_args) >= 3:
                set_base = child_args[0]
                set_key_node = child_args[1]
                set_val_node = child_args[2]
            # Name-bound view products before getattr Call layout: Name ``si``
            # is also aliased to operator ``setitem``, so ``next(iter([si]))``
            # must not treat ``next(...)`` as ``getattr(keys,"__setitem__")``.
            if set_base is None and (
                proj == "setitem" or proj is None
            ) and len(child_args) >= 2:
                from ovk.compilers.authorization.python_callee_resolution import (
                    _peel_transparent_callee as _peel_si_call,
                )

                for si_cand in [func, *_shallow_packed_callee_exprs(func)]:
                    si_nested = si_cand
                    while isinstance(si_nested, ast.NamedExpr):
                        si_nested = si_nested.value
                    si_nested = _peel_si_call(si_nested)
                    if not isinstance(si_nested, ast.Name):
                        continue
                    view = request_aliases.dict_view_products.get(si_nested.id)
                    recv = request_aliases.bound_view_receivers.get(si_nested.id)
                    if (
                        view is not None
                        and view.split(".")[-1] in {"__setitem__", "setitem"}
                        and recv is not None
                    ):
                        set_base = ast.Name(id=recv, ctx=ast.Load())
                        set_key_node = child_args[0]
                        set_val_node = child_args[1]
                        break
            if (
                set_base is None
                and proj == "setitem"
                and isinstance(func, ast.Call)
                and len(child_args) >= 2
                and len(func.args) >= 1
            ):
                # Bound ``getattr(keys, "__setitem__")(k, v)``.
                set_base = func.args[0]
                set_key_node = child_args[0]
                set_val_node = child_args[1]
            if set_base is None:
                from ovk.compilers.authorization.python_callee_resolution import (
                    _is_partial_factory as _is_partial_setitem,
                    _projection_factory_name as _proj_partial_bound,
                    _getattr_static_name as _g_setitem_bound,
                    _peel_call_func as _peel_setitem,
                )

                partial_candidates = [func, *_shallow_packed_callee_exprs(func)]
                # Recover Name-bound ``p=partial(setitem, keys, k); p(v)`` /
                # ``p=partial(setitem); p(keys,k,v)`` /
                # ``(0 or p)(…)`` / ``next(iter([p]))(…)`` via shallow peel.
                if isinstance(func, ast.Name):
                    bound_p = request_aliases.partial_factories.get(func.id)
                    if bound_p is not None:
                        partial_candidates.append(bound_p)
                for cand in partial_candidates:
                    nested = cand
                    while isinstance(nested, ast.NamedExpr):
                        nested = nested.value
                    # BoolOp / next(iter([p])) / packed Name → factory Call.
                    if isinstance(nested, ast.Name):
                        bound_p = request_aliases.partial_factories.get(nested.id)
                        if bound_p is not None:
                            nested = bound_p
                    if not (
                        isinstance(nested, ast.Call)
                        and _is_partial_setitem(
                            nested,
                            getattr_aliases=frozenset(getattr_aliases),
                        )
                        and nested.args
                        and child_args
                    ):
                        continue
                    bound0 = _peel_setitem(nested.args[0])
                    bound_proj = None
                    bound_recv: ast.AST | None = None
                    if isinstance(bound0, ast.Name):
                        bound_proj = request_aliases.operator_projection_aliases.get(
                            bound0.id, bound0.id
                        )
                    elif isinstance(bound0, ast.Attribute):
                        bound_proj = _PROJECTION_DUNDER_ALIASES.get(
                            bound0.attr, bound0.attr
                        )
                        if bound0.attr == "__setitem__":
                            bound_proj = "setitem"
                            bound_recv = bound0.value
                    elif isinstance(bound0, ast.Call):
                        g_b = _g_setitem_bound(
                            bound0, getattr_aliases=frozenset(getattr_aliases)
                        )
                        if g_b in {"setitem", "__setitem__"}:
                            bound_proj = "setitem"
                            if g_b == "__setitem__" and bound0.args:
                                bound_recv = bound0.args[0]
                        else:
                            syn = ast.Call(
                                func=bound0,
                                args=list(nested.args[1:3]),
                                keywords=[],
                            )
                            bound_proj = _proj_partial_bound(
                                syn,
                                projection_aliases=(
                                    request_aliases.operator_projection_aliases
                                ),
                                getattr_aliases=frozenset(getattr_aliases),
                            )
                    is_setitem = bound_proj == "setitem" or (
                        isinstance(bound0, ast.Attribute)
                        and bound0.attr in {"setitem", "__setitem__"}
                    ) or (
                        isinstance(bound0, ast.Name)
                        and bound0.id == "setitem"
                    )
                    if not is_setitem:
                        continue
                    # ``partial(setitem, keys, k)(v)`` — 3 bound, 1 apply.
                    if len(nested.args) >= 3 and child_args:
                        set_base = nested.args[1]
                        set_key_node = nested.args[2]
                        set_val_node = child_args[0]
                        break
                    # ``partial(setitem, keys)(k, v)`` — under-applied.
                    if len(nested.args) >= 2 and len(child_args) >= 2:
                        set_base = nested.args[1]
                        set_key_node = child_args[0]
                        set_val_node = child_args[1]
                        break
                    # ``partial(setitem)(keys, k, v)`` / ``p(*args)`` zero-bound.
                    if len(nested.args) == 1 and len(child_args) >= 3:
                        set_base = child_args[0]
                        set_key_node = child_args[1]
                        set_val_node = child_args[2]
                        break
                    # ``partial(keys.__setitem__|getattr(keys,"__setitem__"), k)(v)``.
                    if (
                        bound_recv is not None
                        and len(nested.args) >= 2
                        and child_args
                    ):
                        set_base = bound_recv
                        set_key_node = nested.args[1]
                        set_val_node = child_args[0]
                        break
            if (
                set_base is not None
                and set_key_node is not None
                and set_val_node is not None
            ):
                while isinstance(set_base, ast.NamedExpr):
                    set_base = set_base.value
                if isinstance(set_base, ast.Name):
                    set_val = set_val_node
                    if isinstance(set_val, ast.Call):
                        pending = _pending_pop_values.get(id(set_val))
                        if pending is not None:
                            set_val = pending
                    _rewrite_sequence_dict(
                        set_base.id,
                        set_key=_static_key_for_mutation(set_key_node),
                        set_val=set_val,
                    )
                continue
            if proj in {"ior", "or_"} and len(child.args) >= 2:
                base = child.args[0]
                while isinstance(base, ast.NamedExpr):
                    base = base.value
                rhs = child.args[1]
                while isinstance(rhs, ast.NamedExpr):
                    rhs = rhs.value
                if isinstance(base, ast.Name) and isinstance(rhs, ast.Dict):
                    for map_key, map_val in zip(rhs.keys, rhs.values):
                        if (
                            map_val is None
                            or not isinstance(map_key, ast.Constant)
                        ):
                            continue
                        set_val = map_val
                        if isinstance(set_val, ast.Call):
                            pending = _pending_pop_values.get(id(set_val))
                            if pending is not None:
                                set_val = pending
                        _rewrite_sequence_dict(
                            base.id,
                            set_key=map_key.value,
                            set_val=set_val,
                        )
                elif isinstance(base, ast.Name):
                    request_aliases.sequence_literal_aliases.pop(base.id, None)
                    request_aliases.sequence_string_lists.pop(base.id, None)
                    request_aliases.container_adapter_packs.pop(base.id, None)
                continue
            # ``methodcaller("__setitem__"|"update", …)(keys)`` /
            # Name-bound ``mc=methodcaller(...); mc(keys)`` /
            # packed / getattr methodcaller factory peels.
            mc_name = None
            mc_factory = None
            if isinstance(func, ast.Call):
                mc_name = _methodcaller_static_name(
                    func,
                    projection_aliases=request_aliases.operator_projection_aliases,
                    getattr_aliases=frozenset(getattr_aliases),
                )
                if mc_name is not None:
                    mc_factory = func
            if mc_name is None and isinstance(func, ast.Name):
                bound_mc = request_aliases.methodcaller_factories.get(func.id)
                if bound_mc is not None:
                    mc_name = _methodcaller_static_name(
                        bound_mc,
                        projection_aliases=(
                            request_aliases.operator_projection_aliases
                        ),
                        getattr_aliases=frozenset(getattr_aliases),
                    )
                    if mc_name is not None:
                        mc_factory = bound_mc
            if mc_name is None:
                for cand in _shallow_packed_callee_exprs(func):
                    if isinstance(cand, ast.Call):
                        mc_name = _methodcaller_static_name(
                            cand,
                            projection_aliases=(
                                request_aliases.operator_projection_aliases
                            ),
                            getattr_aliases=frozenset(getattr_aliases),
                        )
                        if mc_name is not None:
                            mc_factory = cand
                            break
                    elif isinstance(cand, ast.Name):
                        bound_mc = request_aliases.methodcaller_factories.get(
                            cand.id
                        )
                        if bound_mc is not None:
                            mc_name = _methodcaller_static_name(
                                bound_mc,
                                projection_aliases=(
                                    request_aliases.operator_projection_aliases
                                ),
                                getattr_aliases=frozenset(getattr_aliases),
                            )
                            if mc_name is not None:
                                mc_factory = bound_mc
                                break
            if (
                mc_name in {"__setitem__", "setdefault", "update"}
                and mc_factory is not None
                and child.args
            ):
                base = child.args[0]
                while isinstance(base, ast.NamedExpr):
                    base = base.value
                if isinstance(base, ast.Name):
                    bound_args = list(mc_factory.args[1:]) + list(child.args[1:])
                    bound_keywords = list(mc_factory.keywords) + list(
                        child.keywords
                    )
                    if mc_name in {"__setitem__", "setdefault"} and len(
                        bound_args
                    ) >= 2:
                        set_val = bound_args[1]
                        if isinstance(set_val, ast.Call):
                            pending = _pending_pop_values.get(id(set_val))
                            if pending is not None:
                                set_val = pending
                        _rewrite_sequence_dict(
                            base.id,
                            set_key=_static_key_for_mutation(bound_args[0]),
                            set_val=set_val,
                        )
                    elif mc_name == "update":
                        rewritten = False
                        if bound_args:
                            rhs = bound_args[0]
                            while isinstance(rhs, ast.NamedExpr):
                                rhs = rhs.value
                            if isinstance(rhs, ast.Dict):
                                for map_key, map_val in zip(
                                    rhs.keys, rhs.values
                                ):
                                    if (
                                        map_val is None
                                        or not isinstance(map_key, ast.Constant)
                                    ):
                                        continue
                                    set_val = map_val
                                    if isinstance(set_val, ast.Call):
                                        pending = _pending_pop_values.get(
                                            id(set_val)
                                        )
                                        if pending is not None:
                                            set_val = pending
                                    _rewrite_sequence_dict(
                                        base.id,
                                        set_key=map_key.value,
                                        set_val=set_val,
                                    )
                                    rewritten = True
                        for kw in bound_keywords:
                            if kw.arg is None:
                                continue
                            set_val = kw.value
                            if isinstance(set_val, ast.Call):
                                pending = _pending_pop_values.get(id(set_val))
                                if pending is not None:
                                    set_val = pending
                            _rewrite_sequence_dict(
                                base.id,
                                set_key=kw.arg,
                                set_val=set_val,
                            )
                            rewritten = True
                        if not rewritten:
                            request_aliases.sequence_literal_aliases.pop(
                                base.id, None
                            )
                            request_aliases.sequence_string_lists.pop(
                                base.id, None
                            )
                            request_aliases.container_adapter_packs.pop(
                                base.id, None
                            )
                continue
            if not isinstance(func, ast.Attribute):
                continue
            mut_attr = func.attr
            mut_recv = func.value
            base = mut_recv
            while isinstance(base, ast.NamedExpr):
                base = base.value
            if not isinstance(base, ast.Name):
                continue
            if mut_attr == "pop":
                # Already captured in the pre-pass above.
                continue
            if mut_attr in {"__ior__", "__or__"} and child.args:
                # ``keys.__ior__({…})`` / ``keys.__or__({…})`` — share ior peels.
                rhs = child.args[0]
                while isinstance(rhs, ast.NamedExpr):
                    rhs = rhs.value
                if isinstance(rhs, ast.Dict):
                    for map_key, map_val in zip(rhs.keys, rhs.values):
                        if (
                            map_val is None
                            or not isinstance(map_key, ast.Constant)
                        ):
                            continue
                        set_val = map_val
                        if isinstance(set_val, ast.Call):
                            pending = _pending_pop_values.get(id(set_val))
                            if pending is not None:
                                set_val = pending
                        _rewrite_sequence_dict(
                            base.id,
                            set_key=map_key.value,
                            set_val=set_val,
                        )
                else:
                    request_aliases.sequence_literal_aliases.pop(base.id, None)
                    request_aliases.sequence_string_lists.pop(base.id, None)
                    request_aliases.container_adapter_packs.pop(base.id, None)
                continue
            if mut_attr in {"__setitem__", "setdefault"} and len(child.args) >= 2:
                set_val = child.args[1]
                if isinstance(set_val, ast.Call):
                    pending = _pending_pop_values.get(id(set_val))
                    if pending is not None:
                        set_val = pending
                _rewrite_sequence_dict(
                    base.id,
                    set_key=_static_key_for_mutation(child.args[0]),
                    set_val=set_val,
                )
            elif mut_attr == "update" and (child.args or child.keywords):
                # ``keys.update({"z": keys.pop("x")})`` /
                # ``keys.update(z=keys.pop("x"))`` — precise when RHS keys are
                # static; otherwise drop peels (fail closed).
                rewritten = False
                if child.args:
                    rhs = child.args[0]
                    while isinstance(rhs, ast.NamedExpr):
                        rhs = rhs.value
                    if isinstance(rhs, ast.Dict):
                        for map_key, map_val in zip(rhs.keys, rhs.values):
                            if (
                                map_val is None
                                or not isinstance(map_key, ast.Constant)
                            ):
                                continue
                            set_val = map_val
                            if isinstance(set_val, ast.Call):
                                pending = _pending_pop_values.get(id(set_val))
                                if pending is not None:
                                    set_val = pending
                            _rewrite_sequence_dict(
                                base.id,
                                set_key=map_key.value,
                                set_val=set_val,
                            )
                            rewritten = True
                for kw in child.keywords:
                    if kw.arg is None:
                        continue
                    set_val = kw.value
                    if isinstance(set_val, ast.Call):
                        pending = _pending_pop_values.get(id(set_val))
                        if pending is not None:
                            set_val = pending
                    _rewrite_sequence_dict(
                        base.id,
                        set_key=kw.arg,
                        set_val=set_val,
                    )
                    rewritten = True
                if not rewritten:
                    request_aliases.sequence_literal_aliases.pop(base.id, None)
                    request_aliases.sequence_string_lists.pop(base.id, None)
                    request_aliases.container_adapter_packs.pop(base.id, None)
            elif mut_attr == "copy" and not child.args:
                # Bound ``c = keys.copy()`` is handled on Assign; in-expression
                # ``keys.copy()`` as a standalone Expr is a no-op for peels.
                pass
            elif mut_attr in {"clear", "__delitem__"}:
                # Coarse mutators: drop precise peels (fail closed).
                request_aliases.sequence_literal_aliases.pop(base.id, None)
                request_aliases.sequence_string_lists.pop(base.id, None)
                request_aliases.container_adapter_packs.pop(base.id, None)
        # Comprehension Attribute/subscript for-targets rebind exports
        # (``[0 for helpers.write_state in [evil]]``) — observe as Assign.
        # Also seed instance aliases for ``[x.fn() for x in [Box()]]``.
        for child in ast.walk(expr):
            if not isinstance(
                child, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
            ):
                continue
            for gen in child.generators:
                if identity_session is not None and _assign_target_has_attr_or_subscript(
                    gen.target
                ):
                    identity_session.observe_statement(
                        ast.Assign(targets=[gen.target], value=gen.iter)
                    )
                _seed_assign_target_instance_bindings(gen.target, gen.iter)
        # Seed walrus class/instance aliases before Call follow so
        # ``(C := Cls)()()`` observes ``__call__`` (Unknown > false PASS).
        for child in ast.walk(expr):
            if not isinstance(child, ast.NamedExpr):
                continue
            if not isinstance(child.target, ast.Name):
                continue
            if isinstance(child.value, ast.Name) and child.value.id in getattr_aliases:
                getattr_aliases.add(child.target.id)
            _seed_name_instance_or_class(child.target.id, child.value)
            request_aliases.note_projection_name_alias(
                child.target.id,
                child.value,
                getattr_aliases=frozenset(getattr_aliases),
            )
        # Identity first: arg-order mutators (``write_state(..., poison())``)
        # must poison resolve before interprocedural write inlining.
        if identity_session is not None:
            identity_session.observe_expression(expr)
        # Wrap as Expr so setattr / escape / interprocedural call accounting
        # reuses the statement walker without inventing a second theorem.
        _record_dynamic_calls(
            ast.Expr(value=expr),  # type: ignore[arg-type]
            control_dependent=control_dependent,
            async_entry=async_entry,
        )
        # Walrus callable products (``fn := mid()`` / ``fn := mid() if c else
        # noop``) bind only after Calls are followed and returned closures /
        # awaitables are recorded.
        for child in ast.walk(expr):
            if not isinstance(child, ast.NamedExpr):
                continue
            if not isinstance(child.target, ast.Name):
                continue
            closures, unknown = _callable_products_from_expr(child.value)
            if closures or unknown:
                _install_returned_closures(
                    child.target.id, closures, unknown=unknown
                )
            elif isinstance(child.value, ast.Call):
                _bind_call_product_to_name(child.target.id, child.value)

    def _visit_statement(
        statement: ast.stmt,
        *,
        control_dependent: bool = False,
    ) -> None:
        nonlocal frame_returned_unknown
        if isinstance(statement, ast.Assign):
            # Observe identity before write inlining so RHS arg-order mutators
            # invalidate authorizing resolve in the same statement.
            if identity_session is not None:
                identity_session.observe_statement(statement)
            for target in statement.targets:
                _record_assign_target(
                    target,
                    statement.value,
                    statement,
                    dynamic=False,
                    control_dependent=control_dependent,
                )
                # Unpack / star peels: ``C, = [Cls]`` / ``*xs, = [Mut]``.
                # The session already observed the real Assign; a synthetic
                # element alias would clobber ``d = {...}`` container packs.
                _seed_assign_target_instance_bindings(
                    target, statement.value, observe_session=False
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
            _note_alias_bindings(statement, control_dependent=control_dependent)
            apply_statement_bindings(
                statement,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            return

        if isinstance(statement, ast.AnnAssign):
            _observe_executed_expression(
                statement.annotation, control_dependent=control_dependent
            )
            if statement.value is None:
                if identity_session is not None:
                    identity_session.observe_statement(statement)
                return
            if identity_session is not None:
                identity_session.observe_statement(statement)
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
            _note_alias_bindings(statement, control_dependent=control_dependent)
            apply_statement_bindings(
                statement,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            return

        if isinstance(statement, ast.AugAssign):
            if identity_session is not None:
                identity_session.observe_statement(statement)
            _record_assign_target(
                statement.target,
                statement.value,
                statement,
                dynamic=True,
                control_dependent=control_dependent,
            )
            # RHS executes: setattr / escape / callable-identity mutators /
            # key-carrier ``keys |= {"z": keys.pop("x")}`` rewrites.
            _observe_executed_expression(
                statement.value, control_dependent=control_dependent
            )
            if isinstance(statement.op, (ast.BitOr, ast.Add)):
                target = statement.target
                while isinstance(target, ast.NamedExpr):
                    target = target.value
                if isinstance(target, ast.Name):
                    rhs = statement.value
                    while isinstance(rhs, ast.NamedExpr):
                        rhs = rhs.value
                    if isinstance(rhs, ast.Dict):
                        for map_key, map_val in zip(rhs.keys, rhs.values):
                            if (
                                map_val is None
                                or not isinstance(map_key, ast.Constant)
                            ):
                                continue
                            set_val = map_val
                            if isinstance(set_val, ast.Call):
                                pending = _pending_pop_values.get(id(set_val))
                                if pending is not None:
                                    set_val = pending
                            _rewrite_sequence_dict(
                                target.id,
                                set_key=map_key.value,
                                set_val=set_val,
                            )
                    else:
                        request_aliases.sequence_literal_aliases.pop(
                            target.id, None
                        )
                        request_aliases.sequence_string_lists.pop(target.id, None)
                        request_aliases.container_adapter_packs.pop(
                            target.id, None
                        )
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
            apply_statement_bindings(
                statement,
                path=path,
                handler_param_names=handler_param_names,
                alias_state=alias_state,
            )
            return

        if isinstance(statement, ast.Delete):
            # ``del request.state.bypass_filter`` (and del in if body) after a
            # literal server write must not yield source_proved authorize —
            # record as state mutation/dynamic (#173).
            if identity_session is not None:
                identity_session.observe_statement(statement)
            for target in statement.targets:
                field, exact = request_aliases.field_from_assign_target(target)
                if field is not None:
                    writes.append(
                        StateAttributeWrite(
                            field_name=field,
                            value_expression=ast.unparse(statement),
                            origin=_classify(ast.Constant(value=None)),
                            dynamic=True,
                            source_range=_origin(path, statement).source_range,
                            path=path,
                            control_dependent=control_dependent or (not exact),
                        )
                    )
                    continue
                if request_aliases.is_poison_state_store(target):
                    _record_escape(
                        statement,
                        ast.unparse(statement),
                        control_dependent=control_dependent,
                    )
                    continue
                # Plausible ``*.state.<field>`` delete outside proved alias.
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Attribute)
                    and target.value.attr == "state"
                ):
                    _record_escape(
                        statement,
                        ast.unparse(statement),
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
            # Test executes before branch / loop body selection (#173).
            # While: test runs at least once; nested short-circuit may-effects
            # stay conservative via the shared observer (Unknown > false PASS).
            _observe_executed_expression(
                statement.test, control_dependent=control_dependent
            )
            pre_identity: RequestTimeIdentityState | None = (
                identity_session.fork() if identity_session is not None else None
            )
            pre_aliases = request_aliases.snapshot()
            pre_alias_state = alias_state.snapshot()
            pre_callable = _snapshot_callable_env()
            for child in statement.body:
                _visit_statement(child, control_dependent=True)
            body_identity = (
                identity_session.snapshot() if identity_session is not None else None
            )
            body_aliases = request_aliases.snapshot()
            body_alias_state = alias_state.snapshot()
            body_callable = _snapshot_callable_env()
            request_aliases.restore(pre_aliases)
            alias_state.restore(pre_alias_state)
            _restore_callable_env(pre_callable)
            if identity_session is not None and pre_identity is not None:
                identity_session.restore(pre_identity)
            for child in statement.orelse:
                _visit_statement(child, control_dependent=True)
            else_aliases = request_aliases.snapshot()
            else_alias_state = alias_state.snapshot()
            else_callable = _snapshot_callable_env()
            if identity_session is not None and body_identity is not None:
                else_identity = identity_session.snapshot()
                # If: both branches. While with empty orelse: else_identity is
                # the zero-iteration predecessor after restore.
                identity_session.join([body_identity, else_identity])
            request_aliases.install_join([body_aliases, else_aliases])
            alias_state.install_join([body_alias_state, else_alias_state])
            _join_callable_envs([body_callable, else_callable])
            return

        if isinstance(statement, (ast.For, ast.AsyncFor)):
            # Iterable always executes before zero-iteration / body join (#173).
            # AsyncFor entry drives async generator bodies (not bare Call).
            _observe_executed_expression(
                statement.iter,
                control_dependent=control_dependent,
                async_entry=isinstance(statement, ast.AsyncFor),
            )
            # Attribute / subscript for-targets rebind exports
            # (``for helpers.write_state in [evil]``,
            # ``for (helpers.write_state,) in [(evil,)]``) — observe as Assign.
            if identity_session is not None and _assign_target_has_attr_or_subscript(
                statement.target
            ):
                identity_session.observe_statement(
                    ast.Assign(
                        targets=[statement.target],
                        value=statement.iter,
                    )
                )
            # Identity-session seed (shared element resolver): ``for C in
            # d.keys()/values()/items()`` / comps / zip / enumerate / Name packs
            # flow into class, exec/eval, type-protocol and container aliases.
            if identity_session is not None:
                identity_session.observe_for_binding(
                    statement.target, statement.iter, body=statement.body
                )
            # Instance carriers: ``for x in [Box()]: x.fn()`` (comp parity).
            _seed_assign_target_instance_bindings(statement.target, statement.iter)
            # ``for s in [request.state]: s.field = client`` must not authorize.
            # IfExp/BoolOp packing, container adapters/views, and Call iters that
            # receive identity (module-level generators) are residual escapes.
            iter_escapes = (
                request_aliases.is_request_or_state_expr(statement.iter)
                or request_aliases.packs_request_or_state_identity(statement.iter)
                or request_aliases.is_state_dict_surface(statement.iter)
            )
            if isinstance(statement.iter, ast.Call) and (
                request_aliases.call_iter_carries_request_or_state_identity(
                    statement.iter
                )
            ):
                iter_escapes = True
            if iter_escapes:
                _record_escape(
                    statement,
                    ast.unparse(statement),
                    control_dependent=True,
                )
            # Loop target severs precise aliasing for the iterated path only;
            # zero-iteration join preserves may-alias (#171). For-else walks
            # from the pre-loop env (like while/else), not after body-only.
            pre_identity = (
                identity_session.fork() if identity_session is not None else None
            )
            pre_aliases = request_aliases.snapshot()
            pre_alias_state = alias_state.snapshot()
            pre_callable = _snapshot_callable_env()
            target_names = _collect_assign_target_names(statement.target)
            request_aliases.poison_names(target_names)
            for name in target_names:
                alias_state.poison(name)
            for child in statement.body:
                _visit_statement(child, control_dependent=True)
            body_identity = (
                identity_session.snapshot() if identity_session is not None else None
            )
            body_aliases = request_aliases.snapshot()
            body_alias_state = alias_state.snapshot()
            body_callable = _snapshot_callable_env()
            request_aliases.restore(pre_aliases)
            alias_state.restore(pre_alias_state)
            _restore_callable_env(pre_callable)
            if identity_session is not None and pre_identity is not None:
                identity_session.restore(pre_identity)
            for child in statement.orelse:
                _visit_statement(child, control_dependent=True)
            else_aliases = request_aliases.snapshot()
            else_alias_state = alias_state.snapshot()
            else_callable = _snapshot_callable_env()
            if identity_session is not None and pre_identity is not None:
                else_identity = identity_session.snapshot()
                predecessors = [pre_identity, else_identity]
                if body_identity is not None:
                    predecessors.insert(1, body_identity)
                identity_session.join(predecessors)
            request_aliases.install_join([pre_aliases, body_aliases, else_aliases])
            alias_state.install_join(
                [pre_alias_state, body_alias_state, else_alias_state]
            )
            _join_callable_envs([pre_callable, body_callable, else_callable])
            return

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            assigned = _collect_assigned_names_in_statements(list(statement.body))
            bound_as: set[str] = set()
            for item in statement.items:
                # context_expr effects are unconditional on entering (#173).
                # AsyncWith entry awaits ``__aenter__`` / async CM factories.
                is_async_with = isinstance(statement, ast.AsyncWith)
                _observe_executed_expression(
                    item.context_expr,
                    control_dependent=control_dependent,
                    async_entry=is_async_with,
                )
                # Local class context managers: protocol entry runs
                # ``__aenter__`` / ``__enter__`` bodies (Unknown > false PASS).
                enter_products, enter_unknown = _follow_local_class_protocol_methods(
                    item.context_expr,
                    method_names=(
                        ("__aenter__",)
                        if is_async_with
                        else ("__enter__",)
                    ),
                    control_dependent=control_dependent,
                    execute_async_body=is_async_with,
                )
                if item.optional_vars is not None:
                    as_names = _collect_assign_target_names(item.optional_vars)
                    assigned.update(as_names)
                    bound_as.update(as_names)
                    # Attribute / subscript as-targets rebind exports
                    # (``with CM() as helpers.write_state``,
                    # ``with CM() as (helpers.write_state,)``).
                    if identity_session is not None and _assign_target_has_attr_or_subscript(
                        item.optional_vars
                    ):
                        identity_session.observe_statement(
                            ast.Assign(
                                targets=[item.optional_vars],
                                value=item.context_expr,
                            )
                        )
                    # ``with nullcontext(request.state) as x`` / bare state CM:
                    # ``__enter__`` may return the governed identity — bind may
                    # before the body so client writes through ``x`` are counted.
                    enter_flow = _uncertain_alias_flow_in_expr(
                        request_aliases, item.context_expr
                    )
                    direct = request_aliases.classify(item.context_expr)
                    if enter_flow.any_alias:
                        classification = enter_flow
                    elif direct.any_alias:
                        classification = direct.as_may_only()
                    else:
                        classification = AliasClassification()
                    # Instance / class-constructor / pack carriers from
                    # ``__enter__`` return / context expr
                    # (``with CM() as M: M()`` / ``with CM() as ks: C, = ks``).
                    enter_cls = _enter_return_instance_class(
                        item.context_expr, async_enter=is_async_with
                    )
                    enter_ctor = None
                    enter_return: ast.AST | None = None
                    if (
                        isinstance(item.context_expr, ast.Call)
                        and isinstance(item.context_expr.func, ast.Name)
                    ):
                        cm_cls = _lookup_local_class(item.context_expr.func.id)
                        if cm_cls is not None:
                            method_name = (
                                "__aenter__" if is_async_with else "__enter__"
                            )
                            method = _governed_class_method(cm_cls, method_name)
                            if method is not None:
                                for stmt in method.body:
                                    if (
                                        isinstance(stmt, ast.Return)
                                        and stmt.value is not None
                                    ):
                                        enter_return = stmt.value
                                        enter_ctor = (
                                            _resolve_class_constructor_alias(
                                                stmt.value
                                            )
                                        )
                                        break
                    # Prefer ``__enter__`` return as the as-target seed so
                    # ``return {Mut:1}.keys()`` / dict packs share Assign peel.
                    # Also seed bare view carriers:
                    # ``with ({Mut:1}.keys()) as ks: C, = ks``.
                    # ``nullcontext(n.install)`` — enter returns the argument
                    # (shared peel with identity scanner; Unknown > false PASS).
                    # Pass sequence_literal_aliases so Name star packs
                    # ``with nullcontext(*args) as f`` share Assign/``__enter__()``
                    # peels (Unknown > false PASS).
                    nc_enter = _nullcontext_enter_arg(
                        item.context_expr,
                        nullcontext_aliases=frozenset(
                            request_aliases.nullcontext_aliases
                        ),
                        sequence_aliases=request_aliases.sequence_literal_aliases,
                    )
                    if nc_enter is not None:
                        from ovk.compilers.authorization.python_callee_resolution import (
                            _iter_boolop_ifexp_arms as _nc_arms,
                        )

                        # Prefer Attribute/Call BoolOp/IfExp arm for as-target
                        # seed (``nullcontext((0 or n.install))``).
                        arms = _nc_arms(nc_enter)
                        preferred = None
                        for arm in arms:
                            peeled_arm = arm
                            while isinstance(peeled_arm, ast.NamedExpr):
                                peeled_arm = peeled_arm.value
                            if isinstance(
                                peeled_arm, (ast.Attribute, ast.Call, ast.Name)
                            ):
                                preferred = arm
                                break
                        if preferred is not None:
                            nc_enter = preferred
                        elif arms:
                            nc_enter = arms[0]
                    seed_value = (
                        enter_return
                        if enter_return is not None
                        else nc_enter
                        if nc_enter is not None
                        else item.context_expr
                    )
                    seeded_enter_identity = False

                    def _context_is_dict_view(expr: ast.AST) -> bool:
                        """``d.keys()`` / ``k()`` / ``fk([Mut])`` when Name-bound.

                        Shared with identity session seeding so ``with`` as-targets
                        observe class keys from keys/values/items/fromkeys views
                        (Unknown > false PASS).
                        """

                        peeled = expr
                        while isinstance(peeled, ast.NamedExpr):
                            peeled = peeled.value
                        if not isinstance(peeled, ast.Call):
                            return False
                        func = peeled.func
                        while isinstance(func, ast.NamedExpr):
                            func = func.value
                        while (
                            isinstance(func, ast.Attribute) and func.attr == "__call__"
                        ):
                            func = func.value
                            while isinstance(func, ast.NamedExpr):
                                func = func.value
                        _VIEW_CTX = {"keys", "values", "items", "fromkeys"}
                        if isinstance(func, ast.Attribute) and func.attr in _VIEW_CTX:
                            return True
                        # Name-bound: ``k = d.keys; with k() as ks`` /
                        # ``fk = dict.fromkeys; with fk([Mut]) as ks``.
                        if isinstance(func, ast.Name):
                            view = request_aliases.dict_view_products.get(func.id)
                            if view is not None and view.split(".")[-1] in _VIEW_CTX:
                                return True
                        return False

                    if identity_session is not None and (
                        enter_return is not None
                        or nc_enter is not None
                        or _context_is_dict_view(item.context_expr)
                    ):
                        identity_session.observe_statement(
                            ast.Assign(
                                targets=[item.optional_vars],
                                value=seed_value,
                            )
                        )
                        seeded_enter_identity = True
                    elif identity_session is not None and nc_enter is None:
                        # Deferred Name-bound cm packing peels:
                        # ``with (0 or cm) as f`` / ``with [cm][0] as f`` —
                        # synthesize ``f = ctx.__enter__()`` so Assign-enter
                        # shares the bare ``cm.__enter__()`` seed path
                        # (Unknown > false PASS).
                        from ovk.compilers.authorization.python_callee_resolution import (
                            _iter_boolop_ifexp_arms as _with_arms,
                            _peel_call_func as _with_peel,
                            _shallow_packed_callee_exprs as _with_shallow,
                        )

                        deferred_cm_name = False
                        for _arm in _with_shallow(item.context_expr):
                            for _seed in _with_arms(_arm):
                                if isinstance(_with_peel(_seed), ast.Name):
                                    deferred_cm_name = True
                                    break
                            if deferred_cm_name:
                                break
                        if deferred_cm_name:
                            identity_session.observe_statement(
                                ast.Assign(
                                    targets=[item.optional_vars],
                                    value=ast.Call(
                                        func=ast.Attribute(
                                            value=item.context_expr,
                                            attr="__enter__",
                                            ctx=ast.Load(),
                                        ),
                                        args=[],
                                        keywords=[],
                                    ),
                                )
                            )
                            seeded_enter_identity = True
                    if enter_cls is not None or enter_ctor is not None:
                        for name in as_names:
                            if enter_ctor is not None:
                                # Shared seed notifies identity session so
                                # ``with CM() as M: M()`` observes ``__init__``.
                                # Skip session when Assign(enter_return) already
                                # installed packs (``ks = {Mut:1}.keys()``).
                                if enter_return is not None:
                                    _seed_name_instance_or_class(
                                        name,
                                        enter_return,
                                        observe_session=not seeded_enter_identity,
                                    )
                                else:
                                    local_classes[name] = enter_ctor
                                    instance_class_of.pop(name, None)
                            elif enter_cls is not None:
                                instance_class_of[name] = enter_cls
                    else:
                        _seed_assign_target_instance_bindings(
                            item.optional_vars,
                            seed_value,
                            observe_session=not seeded_enter_identity,
                        )
                    for name in as_names:
                        request_aliases.apply_classification(name, classification)
                        if not classification.any_alias:
                            alias_state.poison(name)
                        # Opaque with-as projection for callable identity —
                        # skip when ``__enter__`` return was already observed
                        # (pack/class seeds must not be wiped).
                        if identity_session is not None and not seeded_enter_identity:
                            identity_session.bind_name_unknown(name)
                        # ``with CM() as fn``: bind ``__enter__`` return products
                        # so later ``fn()`` follows the governed closure.
                        if enter_products or enter_unknown:
                            _install_returned_closures(
                                name,
                                enter_products,
                                unknown=enter_unknown,
                            )
            if (
                identity_session is not None
                and bound_as
                and _with_as_body_mutates_names(statement.body, bound_as)
            ):
                identity_session.mark_unsupported()
            for child in statement.body:
                _visit_statement(
                    child,
                    control_dependent=control_dependent,
                )
            for name in assigned:
                alias_state.poison(name)
            request_aliases.poison_names(assigned)
            # Do not re-scan the whole With via observe_statement: context_expr
            # was observed before the body, and body statements are observed
            # individually (avoids post-body identity reordering (#173)).
            return

        if isinstance(statement, ast.Try):
            pre_identity = (
                identity_session.fork() if identity_session is not None else None
            )
            pre_aliases = request_aliases.snapshot()
            pre_alias_state = alias_state.snapshot()
            pre_callable = _snapshot_callable_env()
            for child in statement.body:
                _visit_statement(child, control_dependent=True)
            body_identity = (
                identity_session.snapshot() if identity_session is not None else None
            )
            body_aliases = request_aliases.snapshot()
            body_alias_state = alias_state.snapshot()
            body_callable = _snapshot_callable_env()
            handler_identities: list[RequestTimeIdentityState] = []
            handler_aliases: list[_RequestStateAliasEnv] = []
            handler_alias_states: list[AliasState] = []
            handler_callables: list[_CallableEnv] = []
            for handler in statement.handlers:
                request_aliases.restore(pre_aliases)
                alias_state.restore(pre_alias_state)
                _restore_callable_env(pre_callable)
                if identity_session is not None and pre_identity is not None:
                    identity_session.restore(pre_identity)
                # except TYPE executes when matching is considered (#173).
                if handler.type is not None:
                    _observe_executed_expression(
                        handler.type, control_dependent=True
                    )
                if handler.name:
                    request_aliases.poison_names({handler.name})
                    alias_state.poison(handler.name)
                for child in handler.body:
                    _visit_statement(child, control_dependent=True)
                if identity_session is not None:
                    handler_identities.append(identity_session.snapshot())
                handler_aliases.append(request_aliases.snapshot())
                handler_alias_states.append(alias_state.snapshot())
                handler_callables.append(_snapshot_callable_env())
            request_aliases.restore(body_aliases)
            alias_state.restore(body_alias_state)
            _restore_callable_env(body_callable)
            if identity_session is not None and body_identity is not None:
                identity_session.restore(body_identity)
            for child in statement.orelse:
                _visit_statement(child, control_dependent=True)
            normal_aliases = request_aliases.snapshot()
            normal_alias_state = alias_state.snapshot()
            normal_callable = _snapshot_callable_env()
            if identity_session is not None:
                normal_identity = identity_session.snapshot()
                # Join normal + exceptional, then run finally on that state.
                # With no handlers, exceptional exit still reaches finally —
                # include the pre-try predecessor so finally alias / identity
                # writes are not dropped (#173).
                if statement.handlers:
                    predecessors = [normal_identity, *handler_identities]
                else:
                    predecessors = [normal_identity]
                    if pre_identity is not None:
                        predecessors.append(pre_identity)
                identity_session.join(predecessors)
            if statement.handlers:
                request_aliases.install_join([normal_aliases, *handler_aliases])
                alias_state.install_join([normal_alias_state, *handler_alias_states])
                _join_callable_envs([normal_callable, *handler_callables])
            else:
                request_aliases.install_join([normal_aliases, pre_aliases])
                alias_state.install_join([normal_alias_state, pre_alias_state])
                _join_callable_envs([normal_callable, pre_callable])
            for child in statement.finalbody:
                _visit_statement(child, control_dependent=True)
            return

        if isinstance(statement, ast.Match):
            # Subject executes once before case selection (#173).
            _observe_executed_expression(
                statement.subject, control_dependent=control_dependent
            )
            pre_identity = (
                identity_session.fork() if identity_session is not None else None
            )
            pre_aliases = request_aliases.snapshot()
            pre_alias_state = alias_state.snapshot()
            pre_callable = _snapshot_callable_env()
            case_identities: list[RequestTimeIdentityState] = []
            case_aliases: list[_RequestStateAliasEnv] = []
            case_alias_states: list[AliasState] = []
            case_callables: list[_CallableEnv] = []
            for case in statement.cases:
                request_aliases.restore(pre_aliases)
                alias_state.restore(pre_alias_state)
                _restore_callable_env(pre_callable)
                if identity_session is not None and pre_identity is not None:
                    identity_session.restore(pre_identity)
                # MatchClass ``__instancecheck__`` / ``__match_args__`` side
                # effects against local / dynamic match protocols: fail closed
                # rather than authorize (#173). Builtin type names stay peelable.
                if isinstance(case.pattern, ast.MatchClass):
                    cls_expr = case.pattern.cls
                    if not isinstance(cls_expr, ast.Name) or cls_expr.id not in {
                        "bool",
                        "int",
                        "str",
                        "list",
                        "dict",
                        "tuple",
                        "set",
                        "bytes",
                        "type",
                        "object",
                        "float",
                        "complex",
                        "range",
                        "enumerate",
                    }:
                        if identity_session is not None:
                            identity_session.mark_unsupported()
                # Bind pattern names from the subject (as-capture / peels);
                # never silently poison subject-capturing aliases.
                _apply_match_pattern_alias_bindings(
                    request_aliases, case.pattern, statement.subject
                )
                # Subject-capturing MatchAs must also carry callable products
                # (``match mid(): case fn: fn()``) — alias peel alone omits
                # the writer theorem (Unknown > false PASS).
                _apply_match_pattern_callable_bindings(
                    case.pattern, statement.subject
                )
                for name in _match_pattern_bound_names(case.pattern):
                    # Value-origin alias state has no request/state lattice;
                    # sever precise origins for rebound names.
                    alias_state.poison(name)
                    # Identity env: match-bound names may be class aliases
                    # (``match Base: case x: class C(x)``) — fail closed on
                    # unresolved bases via env membership (#173).
                    # Subject-capturing ``case x`` keeps subject identity for
                    # ``match n: case x: x.install(…)`` (do not unknown-wipe).
                    if identity_session is not None and not (
                        isinstance(case.pattern, ast.MatchAs)
                        and case.pattern.name == name
                        and case.pattern.pattern is None
                    ):
                        identity_session.bind_name_unknown(name)
                # Class / instance aliases through MatchAs and seq/map/or peels
                # (``match [Box()]: case [b]: b.fn()`` / ``match (Mut,): case (C,):``).
                _apply_match_pattern_instance_class_bindings(
                    case.pattern, statement.subject
                )
                # Identity session is statement-CF (not whole-Match observe):
                # seed protocol/container packs via synthetic Assigns so
                # ``case (*xs,): xs[0](…)`` / ``case {"e": e}: e(…)`` /
                # ``case {**rest}: rest["c"]()`` cannot false-PASS.
                if identity_session is not None:
                    _seed_match_identity_binds(
                        identity_session, case.pattern, statement.subject
                    )
                # MatchValue Attribute: fail-closed export rebind
                # (``match (evil,): case (helpers.write_state,):``).
                for attr_target in _match_pattern_attribute_targets(case.pattern):
                    if identity_session is not None:
                        identity_session.observe_statement(
                            ast.Assign(
                                targets=[attr_target],
                                value=statement.subject,
                            )
                        )
                if case.guard is not None:
                    # Guard effects are path-dependent: possible on paths that
                    # reach this guard; never omit; keep control_dependent so
                    # they are not over-promoted to unconditional authority (#173).
                    _observe_executed_expression(
                        case.guard, control_dependent=True
                    )
                # Starred / rest binders yield containers, not field bases —
                # escape when the subject still flows governed identity.
                if _match_pattern_has_star(case.pattern):
                    star_flow = _uncertain_alias_flow_in_expr(
                        request_aliases, statement.subject
                    )
                    if star_flow.any_alias or request_aliases.packs_request_or_state_identity(
                        statement.subject
                    ):
                        _record_escape(
                            statement,
                            ast.unparse(statement),
                            control_dependent=True,
                        )
                for child in case.body:
                    _visit_statement(child, control_dependent=True)
                if identity_session is not None:
                    case_identities.append(identity_session.snapshot())
                case_aliases.append(request_aliases.snapshot())
                case_alias_states.append(alias_state.snapshot())
                case_callables.append(_snapshot_callable_env())
            alias_predecessors = list(case_aliases)
            alias_state_predecessors = list(case_alias_states)
            callable_predecessors = list(case_callables)
            identity_predecessors: list[RequestTimeIdentityState] = list(
                case_identities
            )
            if not _match_statement_exhaustive(statement):
                alias_predecessors.append(pre_aliases)
                alias_state_predecessors.append(pre_alias_state)
                callable_predecessors.append(pre_callable)
                if pre_identity is not None:
                    identity_predecessors.append(pre_identity)
            if identity_session is not None and pre_identity is not None:
                if identity_predecessors:
                    identity_session.join(identity_predecessors)
                else:
                    identity_session.restore(pre_identity)
            if alias_predecessors:
                request_aliases.install_join(alias_predecessors)
                alias_state.install_join(alias_state_predecessors)
                _join_callable_envs(callable_predecessors)
            else:
                request_aliases.restore(pre_aliases)
                alias_state.restore(pre_alias_state)
                _restore_callable_env(pre_callable)
            return

        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Definition-time execution only: defaults, annotations, type
            # params, decorators. Nested *bodies* execute at call time under
            # the bounded lexical-environment theorem (Unknown > false PASS).
            for default in statement.args.defaults:
                _observe_executed_expression(
                    default, control_dependent=control_dependent
                )
            for default in statement.args.kw_defaults:
                if default is not None:
                    _observe_executed_expression(
                        default, control_dependent=control_dependent
                    )
            # Capture defaults under the definition-time env before registering.
            _register_nested_callable(statement, name=statement.name)
            for param in getattr(statement, "type_params", ()) or ():
                bound = getattr(param, "bound", None)
                if bound is not None:
                    _observe_executed_expression(
                        bound, control_dependent=control_dependent
                    )
                default_value = getattr(param, "default_value", None)
                if default_value is not None:
                    _observe_executed_expression(
                        default_value, control_dependent=control_dependent
                    )
            for arg in (
                *statement.args.posonlyargs,
                *statement.args.args,
                *statement.args.kwonlyargs,
            ):
                if arg.annotation is not None:
                    _observe_executed_expression(
                        arg.annotation, control_dependent=control_dependent
                    )
            if (
                statement.args.vararg is not None
                and statement.args.vararg.annotation is not None
            ):
                _observe_executed_expression(
                    statement.args.vararg.annotation,
                    control_dependent=control_dependent,
                )
            if (
                statement.args.kwarg is not None
                and statement.args.kwarg.annotation is not None
            ):
                _observe_executed_expression(
                    statement.args.kwarg.annotation,
                    control_dependent=control_dependent,
                )
            if statement.returns is not None:
                _observe_executed_expression(
                    statement.returns, control_dependent=control_dependent
                )
            # Decorators apply bottom-up; outermost is decorator_list[0].
            # ``@deco`` / ``@deco(...)`` may replace the Name with a returned
            # poison closure — install that product or fail closed (#173).
            outermost_deco_call: ast.Call | None = None
            for deco in statement.decorator_list:
                if isinstance(deco, ast.Call):
                    deco_call = deco
                else:
                    deco_call = ast.Call(
                        func=deco,
                        args=[ast.Name(id=statement.name, ctx=ast.Load())],
                        keywords=[],
                    )
                if outermost_deco_call is None:
                    outermost_deco_call = deco_call
                _observe_executed_expression(
                    deco_call, control_dependent=control_dependent
                )
            if outermost_deco_call is not None:
                returned, unknown = _ensure_call_callable_products(outermost_deco_call)
                if not returned and id(outermost_deco_call) in call_returned_closures:
                    returned = list(call_returned_closures[id(outermost_deco_call)])
                if not unknown and id(outermost_deco_call) in call_returned_unknown:
                    unknown = True
                if returned or unknown:
                    _install_returned_closures(
                        statement.name, returned, unknown=unknown
                    )
                else:
                    # Opaque decorator rebind — later ``fn()`` must not follow
                    # the original nested body as if undecorated.
                    name_unknown_callables.add(statement.name)
                    local_nested.pop(statement.name, None)
                    local_lambdas.pop(statement.name, None)
            if identity_session is not None:
                identity_session.observe_statement(statement)
            return

        if isinstance(statement, ast.ClassDef):
            # Local metaclass / dynamic bases: fail closed on class creation
            # protocols when identity observation cannot fully simulate them.
            if any(kw.arg == "metaclass" for kw in statement.keywords):
                if identity_session is not None:
                    identity_session.mark_unsupported()
            # Header executes at definition: bases, keywords, decorators (#173).
            for deco in statement.decorator_list:
                if isinstance(deco, ast.Call):
                    _observe_executed_expression(
                        deco, control_dependent=control_dependent
                    )
                else:
                    _observe_executed_expression(
                        ast.Call(
                            func=deco,
                            args=[ast.Name(id=statement.name, ctx=ast.Load())],
                            keywords=[],
                        ),
                        control_dependent=control_dependent,
                    )
            for param in getattr(statement, "type_params", ()) or ():
                bound = getattr(param, "bound", None)
                if bound is not None:
                    _observe_executed_expression(
                        bound, control_dependent=control_dependent
                    )
                default_value = getattr(param, "default_value", None)
                if default_value is not None:
                    _observe_executed_expression(
                        default_value, control_dependent=control_dependent
                    )
            for base in statement.bases:
                _observe_executed_expression(
                    base, control_dependent=control_dependent
                )
            for kw in statement.keywords:
                _observe_executed_expression(
                    kw.value, control_dependent=control_dependent
                )
            # Class body executes at definition: Assign/AnnAssign/Expr/nested
            # defs must observe writer + identity effects (Unknown > false PASS).
            for child in statement.body:
                _visit_statement(child, control_dependent=control_dependent)
            local_classes[statement.name] = statement
            if identity_session is not None:
                identity_session.observe_statement(statement)
            return

        type_alias_cls = getattr(ast, "TypeAlias", None)
        if type_alias_cls is not None and isinstance(statement, type_alias_cls):
            # ``type X = expr`` evaluates type_params and value at runtime.
            for param in getattr(statement, "type_params", ()) or ():
                bound = getattr(param, "bound", None)
                if bound is not None:
                    _observe_executed_expression(
                        bound, control_dependent=control_dependent
                    )
                default_value = getattr(param, "default_value", None)
                if default_value is not None:
                    _observe_executed_expression(
                        default_value, control_dependent=control_dependent
                    )
            _observe_executed_expression(
                statement.value, control_dependent=control_dependent
            )
            if identity_session is not None:
                identity_session.observe_statement(statement)
            return

        if isinstance(statement, ast.Assert):
            # Assert.test / Assert.msg execute (incl. walrus callable products).
            _observe_executed_expression(
                statement.test, control_dependent=control_dependent
            )
            if statement.msg is not None:
                _observe_executed_expression(
                    statement.msg, control_dependent=control_dependent
                )
            return

        if isinstance(statement, ast.Raise):
            # Raise.exc / Raise.cause execute (incl. walrus callable products).
            if statement.exc is not None:
                _observe_executed_expression(
                    statement.exc, control_dependent=control_dependent
                )
            if statement.cause is not None:
                _observe_executed_expression(
                    statement.cause, control_dependent=control_dependent
                )
            if identity_session is not None:
                identity_session.observe_statement(statement)
            return

        if isinstance(statement, ast.Return) and statement.value is not None:
            # Returning request.state escapes state identity into an unresolved
            # caller theorem → UNKNOWN. Bare ``return request`` is not itself a
            # state mutation channel under this bounded escape relation.
            if identity_session is not None:
                identity_session.observe_statement(statement)
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
            # Nested frames: propagate returned closures to the call site for
            # precise ``fn = mid(); fn()`` follow — including nested factories
            # (``return mid``) whose free-var set is empty but whose body can
            # still yield governed closures. Entry frame: residual escape to
            # the unresolved FastAPI caller (Unknown > false PASS).
            # IfExp/BoolOp returns dual-may join known arms; unknown arms set
            # ``frame_returned_unknown`` so callers fail closed on later call.
            _note_named_expr_bindings(
                statement.value, control_dependent=control_dependent
            )
            _record_dynamic_calls(
                statement,
                control_dependent=control_dependent,
            )
            returned_here, returned_unknown = _callable_products_from_expr(
                statement.value
            )
            if isinstance(statement.value, ast.Call):
                for item in call_returned_closures.get(id(statement.value), []):
                    if id(item.node) not in {id(c.node) for c in returned_here}:
                        returned_here.append(item)
                if id(statement.value) in call_returned_unknown:
                    returned_unknown = True
            if returned_unknown:
                frame_returned_unknown = True
            for closure in returned_here:
                if is_entry_frame:
                    if _closure_is_residual_escape(closure) or returned_unknown:
                        _record_escape(
                            statement,
                            ast.unparse(statement),
                            control_dependent=control_dependent,
                        )
                else:
                    # Always propagate nested-frame callable products so
                    # ``mid_fn = outer(); fn = mid_fn(); fn()`` stays precise.
                    frame_returned_closures.append(closure)
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
            # ``[x.fn() for x in [Box()]]`` — bind for-target instance before
            # Call peel of the element expression (Unknown > false PASS).
            for child in ast.walk(statement.value):
                if not isinstance(
                    child,
                    (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp),
                ):
                    continue
                for gen in child.generators:
                    _seed_assign_target_instance_bindings(gen.target, gen.iter)
            # Shared PE observer: ``operator.setitem(keys,…)`` /
            # ``keys.__setitem__/update/pop`` as Expr statements rewrite
            # Name-bound key carriers (Unknown > false PASS).
            _observe_executed_expression(
                statement.value, control_dependent=control_dependent
            )

        # Identity before write inlining (same-statement arg-order mutators).
        if identity_session is not None:
            identity_session.observe_statement(statement)
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
    return writes, frame_returned_closures, frame_returned_unknown


def _module_projection_export_map(
    trees: Mapping[str, ast.AST],
    *,
    import_roots: tuple[str, ...] = (),
) -> dict[str, dict[str, str]]:
    """Per-module export → canonical adapter/operator projection name.

    Seeds cross-module ``from helpers import Proxy`` after
    ``Proxy = MappingProxyType`` (Unknown > false PASS).
    """

    available = set(trees)
    # path -> local name -> canonical ("MappingProxyType" | operator proj)
    exports: dict[str, dict[str, str]] = {path: {} for path in trees}

    def _seed_local(path: str, tree: ast.AST) -> None:
        env = _RequestStateAliasEnv.seed(param_names=frozenset())
        for node in getattr(tree, "body", ()):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                env.note_projection_import(node)
                # Direct re-exports: ``from types import MappingProxyType as Proxy``.
                if isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        local = alias.asname or alias.name
                        if alias.name == "MappingProxyType":
                            exports[path][local] = "MappingProxyType"
                        elif alias.name in _OPERATOR_PROJECTION_NAMES:
                            exports[path][local] = alias.name
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        env.note_projection_name_alias(target.id, node.value)
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.value is not None:
                    env.note_projection_name_alias(node.target.id, node.value)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.NamedExpr):
                if isinstance(node.value.target, ast.Name):
                    env.note_projection_name_alias(
                        node.value.target.id, node.value.value
                    )
        for name in env.adapter_aliases:
            exports[path][name] = "MappingProxyType"
        for name, canon in env.operator_projection_aliases.items():
            exports[path][name] = canon

    for path, tree in trees.items():
        _seed_local(path, tree)

    # One fixed-point pass for ``from helpers import Proxy`` re-exports.
    for path, tree in trees.items():
        for node in getattr(tree, "body", ()):
            if not isinstance(node, ast.ImportFrom):
                continue
            module_name = import_module_name_from_importer(node, importer_path=path)
            if module_name is None:
                continue
            target = _module_path_in_unit(
                module_name,
                available_paths=available,
                import_roots=import_roots,
            )
            if target is None:
                continue
            foreign = exports.get(target, {})
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                canon = foreign.get(alias.name)
                if canon is not None:
                    exports[path][local] = canon
    return exports


def _collect_state_writes(
    tree: ast.AST,
    *,
    path: str,
    externally_bound_function_name: str | None,
    callee_resolver: CalleeResolver | None = None,
    trees: Mapping[str, ast.AST] | None = None,
    import_roots: tuple[str, ...] = (),
    projection_exports: Mapping[str, Mapping[str, str]] | None = None,
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
        # Module-level ``from types import MappingProxyType as MPT`` /
        # ``from operator import itemgetter as ig`` / AnnAssign / walrus seed.
        module_projection_seed = _RequestStateAliasEnv.seed(param_names=frozenset())
        available = set(trees) if trees is not None else set()
        export_map = projection_exports or {}
        for node in getattr(tree, "body", ()):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module_projection_seed.note_projection_import(node)
                # Cross-module adapter/operator re-exports.
                if isinstance(node, ast.ImportFrom) and trees is not None:
                    module_name = import_module_name_from_importer(
                        node, importer_path=path
                    )
                    target = (
                        _module_path_in_unit(
                            module_name,
                            available_paths=available,
                            import_roots=import_roots,
                        )
                        if module_name is not None
                        else None
                    )
                    foreign = export_map.get(target or "", {})
                    for alias in node.names:
                        if alias.name == "*":
                            continue
                        local = alias.asname or alias.name
                        canon = foreign.get(alias.name)
                        if canon == "MappingProxyType":
                            module_projection_seed.adapter_aliases.add(local)
                        elif canon in _OPERATOR_PROJECTION_NAMES:
                            module_projection_seed.operator_projection_aliases[
                                local
                            ] = canon
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        module_projection_seed.note_projection_name_alias(
                            target.id, node.value
                        )
            elif isinstance(node, ast.AnnAssign):
                if (
                    isinstance(node.target, ast.Name)
                    and node.value is not None
                ):
                    module_projection_seed.note_projection_name_alias(
                        node.target.id, node.value
                    )
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.NamedExpr):
                if isinstance(node.value.target, ast.Name):
                    module_projection_seed.note_projection_name_alias(
                        node.value.target.id, node.value.value
                    )
        for fn in functions:
            fn_param_names = frozenset(_function_param_names(fn))
            seeded = _RequestStateAliasEnv.seed(param_names=fn_param_names)
            seeded.adapter_aliases |= module_projection_seed.adapter_aliases
            seeded.operator_projection_aliases.update(
                module_projection_seed.operator_projection_aliases
            )
            # Also seed imports nested in the function body.
            for node in ast.walk(fn):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    seeded.note_projection_import(node)
            collected, _returned, _returned_unknown = _collect_writes_in_function(
                fn,
                path=path,
                handler_param_names=(
                    fn_param_names
                    if fn.name == externally_bound_function_name
                    else frozenset()
                ),
                callee_resolver=callee_resolver,
                seed_request_aliases=seeded,
            )
            writes.extend(collected)
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
    *,
    import_roots: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Shared import-space theorem (#161); kept as a thin alias for tests."""

    return module_candidates_in_manifest(
        module,
        available_paths,
        import_roots=import_roots,
    )


def _top_level_appears_local(top: str, available_paths: set[str]) -> bool:
    return top_level_appears_local(top, available_paths)


def _module_path_in_unit(
    module: str,
    *,
    available_paths: set[str],
    source_roots: tuple[str, ...] | None = None,
    import_roots: tuple[str, ...] | None = None,
) -> str | None:
    """Resolve an absolute module name under the shared import-root theorem."""

    del source_roots  # path-accounting roots are not import identity
    candidates = module_candidates_in_manifest(
        module,
        available_paths,
        import_roots=import_roots or (),
    )
    return candidates[0] if len(candidates) == 1 else None


def _import_module_name_from_importer(
    node: ast.ImportFrom,
    *,
    importer_path: str,
) -> str | None:
    """Resolve ImportFrom to an absolute module name from the importer path."""

    return import_module_name_from_importer(node, importer_path=importer_path)


def _import_module_name(
    node: ast.ImportFrom,
    *,
    importer_path: str,
    source_roots: tuple[str, ...] | None = None,
) -> str | None:
    """Resolve ImportFrom to an import-space module name."""

    del source_roots
    return import_module_name_from_importer(node, importer_path=importer_path)


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
            python_import_roots=(),
        )

    proof_paths = {
        _normalize_unit_path(path)
        for path in scope_proof.accounted_paths
    }
    source_roots = tuple(
        sorted({_normalize_source_root(root) for root in scope_proof.source_roots})
    )
    import_roots = normalize_import_roots(scope_proof.python_import_roots)
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
            python_import_roots=import_roots,
        )

    unresolvable: list[str] = []

    for path, source in sorted(files.items()):
        norm = _normalize_unit_path(path)
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            unresolvable.append(f"{norm}:syntax_error")
            continue
        # Nested Import/ImportFrom inside handlers affect closed-world
        # completeness the same as module-level imports (Unknown > false PASS).
        for node in ast.walk(tree):
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
                candidates = module_candidates_in_manifest(
                    module_name,
                    available,
                    import_roots=import_roots,
                )
                if len(candidates) == 0:
                    # Relative imports are always repository-local. Absolute
                    # imports whose top-level name already appears under the
                    # manifest are also local misses — never external.
                    relative = bool(node.level and node.level > 0)
                    top = module_name.split(".", 1)[0]
                    if relative or top_level_appears_local(top, available):
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
                    candidates = module_candidates_in_manifest(
                        alias.name,
                        available,
                        import_roots=import_roots,
                    )
                    if len(candidates) == 0:
                        top = alias.name.split(".", 1)[0]
                        if top_level_appears_local(top, available):
                            unresolvable.append(
                                f"{norm}:unresolvable_local_import:{alias.name}"
                            )
                        continue
                    if len(candidates) > 1:
                        unresolvable.append(
                            f"{norm}:ambiguous_local_import:{alias.name}"
                        )
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in {
                    "__import__",
                    "import_module",
                }:
                    unresolvable.append(f"{norm}:dynamic_import")
                elif isinstance(func, ast.Attribute) and func.attr == "import_module":
                    unresolvable.append(f"{norm}:dynamic_import")

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
        python_import_roots=import_roots,
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
    import_roots = (
        normalize_import_roots(scope_proof.python_import_roots)
        if scope_proof is not None
        else ()
    )
    callee_resolver = build_callee_resolver(trees, import_roots=import_roots)

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
    projection_exports = _module_projection_export_map(
        trees, import_roots=import_roots
    )
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
                trees=trees,
                import_roots=import_roots,
                projection_exports=projection_exports,
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
                        "python_import_roots": list(
                            item.closed_world.python_import_roots
                        ),
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
