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


_BYPASS_AUTHORITY_EXTRACTOR_VERSION = "0.32.0"
_MAX_INTERPROCEDURAL_WRITER_DEPTH = 4
_STATE_DICT_ATTRS = frozenset({"__dict__", "__slots__"})

# Container view / adapter surfaces that project packed request/state identity
# without a Name-alias bind (Unknown > false PASS on omitted client writes).
_CONTAINER_VIEW_ATTRS = frozenset({"values", "keys", "items"})
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
    }
)

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

    def snapshot(self) -> "_RequestStateAliasEnv":
        """Deep-copy alias sets for control-flow fork."""

        return _RequestStateAliasEnv(
            request_names=set(self.request_names),
            state_names=set(self.state_names),
            may_request_names=set(self.may_request_names),
            may_state_names=set(self.may_state_names),
        )

    def restore(self, other: "_RequestStateAliasEnv") -> None:
        """Replace live alias sets with a previously snapshotted predecessor."""

        self.request_names = set(other.request_names)
        self.state_names = set(other.state_names)
        self.may_request_names = set(other.may_request_names)
        self.may_state_names = set(other.may_state_names)

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
        if isinstance(value, ast.Call):
            # Dict/set view projections: ``{\"k\": request.state}.values()``.
            if (
                isinstance(value.func, ast.Attribute)
                and value.func.attr in _CONTAINER_VIEW_ATTRS
            ):
                recv = value.func.value
                if self.is_request_or_state_expr(
                    recv
                ) or self.packs_request_or_state_identity(recv):
                    return True
            # Builtin adapters: ``list({request.state})``, ``next(iter(...))``.
            func_name: str | None = None
            if isinstance(value.func, ast.Name):
                func_name = value.func.id
            if func_name in _CONTAINER_ADAPTER_NAMES:
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
    return _RequestStateAliasEnv(
        request_names=must_request,
        state_names=must_state,
        may_request_names=may_request,
        may_state_names=may_state,
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
        function frame (Unknown > false PASS).
        """

        returned = list(call_returned_closures.get(id(call), []))
        unknown = id(call) in call_returned_unknown
        if returned or unknown:
            return returned, unknown
        if isinstance(call.func, ast.Name):
            cls = _lookup_local_class(call.func.id)
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
            if isinstance(pat, ast.MatchOr):
                for alt in pat.patterns:
                    _apply(alt, value)

        _apply(pattern, matched)

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
            _register_nested_callable(value, name=target.id)
            return
        if isinstance(value, (ast.IfExp, ast.BoolOp, ast.NamedExpr)):
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
                _install_returned_closures(
                    target.id, closures, unknown=unknown
                )
                return
        if isinstance(value, ast.Call):
            _clear_callable_name(target.id)
            if _bind_call_product_to_name(target.id, value):
                return
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

    def _getattr_local_callable(
        call_func: ast.AST,
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | None:
        """``getattr(obj, \"poison\")`` / ``getattr(fn, \"__call__\")`` → local callable."""

        if not isinstance(call_func, ast.Call):
            return None
        if not isinstance(call_func.func, ast.Name) or call_func.func.id != "getattr":
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
        return _local_callable_for_name(attr_name)

    def _local_class_method_for_attr(
        attr_expr: ast.Attribute,
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        """Resolve ``Cls.method`` / ``Cls().method`` against local classes."""

        cls: ast.ClassDef | None = None
        if isinstance(attr_expr.value, ast.Name):
            cls = _lookup_local_class(attr_expr.value.id)
        elif isinstance(attr_expr.value, ast.Call) and isinstance(
            attr_expr.value.func, ast.Name
        ):
            cls = _lookup_local_class(attr_expr.value.func.id)
        if cls is None:
            return None
        for child in cls.body:
            if (
                isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name == attr_expr.attr
            ):
                return child
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
                return _follow_local_callable_node(
                    class_method,
                    call=call,
                    control_dependent=control_dependent,
                    execute_async_body=execute_async_body,
                )
            callee = _local_callable_for_name(call.func.attr)
            if callee is not None and _closure_carries_governed_identity(callee):
                return _follow_local_callable_node(
                    callee,
                    call=call,
                    control_dependent=control_dependent,
                    execute_async_body=execute_async_body,
                )

        # ``getattr(box, \"poison\")()`` when the attribute name is constant.
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
                    attr_callee = _local_callable_for_name(node.func.attr)
                    attr_governed = (
                        attr_callee is not None
                        and _closure_carries_governed_identity(attr_callee)
                    )
            getattr_callee = _getattr_local_callable(node.func)
            getattr_governed = (
                getattr_callee is not None
                and _closure_carries_governed_identity(getattr_callee)
            )
            unknown_name_callable = (
                isinstance(node.func, ast.Name)
                and node.func.id in name_unknown_callables
            )
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

    def _note_alias_bindings(
        statement: ast.stmt, *, control_dependent: bool = False
    ) -> None:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                request_aliases.note_binding(target, statement.value)
                _note_callable_name_alias(
                    target, statement.value, control_dependent=control_dependent
                )
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
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
            # RHS executes: setattr / escape / callable-identity mutators.
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
                    for name in as_names:
                        request_aliases.apply_classification(name, classification)
                        if not classification.any_alias:
                            alias_state.poison(name)
                        # Opaque with-as projection for callable identity.
                        if identity_session is not None:
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
            collected, _returned, _returned_unknown = _collect_writes_in_function(
                fn,
                path=path,
                handler_param_names=(
                    fn_param_names
                    if fn.name == externally_bound_function_name
                    else frozenset()
                ),
                callee_resolver=callee_resolver,
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
