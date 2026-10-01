"""Caller-relative Python callee resolution (#160 / #161 / #163).

Replaces repository-global simple-name callee indexing with resolution that
honours the caller's module-level final bindings and authenticated-manifest
import identity under the shared import-root theorem (#161).

#163 adds bounded callable/module mutation closure: an imported module export
or source-grounded callable retains precise authorizing identity only when
both ModuleBindingIdentity and CallableBehaviorIdentity are established.
Mutation analysis is shared by bypass writer closure and interprocedural
argument provenance (no divergent systems).

Resolution for a bare call ``write_state(...)``:
1. local function binding in the caller module
2. explicit imported binding (followed through a unique manifest module)
3. otherwise unresolved → UNKNOWN when Request/state escapes

Never searches the repository for a same-leaf function merely because the
name matches. Import follow uses :func:`python_import_space.module_candidates_in_manifest`
— the same primitive as closed-world import accounting.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Literal

from ovk.compilers.authorization.python_import_space import (
    module_candidates_in_manifest,
    normalize_import_roots,
    normalize_path,
)

_IMPLEMENTATION_VERSION = "0.4.0"
_MAX_IMPORT_FOLLOW_DEPTH = 8

BindingKind = Literal["function", "import_name", "import_module", "rebound"]


@dataclass(frozen=True)
class ResolvedCallee:
    """A uniquely resolved module-level function identity."""

    path: str
    node: ast.FunctionDef | ast.AsyncFunctionDef

    @property
    def identity(self) -> tuple[str, str]:
        return (self.path, self.node.name)

    @property
    def qualified_name(self) -> str:
        return f"{self.path}:{self.node.name}"


@dataclass(frozen=True)
class FinalBinding:
    """Module-scope final binding for one local name.

    ``behavior_established`` is CallableBehaviorIdentity: false when a
    represented execution can mutate the callable object (``__code__``,
    attribute/subscript writes, etc.) while ModuleBindingIdentity remains.
    Authorizing resolution requires both identities.
    """

    kind: BindingKind
    function_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    # Absolute import module name for import_name / import_module.
    module_name: str | None = None
    # Imported attribute for ``from mod import attr`` (attr may differ from local).
    imported_name: str | None = None
    behavior_established: bool = True


@dataclass(frozen=True)
class CalleeResolveResult:
    """Outcome of resolving one call expression's callee."""

    callee: ResolvedCallee | None
    reason: str | None = None

    @property
    def resolved(self) -> bool:
        return self.callee is not None


@dataclass(frozen=True)
class _MutationEffects:
    """Collected module-export and callable-behavior mutation effects (#163)."""

    # Defining module path → export names whose ModuleBindingIdentity is lost.
    export_mutations: Mapping[str, frozenset[str]]
    # (defining_path, export_name) with CallableBehaviorIdentity lost.
    behavior_mutations: frozenset[tuple[str, str]]
    # Unsupported dynamic module surfaces (e.g. sys.modules) → full poison.
    unsupported_module_mutation: bool

def import_module_name_from_importer(
    node: ast.ImportFrom,
    *,
    importer_path: str,
) -> str | None:
    """Resolve ImportFrom to an absolute module name from the importer path."""

    if not node.level or node.level <= 0:
        return node.module

    importer = normalize_path(importer_path)
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


def _collect_store_names(target: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, ast.Starred):
        names.extend(_collect_store_names(target.value))
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_collect_store_names(elt))
    return names


def _collect_match_pattern_names(pattern: ast.AST) -> list[str]:
    """Names bound by a ``match`` pattern (module-scope adversary)."""

    names: list[str] = []
    if isinstance(pattern, ast.MatchAs):
        if pattern.name:
            names.append(pattern.name)
        if pattern.pattern is not None:
            names.extend(_collect_match_pattern_names(pattern.pattern))
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name:
            names.append(pattern.name)
    elif isinstance(pattern, ast.MatchMapping):
        if pattern.rest:
            names.append(pattern.rest)
        for item in pattern.patterns:
            names.extend(_collect_match_pattern_names(item))
    elif isinstance(pattern, (ast.MatchSequence, ast.MatchOr)):
        for item in pattern.patterns:
            names.extend(_collect_match_pattern_names(item))
    elif isinstance(pattern, ast.MatchClass):
        for item in pattern.patterns:
            names.extend(_collect_match_pattern_names(item))
        for item in pattern.kwd_patterns:
            names.extend(_collect_match_pattern_names(item))
    return names


def _mark_rebound(bindings: dict[str, FinalBinding], names: list[str] | set[str]) -> None:
    for name in names:
        if name == "*":
            continue
        bindings[name] = FinalBinding(kind="rebound")


def _is_globals_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"globals", "locals", "vars"}
        and not node.args
        and not node.keywords
    )


def _static_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_module_namespace_expr(node: ast.AST) -> bool:
    """True for module-level namespace objects we refuse to trust as identity."""

    if _is_globals_call(node):
        return True
    return isinstance(node, ast.Name) and node.id in {"__dict__", "globals", "locals", "vars"}


def _names_bound_by_statement(node: ast.AST) -> set[str]:
    """Names a module-level statement may bind, including nested suites.

    Used for conditional / compound control flow where the outcome is not
    statically established: any possible binding forces rebound.
    """

    names: set[str] = set()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names.add(node.name)
    elif isinstance(node, ast.ImportFrom):
        if any(alias.name == "*" for alias in node.names):
            names.add("*")
        else:
            for alias in node.names:
                names.add(alias.asname or alias.name)
    elif isinstance(node, ast.Import):
        for alias in node.names:
            if alias.asname:
                names.add(alias.asname)
            else:
                names.add(alias.name.split(".", 1)[0])
    elif isinstance(node, ast.Assign):
        for target in node.targets:
            names.update(_collect_store_names(target))
            if isinstance(target, ast.Subscript) and _is_module_namespace_expr(
                target.value
            ):
                key = _static_str(target.slice)
                if key is not None:
                    names.add(key)
                else:
                    names.add("*")
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        names.add(node.target.id)
    elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        names.add(node.target.id)
    elif isinstance(node, ast.Delete):
        for target in node.targets:
            names.update(_collect_store_names(target))
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        names.update(_collect_store_names(node.target))
        for stmt in list(node.body) + list(node.orelse):
            names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, ast.While):
        for stmt in list(node.body) + list(node.orelse):
            names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                names.update(_collect_store_names(item.optional_vars))
        for stmt in node.body:
            names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, ast.Try):
        for stmt in node.body:
            names.update(_names_bound_by_statement(stmt))
        for handler in node.handlers:
            if handler.name:
                names.add(handler.name)
            for stmt in handler.body:
                names.update(_names_bound_by_statement(stmt))
        for stmt in list(node.orelse) + list(node.finalbody):
            names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, ast.Match):
        for case in node.cases:
            names.update(_collect_match_pattern_names(case.pattern))
            for stmt in case.body:
                names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, ast.If):
        for stmt in list(node.body) + list(node.orelse):
            names.update(_names_bound_by_statement(stmt))
    elif isinstance(node, ast.Expr):
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                names.add(child.target.id)
        if isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name) and func.id in {"exec", "eval", "compile"}:
                names.add("*")
            elif (
                isinstance(func, ast.Attribute)
                and _is_module_namespace_expr(func.value)
                and func.attr
                in {
                    "update",
                    "setdefault",
                    "pop",
                    "clear",
                    "__setitem__",
                }
            ):
                names.add("*")
    return names


def _apply_precise_binding(
    bindings: dict[str, FinalBinding],
    node: ast.AST,
    *,
    path: str,
) -> None:
    """Apply an unconditional module-level binding statement."""

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if node.decorator_list:
            # Decorator identity is not modeled — refuse authorizing identity.
            bindings[node.name] = FinalBinding(kind="rebound")
        else:
            bindings[node.name] = FinalBinding(
                kind="function",
                function_node=node,
            )
    elif isinstance(node, ast.ClassDef):
        bindings[node.name] = FinalBinding(kind="rebound")
    elif isinstance(node, ast.ImportFrom):
        if any(alias.name == "*" for alias in node.names):
            _mark_rebound(bindings, list(bindings))
            return
        module_name = import_module_name_from_importer(node, importer_path=path)
        for alias in node.names:
            local = alias.asname or alias.name
            if module_name is None:
                bindings[local] = FinalBinding(kind="rebound")
            else:
                bindings[local] = FinalBinding(
                    kind="import_name",
                    module_name=module_name,
                    imported_name=alias.name,
                )
    elif isinstance(node, ast.Import):
        for alias in node.names:
            if alias.asname:
                bindings[alias.asname] = FinalBinding(
                    kind="import_module",
                    module_name=alias.name,
                )
            else:
                top = alias.name.split(".", 1)[0]
                bindings[top] = FinalBinding(
                    kind="import_module",
                    module_name=top,
                )
    elif isinstance(node, ast.Assign):
        poisoned = False
        for target in node.targets:
            if isinstance(target, ast.Subscript) and _is_module_namespace_expr(
                target.value
            ):
                key = _static_str(target.slice)
                if key is None:
                    poisoned = True
                else:
                    bindings[key] = FinalBinding(kind="rebound")
            else:
                _mark_rebound(bindings, _collect_store_names(target))
        if poisoned:
            _mark_rebound(bindings, list(bindings))
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        bindings[node.target.id] = FinalBinding(kind="rebound")
    elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        bindings[node.target.id] = FinalBinding(kind="rebound")
    elif isinstance(node, ast.Delete):
        for target in node.targets:
            _mark_rebound(bindings, _collect_store_names(target))
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        _mark_rebound(bindings, _collect_store_names(node.target))
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                _mark_rebound(bindings, _collect_store_names(item.optional_vars))
    elif isinstance(node, ast.Try):
        for handler in node.handlers:
            if handler.name:
                bindings[handler.name] = FinalBinding(kind="rebound")
    elif isinstance(node, ast.Match):
        for case in node.cases:
            _mark_rebound(bindings, _collect_match_pattern_names(case.pattern))
    elif isinstance(node, ast.Expr):
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                bindings[child.target.id] = FinalBinding(kind="rebound")
        if isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name) and func.id in {"exec", "eval", "compile"}:
                _mark_rebound(bindings, list(bindings))
            elif (
                isinstance(func, ast.Attribute)
                and _is_module_namespace_expr(func.value)
                and func.attr
                in {
                    "update",
                    "setdefault",
                    "pop",
                    "clear",
                    "__setitem__",
                }
            ):
                _mark_rebound(bindings, list(bindings))


_COMPOUND_UNCERTAIN = (
    ast.If,
    ast.While,
    ast.For,
    ast.AsyncFor,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.Match,
)


def module_final_bindings(
    tree: ast.AST,
    *,
    path: str,
) -> dict[str, FinalBinding]:
    """Compute module-scope final bindings in statement order.

    Later unconditional statements win. Conditional / compound suites that may
    bind a name leave that name ``rebound`` unless a later unconditional binding
    restores precise identity (Unknown > false PASS).

    Decorated ``FunctionDef`` / ``AsyncFunctionDef`` nodes are rebound until
    decorator identity is modeled. Dynamic namespace mutations (``globals()``,
    ``locals()``, ``vars()``) likewise refuse precise identity.
    """

    bindings: dict[str, FinalBinding] = {}
    for node in getattr(tree, "body", ()):
        if isinstance(node, _COMPOUND_UNCERTAIN):
            possible = _names_bound_by_statement(node)
            if "*" in possible:
                _mark_rebound(bindings, list(bindings))
            if isinstance(
                node,
                (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith, ast.Try, ast.Match),
            ):
                _apply_precise_binding(bindings, node, path=path)
            _mark_rebound(bindings, possible - {"*"})
            continue
        _apply_precise_binding(bindings, node, path=path)
    return bindings


def _iter_module_level_executable_stmts(
    stmts: Sequence[ast.stmt],
) -> Iterable[tuple[int, ast.stmt]]:
    """Yield (top_level_index, stmt) for every module-level executable stmt.

    Recurses into if/else, try/except/else/finally, for/while, with, and match
    suites. Does not enter function or class bodies.
    """

    for index, node in enumerate(stmts):
        yield index, node
        if isinstance(node, ast.If):
            for _, child in _iter_module_level_executable_stmts(node.body):
                yield index, child
            for _, child in _iter_module_level_executable_stmts(node.orelse):
                yield index, child
        elif isinstance(node, ast.While):
            for _, child in _iter_module_level_executable_stmts(node.body):
                yield index, child
            for _, child in _iter_module_level_executable_stmts(node.orelse):
                yield index, child
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for _, child in _iter_module_level_executable_stmts(node.body):
                yield index, child
            for _, child in _iter_module_level_executable_stmts(node.orelse):
                yield index, child
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for _, child in _iter_module_level_executable_stmts(node.body):
                yield index, child
        elif isinstance(node, ast.Try):
            for _, child in _iter_module_level_executable_stmts(node.body):
                yield index, child
            for handler in node.handlers:
                for _, child in _iter_module_level_executable_stmts(handler.body):
                    yield index, child
            for _, child in _iter_module_level_executable_stmts(node.orelse):
                yield index, child
            for _, child in _iter_module_level_executable_stmts(node.finalbody):
                yield index, child
        elif isinstance(node, ast.Match):
            for case in node.cases:
                for _, child in _iter_module_level_executable_stmts(case.body):
                    yield index, child


def _final_binding_establish_index(
    tree: ast.AST,
    name: str,
) -> int | None:
    """Top-level statement index that establishes ``name``'s final binding."""

    body: Sequence[ast.stmt] = getattr(tree, "body", ())
    establish: int | None = None
    for index, node in enumerate(body):
        if isinstance(node, _COMPOUND_UNCERTAIN):
            possible = _names_bound_by_statement(node)
            if name in possible or "*" in possible:
                # Uncertain compound leaves rebound unless a later precise bind.
                establish = None
            continue
        # Mirror unconditional precise binding that can own ``name``.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == name:
                establish = index
        elif isinstance(node, ast.ClassDef) and node.name == name:
            establish = index
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                establish = None
            else:
                for alias in node.names:
                    if (alias.asname or alias.name) == name:
                        establish = index
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                if local == name:
                    establish = index
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript) and _is_module_namespace_expr(
                    target.value
                ):
                    key = _static_str(target.slice)
                    if key is None:
                        establish = None
                    elif key == name:
                        establish = index
                elif name in _collect_store_names(target):
                    establish = index
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name:
                establish = index
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name:
                establish = index
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                if name in _collect_store_names(target):
                    establish = None
        elif isinstance(node, ast.Expr):
            if isinstance(node.value, ast.Call):
                func = node.value.func
                if isinstance(func, ast.Name) and func.id in {
                    "exec",
                    "eval",
                    "compile",
                }:
                    establish = None
                elif (
                    isinstance(func, ast.Attribute)
                    and _is_module_namespace_expr(func.value)
                    and func.attr
                    in {
                        "update",
                        "setdefault",
                        "pop",
                        "clear",
                        "__setitem__",
                    }
                ):
                    establish = None
    return establish


def _is_sys_modules_expr(node: ast.AST) -> bool:
    """True for ``sys.modules`` (Name sys + Attribute modules)."""

    return (
        isinstance(node, ast.Attribute)
        and node.attr == "modules"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def _module_namespace_surface(
    node: ast.AST,
    *,
    local_bindings: Mapping[str, FinalBinding],
) -> str | None:
    """Return module alias if ``node`` is that module's namespace surface.

    Recognizes ``module``, ``module.__dict__``, and ``vars(module)``.
    """

    if isinstance(node, ast.Name):
        binding = local_bindings.get(node.id)
        if binding is not None and binding.kind == "import_module":
            return node.id
        return None
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return _module_namespace_surface(
            node.value, local_bindings=local_bindings
        )
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and len(node.args) == 1
        and not node.keywords
    ):
        return _module_namespace_surface(
            node.args[0], local_bindings=local_bindings
        )
    return None


def _resolve_import_module_path(
    alias: str,
    *,
    path: str,
    bindings_by_path: Mapping[str, Mapping[str, FinalBinding]],
    available_paths: frozenset[str],
    import_roots: tuple[str, ...],
) -> str | None:
    binding = bindings_by_path.get(path, {}).get(alias)
    if binding is None or binding.kind != "import_module" or binding.module_name is None:
        return None
    candidates = module_candidates_in_manifest(
        binding.module_name,
        set(available_paths),
        import_roots=import_roots,
    )
    if len(candidates) != 1:
        return None
    return candidates[0]


def _resolve_callable_identity(
    expr: ast.AST,
    *,
    path: str,
    bindings_by_path: Mapping[str, Mapping[str, FinalBinding]],
    available_paths: frozenset[str],
    import_roots: tuple[str, ...],
) -> tuple[str, str] | None:
    """Resolve ``expr`` to a (defining_path, export_name) callable identity."""

    local = bindings_by_path.get(path, {})
    if isinstance(expr, ast.Name):
        binding = local.get(expr.id)
        if binding is None:
            return None
        if binding.kind == "function":
            return (path, expr.id)
        if binding.kind == "import_name":
            if binding.module_name is None or binding.imported_name is None:
                return None
            candidates = module_candidates_in_manifest(
                binding.module_name,
                set(available_paths),
                import_roots=import_roots,
            )
            if len(candidates) != 1:
                return None
            return (candidates[0], binding.imported_name)
        return None
    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
        module_path = _resolve_import_module_path(
            expr.value.id,
            path=path,
            bindings_by_path=bindings_by_path,
            available_paths=available_paths,
            import_roots=import_roots,
        )
        if module_path is None:
            return None
        return (module_path, expr.attr)
    return None


def _is_setattr_call(call: ast.Call) -> bool:
    func = call.func
    return (isinstance(func, ast.Name) and func.id == "setattr") or (
        isinstance(func, ast.Attribute) and func.attr == "__setattr__"
    )


def _setattr_target_and_name(
    call: ast.Call,
) -> tuple[ast.AST, ast.AST] | None:
    """Return (target_obj, name_expr) for setattr-shaped calls."""

    if not _is_setattr_call(call) or len(call.args) < 2:
        return None
    func = call.func
    if isinstance(func, ast.Name) and func.id == "setattr":
        return (call.args[0], call.args[1])
    if isinstance(func, ast.Attribute) and func.attr == "__setattr__":
        if isinstance(func.value, ast.Name) and func.value.id == "object":
            if len(call.args) < 3:
                return None
            return (call.args[0], call.args[1])
        # obj.__setattr__(name, value)
        return (func.value, call.args[0])
    return None


def _collect_mutation_effects(
    trees: Mapping[str, ast.AST],
    bindings_by_path: Mapping[str, Mapping[str, FinalBinding]],
    *,
    available_paths: frozenset[str],
    import_roots: tuple[str, ...],
) -> _MutationEffects:
    """Collect module-export and callable-behavior mutations (#163).

    Recursively inspects all module-level executable suites. Shared by bypass
    writer closure and interprocedural argument provenance via CalleeResolver.
    """

    export_mutations: dict[str, set[str]] = {}
    behavior_mutations: set[tuple[str, str]] = set()
    unsupported = False

    def _note_export(module_path: str, name: str) -> None:
        export_mutations.setdefault(module_path, set()).add(name)

    def _note_behavior(
        identity: tuple[str, str],
        *,
        mutation_path: str,
        mutation_index: int,
    ) -> None:
        defining_path, export_name = identity
        if defining_path == mutation_path:
            establish = _final_binding_establish_index(
                trees[defining_path], export_name
            )
            # Later unconditional rebinding in the defining module restores a
            # fresh source-grounded callable; mutations before that index do
            # not poison the final object.
            if establish is not None and mutation_index < establish:
                return
        behavior_mutations.add(identity)

    def _handle_module_alias_export(
        alias: str,
        attr: str | None,
        *,
        path: str,
    ) -> None:
        module_path = _resolve_import_module_path(
            alias,
            path=path,
            bindings_by_path=bindings_by_path,
            available_paths=available_paths,
            import_roots=import_roots,
        )
        if module_path is None:
            return
        _note_export(module_path, "*" if attr is None else attr)

    def _scan_assign_target(
        target: ast.AST,
        *,
        path: str,
        index: int,
        local_bindings: Mapping[str, FinalBinding],
    ) -> None:
        nonlocal unsupported
        # module.name = ... / callable.attr = ...
        if isinstance(target, ast.Attribute):
            if _is_sys_modules_expr(target.value) or (
                isinstance(target.value, ast.Subscript)
                and _is_sys_modules_expr(target.value.value)
            ):
                unsupported = True
                # Static sys.modules["mod"].name when possible.
                if (
                    isinstance(target.value, ast.Subscript)
                    and _is_sys_modules_expr(target.value.value)
                ):
                    key = _static_str(target.value.slice)
                    attr = target.attr
                    if key is not None:
                        candidates = module_candidates_in_manifest(
                            key,
                            set(available_paths),
                            import_roots=import_roots,
                        )
                        if len(candidates) == 1:
                            _note_export(candidates[0], attr)
                        else:
                            for mod_path in available_paths:
                                _note_export(mod_path, "*")
                    else:
                        for mod_path in available_paths:
                            _note_export(mod_path, "*")
                else:
                    for mod_path in available_paths:
                        _note_export(mod_path, "*")
                return
            if isinstance(target.value, ast.Name):
                alias = target.value.id
                binding = local_bindings.get(alias)
                if binding is not None and binding.kind == "import_module":
                    _handle_module_alias_export(alias, target.attr, path=path)
                    return
                identity = _resolve_callable_identity(
                    target.value,
                    path=path,
                    bindings_by_path=bindings_by_path,
                    available_paths=available_paths,
                    import_roots=import_roots,
                )
                if identity is not None:
                    _note_behavior(
                        identity, mutation_path=path, mutation_index=index
                    )
                    return
            # helpers.write_state.__code__ = ... (Attribute of Attribute)
            if isinstance(target.value, ast.Attribute):
                identity = _resolve_callable_identity(
                    target.value,
                    path=path,
                    bindings_by_path=bindings_by_path,
                    available_paths=available_paths,
                    import_roots=import_roots,
                )
                if identity is not None:
                    _note_behavior(
                        identity, mutation_path=path, mutation_index=index
                    )
                return
        # module.__dict__[name] / vars(module)[name] / callable.__globals__[k]
        if isinstance(target, ast.Subscript):
            if _is_sys_modules_expr(target.value):
                unsupported = True
                key = _static_str(target.slice)
                if key is not None:
                    candidates = module_candidates_in_manifest(
                        key,
                        set(available_paths),
                        import_roots=import_roots,
                    )
                    if len(candidates) == 1:
                        _note_export(candidates[0], "*")
                    else:
                        for mod_path in available_paths:
                            _note_export(mod_path, "*")
                else:
                    for mod_path in available_paths:
                        _note_export(mod_path, "*")
                return
            surface = _module_namespace_surface(
                target.value, local_bindings=local_bindings
            )
            if surface is not None:
                key = _static_str(target.slice)
                _handle_module_alias_export(surface, key, path=path)
                return
            # fn.__globals__[x] / fn.__dict__[x] / any callable subscript write
            if isinstance(target.value, ast.Attribute):
                identity = _resolve_callable_identity(
                    target.value.value,
                    path=path,
                    bindings_by_path=bindings_by_path,
                    available_paths=available_paths,
                    import_roots=import_roots,
                )
                if identity is not None:
                    _note_behavior(
                        identity, mutation_path=path, mutation_index=index
                    )
                    return
            identity = _resolve_callable_identity(
                target.value,
                path=path,
                bindings_by_path=bindings_by_path,
                available_paths=available_paths,
                import_roots=import_roots,
            )
            if identity is not None:
                _note_behavior(
                    identity, mutation_path=path, mutation_index=index
                )

    def _scan_call(
        call: ast.Call,
        *,
        path: str,
        index: int,
        local_bindings: Mapping[str, FinalBinding],
    ) -> None:
        nonlocal unsupported
        setattr_parts = _setattr_target_and_name(call)
        if setattr_parts is not None:
            obj, name_expr = setattr_parts
            if _is_sys_modules_expr(obj) or (
                isinstance(obj, ast.Subscript) and _is_sys_modules_expr(obj.value)
            ):
                unsupported = True
                for mod_path in available_paths:
                    _note_export(mod_path, "*")
                return
            attr = _static_str(name_expr)
            surface = _module_namespace_surface(
                obj, local_bindings=local_bindings
            )
            if surface is not None:
                _handle_module_alias_export(surface, attr, path=path)
                return
            if isinstance(obj, ast.Name):
                binding = local_bindings.get(obj.id)
                if binding is not None and binding.kind == "import_module":
                    _handle_module_alias_export(obj.id, attr, path=path)
                    return
            identity = _resolve_callable_identity(
                obj,
                path=path,
                bindings_by_path=bindings_by_path,
                available_paths=available_paths,
                import_roots=import_roots,
            )
            if identity is not None:
                _note_behavior(
                    identity, mutation_path=path, mutation_index=index
                )
            return

        # module.__dict__.update(...) / vars(module).update(...)
        func = call.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr
            in {"update", "setdefault", "pop", "clear", "__setitem__"}
        ):
            surface = _module_namespace_surface(
                func.value, local_bindings=local_bindings
            )
            if surface is not None:
                _handle_module_alias_export(surface, None, path=path)
                return
            # callable.__globals__.update(...)
            if isinstance(func.value, ast.Attribute):
                identity = _resolve_callable_identity(
                    func.value.value,
                    path=path,
                    bindings_by_path=bindings_by_path,
                    available_paths=available_paths,
                    import_roots=import_roots,
                )
                if identity is not None:
                    _note_behavior(
                        identity, mutation_path=path, mutation_index=index
                    )

    for path, tree in trees.items():
        local_bindings = bindings_by_path.get(path, {})
        body: Sequence[ast.stmt] = getattr(tree, "body", ())
        for index, node in _iter_module_level_executable_stmts(body):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets: list[ast.AST]
                if isinstance(node, ast.Assign):
                    targets = list(node.targets)
                else:
                    targets = [node.target]
                for target in targets:
                    _scan_assign_target(
                        target,
                        path=path,
                        index=index,
                        local_bindings=local_bindings,
                    )
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                _scan_call(
                    node.value,
                    path=path,
                    index=index,
                    local_bindings=local_bindings,
                )
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    _scan_assign_target(
                        target,
                        path=path,
                        index=index,
                        local_bindings=local_bindings,
                    )

    return _MutationEffects(
        export_mutations={
            path: frozenset(names) for path, names in export_mutations.items()
        },
        behavior_mutations=frozenset(behavior_mutations),
        unsupported_module_mutation=unsupported,
    )


def _apply_mutation_effects(
    bindings_by_path: dict[str, dict[str, FinalBinding]],
    effects: _MutationEffects,
    *,
    available_paths: frozenset[str],
    import_roots: tuple[str, ...],
) -> dict[str, dict[str, FinalBinding]]:
    """Apply ModuleBindingIdentity and CallableBehaviorIdentity poisons."""

    result: dict[str, dict[str, FinalBinding]] = {
        path: dict(bindings) for path, bindings in bindings_by_path.items()
    }

    export_mutations = {
        path: set(names) for path, names in effects.export_mutations.items()
    }
    if effects.unsupported_module_mutation:
        for path in list(available_paths):
            export_mutations.setdefault(path, set()).add("*")

    for path, names in export_mutations.items():
        target = result.setdefault(path, {})
        if "*" in names:
            _mark_rebound(target, list(target))
            poison_names = set(target) | (names - {"*"})
        else:
            poison_names = set(names)
            for name in names:
                target[name] = FinalBinding(kind="rebound")
        for other_path, other_bindings in result.items():
            if other_path == path:
                continue
            for local, binding in list(other_bindings.items()):
                if binding.kind != "import_name" or binding.module_name is None:
                    continue
                candidates = module_candidates_in_manifest(
                    binding.module_name,
                    set(available_paths),
                    import_roots=import_roots,
                )
                if len(candidates) != 1 or candidates[0] != path:
                    continue
                if "*" in names or binding.imported_name in poison_names:
                    other_bindings[local] = FinalBinding(kind="rebound")

    for defining_path, export_name in effects.behavior_mutations:
        target = result.setdefault(defining_path, {})
        binding = target.get(export_name)
        if binding is not None and binding.kind == "function":
            target[export_name] = replace(binding, behavior_established=False)
        elif binding is not None:
            target[export_name] = replace(binding, behavior_established=False)
        else:
            target[export_name] = FinalBinding(
                kind="rebound",
                behavior_established=False,
            )
        for other_path, other_bindings in result.items():
            for local, other in list(other_bindings.items()):
                if other.kind != "import_name" or other.module_name is None:
                    continue
                if other.imported_name != export_name:
                    continue
                candidates = module_candidates_in_manifest(
                    other.module_name,
                    set(available_paths),
                    import_roots=import_roots,
                )
                if len(candidates) == 1 and candidates[0] == defining_path:
                    other_bindings[local] = replace(
                        other, behavior_established=False
                    )

    return result


@dataclass(frozen=True)
class CalleeResolver:
    """Caller-relative callee resolver over an authenticated Python file set."""

    trees: Mapping[str, ast.AST]
    bindings_by_path: Mapping[str, Mapping[str, FinalBinding]]
    available_paths: frozenset[str]
    import_roots: tuple[str, ...] = ()
    implementation_version: str = _IMPLEMENTATION_VERSION

    def resolve_call(
        self,
        func: ast.AST,
        *,
        caller_path: str,
        shadowed_names: frozenset[str] = frozenset(),
    ) -> CalleeResolveResult:
        """Resolve ``func`` of a Call relative to ``caller_path``."""

        caller = normalize_path(caller_path)
        if isinstance(func, ast.Name):
            if func.id in shadowed_names:
                return CalleeResolveResult(
                    callee=None,
                    reason="shadowed_local_binding",
                )
            return self._resolve_name(func.id, owner_path=caller)

        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return self._resolve_module_attribute(
                module_alias=func.value.id,
                attr=func.attr,
                caller_path=caller,
                shadowed_names=shadowed_names,
            )

        return CalleeResolveResult(callee=None, reason="deferred_callee_form")

    def _resolve_name(
        self,
        name: str,
        *,
        owner_path: str,
        depth: int = 0,
    ) -> CalleeResolveResult:
        if depth > _MAX_IMPORT_FOLLOW_DEPTH:
            return CalleeResolveResult(callee=None, reason="import_follow_depth")

        owner = normalize_path(owner_path)
        bindings = self.bindings_by_path.get(owner)
        if bindings is None:
            return CalleeResolveResult(callee=None, reason="caller_module_absent")

        binding = bindings.get(name)
        if binding is None:
            return CalleeResolveResult(callee=None, reason="unbound_name")

        if not binding.behavior_established:
            return CalleeResolveResult(
                callee=None,
                reason="callable_behavior_unknown",
            )

        if binding.kind == "function":
            assert binding.function_node is not None
            return CalleeResolveResult(
                callee=ResolvedCallee(path=owner, node=binding.function_node),
            )

        if binding.kind == "rebound":
            return CalleeResolveResult(callee=None, reason="module_level_rebinding")

        if binding.kind == "import_name":
            assert binding.module_name is not None
            assert binding.imported_name is not None
            return self._resolve_from_module(
                binding.module_name,
                binding.imported_name,
                depth=depth + 1,
            )

        if binding.kind == "import_module":
            return CalleeResolveResult(callee=None, reason="module_alias_not_callable")

        return CalleeResolveResult(callee=None, reason="unresolved_binding")

    def _resolve_module_attribute(
        self,
        *,
        module_alias: str,
        attr: str,
        caller_path: str,
        shadowed_names: frozenset[str],
    ) -> CalleeResolveResult:
        if module_alias in shadowed_names:
            return CalleeResolveResult(
                callee=None,
                reason="shadowed_local_binding",
            )
        bindings = self.bindings_by_path.get(caller_path)
        if bindings is None:
            return CalleeResolveResult(callee=None, reason="caller_module_absent")
        binding = bindings.get(module_alias)
        if binding is None:
            return CalleeResolveResult(callee=None, reason="unbound_module_alias")
        if binding.kind != "import_module" or binding.module_name is None:
            return CalleeResolveResult(
                callee=None,
                reason="deferred_module_attribute",
            )
        return self._resolve_from_module(binding.module_name, attr, depth=0)

    def _resolve_from_module(
        self,
        module_name: str,
        attr: str,
        *,
        depth: int,
    ) -> CalleeResolveResult:
        candidates = module_candidates_in_manifest(
            module_name,
            set(self.available_paths),
            import_roots=self.import_roots,
        )
        if len(candidates) == 0:
            return CalleeResolveResult(callee=None, reason="external_import")
        if len(candidates) > 1:
            return CalleeResolveResult(callee=None, reason="ambiguous_manifest")
        target_path = candidates[0]
        return self._resolve_name(attr, owner_path=target_path, depth=depth)


def build_callee_resolver(
    trees: Mapping[str, ast.AST],
    *,
    import_roots: Sequence[str] = (),
) -> CalleeResolver:
    """Build a resolver over already-parsed module ASTs keyed by path."""

    roots = normalize_import_roots(import_roots)
    normalized: dict[str, ast.AST] = {
        normalize_path(path): tree for path, tree in trees.items()
    }
    available = frozenset(normalized)
    bindings = {
        path: module_final_bindings(tree, path=path)
        for path, tree in normalized.items()
    }
    effects = _collect_mutation_effects(
        normalized,
        bindings,
        available_paths=available,
        import_roots=roots,
    )
    if (
        effects.export_mutations
        or effects.behavior_mutations
        or effects.unsupported_module_mutation
    ):
        bindings = _apply_mutation_effects(
            bindings,
            effects,
            available_paths=available,
            import_roots=roots,
        )
    return CalleeResolver(
        trees=normalized,
        bindings_by_path=bindings,
        available_paths=available,
        import_roots=roots,
    )


def build_callee_resolver_from_sources(
    files: Mapping[str, str],
    *,
    import_roots: Sequence[str] = (),
) -> CalleeResolver:
    """Parse ``files`` and build a caller-relative callee resolver."""

    trees: dict[str, ast.AST] = {}
    for path, source in files.items():
        norm = normalize_path(path)
        trees[norm] = ast.parse(source, filename=path)
    return build_callee_resolver(trees, import_roots=import_roots)


def index_unique_module_functions(
    trees: Mapping[str, ast.AST],
) -> dict[str, ResolvedCallee]:
    """Map simple name → unique non-rebound module function, when unambiguous.

    Used only to select an analysis *target* by leaf name. Callsite matching
    must still go through :meth:`CalleeResolver.resolve_call`.
    """

    buckets: dict[str, list[ResolvedCallee]] = {}
    for path, tree in sorted(
        (normalize_path(p), t) for p, t in trees.items()
    ):
        bindings = module_final_bindings(tree, path=path)
        for name, binding in bindings.items():
            if binding.kind != "function" or binding.function_node is None:
                continue
            buckets.setdefault(name, []).append(
                ResolvedCallee(path=path, node=binding.function_node)
            )
    unique: dict[str, ResolvedCallee] = {}
    for name, items in buckets.items():
        if len(items) == 1:
            unique[name] = items[0]
    return unique
