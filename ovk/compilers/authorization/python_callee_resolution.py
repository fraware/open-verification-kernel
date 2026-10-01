"""Caller-relative Python callee resolution (#160).

Replaces repository-global simple-name callee indexing with resolution that
honours the caller's module-level final bindings and authenticated-manifest
import identity.

Shared by:
- bypass interprocedural writer closure
- interprocedural argument provenance

Resolution for a bare call ``write_state(...)``:
1. local function binding in the caller module
2. explicit imported binding (followed through a unique manifest module)
3. otherwise unresolved → UNKNOWN when Request/state escapes

Never searches the repository for a same-leaf function merely because the
name matches.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

_IMPLEMENTATION_VERSION = "0.2.0"
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
    """Module-scope final binding for one local name."""

    kind: BindingKind
    function_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    # Absolute import module name for import_name / import_module.
    module_name: str | None = None
    # Imported attribute for ``from mod import attr`` (attr may differ from local).
    imported_name: str | None = None


@dataclass(frozen=True)
class CalleeResolveResult:
    """Outcome of resolving one call expression's callee."""

    callee: ResolvedCallee | None
    reason: str | None = None

    @property
    def resolved(self) -> bool:
        return self.callee is not None


def normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def module_candidates_in_manifest(
    module: str,
    available_paths: set[str],
) -> tuple[str, ...]:
    """Locate repository paths that could bind an absolute import."""

    stem = module.replace(".", "/")
    wanted = (f"{stem}.py", f"{stem}/__init__.py")
    found: set[str] = set()
    for path in available_paths:
        for suffix in wanted:
            if path == suffix or path.endswith("/" + suffix):
                found.add(path)
                break
    return tuple(sorted(found))


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


def _mark_rebound(bindings: dict[str, FinalBinding], names: list[str]) -> None:
    for name in names:
        bindings[name] = FinalBinding(kind="rebound")


def module_final_bindings(
    tree: ast.AST,
    *,
    path: str,
) -> dict[str, FinalBinding]:
    """Compute module-scope final bindings in statement order.

    Later statements win. ``def name`` then ``from ext import name`` leaves an
    import binding. ``from local import name`` then ``name = wrapper`` leaves a
    rebound binding (UNKNOWN unless independently resolved).

    Module-level ``for``/``with``/``except``/``match``/``del`` stores and star
    imports also overwrite prior function identity — omitting them lets a stale
    ``def write_state`` authorize after runtime rebinding (Unknown > false PASS).
    """

    bindings: dict[str, FinalBinding] = {}
    for node in getattr(tree, "body", ()):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bindings[node.name] = FinalBinding(
                kind="function",
                function_node=node,
            )
        elif isinstance(node, ast.ClassDef):
            bindings[node.name] = FinalBinding(kind="rebound")
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                # ``from M import *`` may overwrite any previously bound name.
                # Names rebound *after* the star regain precise identity.
                _mark_rebound(bindings, list(bindings))
                continue
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
                # ``import a.b.c as h`` → h binds module a.b.c uniquely.
                # ``import a.b.c`` → only top-level ``a`` is bound; nested
                # ``a.b.c.func`` attribute chains are outside this theorem.
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
            for target in node.targets:
                _mark_rebound(bindings, _collect_store_names(target))
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
                    _mark_rebound(
                        bindings, _collect_store_names(item.optional_vars)
                    )
        elif isinstance(node, ast.Try):
            for handler in node.handlers:
                if handler.name:
                    bindings[handler.name] = FinalBinding(kind="rebound")
        elif isinstance(node, ast.Match):
            for case in node.cases:
                _mark_rebound(
                    bindings, _collect_match_pattern_names(case.pattern)
                )
        elif isinstance(node, ast.Expr):
            # Module-level walrus ``(name := value)`` rebinds ``name``.
            for child in ast.walk(node):
                if isinstance(child, ast.NamedExpr) and isinstance(
                    child.target, ast.Name
                ):
                    bindings[child.target.id] = FinalBinding(kind="rebound")
    return bindings


@dataclass(frozen=True)
class CalleeResolver:
    """Caller-relative callee resolver over an authenticated Python file set."""

    trees: Mapping[str, ast.AST]
    bindings_by_path: Mapping[str, Mapping[str, FinalBinding]]
    available_paths: frozenset[str]
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
            # A bare call of a module alias is not a function identity.
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
            # Only uniquely imported module aliases participate.
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
        )
        if len(candidates) == 0:
            return CalleeResolveResult(callee=None, reason="external_import")
        if len(candidates) > 1:
            return CalleeResolveResult(callee=None, reason="ambiguous_manifest")
        target_path = candidates[0]
        return self._resolve_name(attr, owner_path=target_path, depth=depth)


def build_callee_resolver(
    trees: Mapping[str, ast.AST],
) -> CalleeResolver:
    """Build a resolver over already-parsed module ASTs keyed by path."""

    normalized: dict[str, ast.AST] = {
        normalize_path(path): tree for path, tree in trees.items()
    }
    bindings = {
        path: module_final_bindings(tree, path=path)
        for path, tree in normalized.items()
    }
    return CalleeResolver(
        trees=normalized,
        bindings_by_path=bindings,
        available_paths=frozenset(normalized),
    )


def build_callee_resolver_from_sources(
    files: Mapping[str, str],
) -> CalleeResolver:
    """Parse ``files`` and build a caller-relative callee resolver."""

    trees: dict[str, ast.AST] = {}
    for path, source in files.items():
        norm = normalize_path(path)
        trees[norm] = ast.parse(source, filename=path)
    return build_callee_resolver(trees)


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
