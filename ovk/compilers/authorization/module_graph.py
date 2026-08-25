"""Module-graph helpers for FastAPI AST authorization (WP-06)."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModuleSymbol:
    name: str
    origin_module: str | None = None
    is_star: bool = False
    alias_of: str | None = None


@dataclass
class ModuleGraph:
    """Conservative import/alias/re-export graph across compiled files."""

    modules: dict[str, dict[str, ModuleSymbol]] = field(default_factory=dict)
    star_imports: dict[str, list[str]] = field(default_factory=dict)
    unsupported: list[str] = field(default_factory=list)

    def resolve(self, module_path: str, name: str, *, depth: int = 0) -> ModuleSymbol | None:
        if depth > 16:
            self.unsupported.append(f"{module_path}:import_resolution_depth")
            return None
        table = self.modules.get(module_path) or {}
        symbol = table.get(name)
        if symbol is None:
            for imported in self.star_imports.get(module_path, []):
                # Star imports are conservative: mark unresolved unless exact match found.
                self.unsupported.append(f"{module_path}:star_import:{imported}")
            return None
        if symbol.alias_of and symbol.origin_module:
            return self.resolve(symbol.origin_module, symbol.alias_of, depth=depth + 1) or symbol
        return symbol


def _module_key(path: str) -> str:
    return path.replace("\\", "/")


def build_module_graph(files: dict[str, str]) -> ModuleGraph:
    graph = ModuleGraph()
    for path, source in sorted(files.items()):
        key = _module_key(path)
        table: dict[str, ModuleSymbol] = {}
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            continue
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    table[local] = ModuleSymbol(name=local, origin_module=alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        graph.star_imports.setdefault(key, []).append(module)
                        graph.unsupported.append(f"{path}:star_import:{module}")
                        continue
                    local = alias.asname or alias.name
                    table[local] = ModuleSymbol(
                        name=local,
                        origin_module=module,
                        alias_of=alias.name,
                    )
            elif isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Name):
                    table[target.id] = ModuleSymbol(
                        name=target.id,
                        origin_module=key,
                        alias_of=node.value.id,
                    )
        graph.modules[key] = table
    return graph


# Versioned registry of trusted guard symbols/scopes for strict FastAPI auth.
TRUSTED_GUARD_REGISTRY_V1: dict[str, dict[str, Any]] = {
    "require_admin": {"roles": ["admin"], "scopes": ["admin"]},
    "requireAdmin": {"roles": ["admin"], "scopes": ["admin"]},
    "AdminRequired": {"roles": ["admin"], "scopes": ["admin"]},
    "ensure_admin": {"roles": ["admin"], "scopes": ["admin"]},
    "check_admin": {"roles": ["admin"], "scopes": ["admin"]},
    "require_role": {"roles": ["role"], "scopes": ["role"]},
}


def trusted_guard_roles(name: str) -> list[str]:
    entry = TRUSTED_GUARD_REGISTRY_V1.get(name)
    if not entry:
        return []
    return list(entry.get("roles") or [])
