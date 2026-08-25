"""ESTree-backed Express authorization compiler (profile ``authorization.express.ast_v1``).

Uses a pinned pure-Python ESTree *subset* parser so production does not depend on
a Node binary or regex coverage. The legacy regex compiler in ``express.py``
remains advisory-only.

Support boundary (fail closed outside this set):
- Static string path literals (single/double/backtick without ``${}``)
- ``express.Router`` / ``app.use`` mounts / ``router.route(...).METHOD(...)`` chains
- CJS ``require`` and ESM ``import`` alias maps for middleware identities
- Ordered middleware identifier lists (not spreads, not ``eval``/``new Function``)
- Optional simple TypeScript parameter type erasures (``: Type``) before scan

Unsupported (forces review / incomplete coverage):
- Dynamic path construction, template interpolations, computed keys
- Spread middleware, eval/new Function, unresolved array middleware literals
- Full TS/JSX/decorators, ambient types, and any syntax the subset cannot parse
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from ovk.compilers.authorization.base import looks_admin_protected, normalize_path
from ovk.compilers.authorization.ir import AuthCheck, AuthDependency, AuthMount, AuthRoute, AuthorizationIR, SourceSpan
from ovk.compilers.authorization.material_loader import AuthMaterials

_SOURCE_PROFILE_ID = "authorization.express.ast_v1"
_PARSER_ID = "ovk.estree.subset.v2"
_PARSER_DIGEST = hashlib.sha256(_PARSER_ID.encode("utf-8")).hexdigest()

_STRING = re.compile(r"""(?P<q>['"`])(?P<val>(?:\\.|(?!(?P=q)).)*)(?P=q)""")
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_HTTP = frozenset({"get", "post", "put", "patch", "delete", "use", "all"})
_TEMPLATE_INTERP = re.compile(r"\$\{")
_SIMPLE_TS_PARAM = re.compile(r"(\(|,)\s*([A-Za-z_$][\w$]*)\s*:\s*[A-Za-z_$][\w$<>\[\]\|\&\s.,]*")


def _strip_comments(source: str) -> str:
    """Remove // and /* */ comments outside of strings (best-effort subset)."""
    out: list[str] = []
    i = 0
    n = len(source)
    in_sq = in_dq = in_bt = False
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if not (in_sq or in_dq or in_bt):
            if ch == "/" and nxt == "/":
                while i < n and source[i] != "\n":
                    i += 1
                continue
            if ch == "/" and nxt == "*":
                i += 2
                while i + 1 < n and not (source[i] == "*" and source[i + 1] == "/"):
                    i += 1
                i = min(n, i + 2)
                continue
        if ch == "'" and not (in_dq or in_bt):
            in_sq = not in_sq
        elif ch == '"' and not (in_sq or in_bt):
            in_dq = not in_dq
        elif ch == "`" and not (in_sq or in_dq):
            in_bt = not in_bt
        out.append(ch)
        i += 1
    return "".join(out)


def _erase_simple_ts_params(source: str) -> str:
    """Erase simple ``(x: Type`` parameter annotations that break identifier scans."""
    return _SIMPLE_TS_PARAM.sub(r"\1\2", source)


@dataclass
class _Call:
    object: str | None
    method: str
    args: list[str]
    start: int
    end: int
    path: str


def _line_span(source: str, start: int, end: int, path: str) -> SourceSpan:
    return SourceSpan(
        path=path,
        start_line=source.count("\n", 0, start) + 1,
        end_line=source.count("\n", 0, end) + 1,
    )


def parse_estree_subset(source: str, *, path: str) -> tuple[list[_Call], list[str], dict[str, str]]:
    """Parse a bounded Express-relevant ESTree subset.

    Returns call sites, unsupported constructs, and import alias map.
    """
    unsupported: list[str] = []
    imports: dict[str, str] = {}
    calls: list[_Call] = []

    cleaned = _erase_simple_ts_params(_strip_comments(source))
    if _TEMPLATE_INTERP.search(cleaned):
        unsupported.append(f"{path}:template_interpolation")

    for match in re.finditer(
        r"""(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*require\((['"])(.+?)\3\)"""
        r"""|import\s+(?:\{([^}]+)\}|(\w+))\s+from\s+(['"])(.+?)\7"""
        r"""|(?:module\.)?exports\.(\w+)\s*=""",
        cleaned,
    ):
        named = match.group(1) or match.group(5)
        default = match.group(2) or match.group(6)
        mod = match.group(4) or match.group(8)
        export_name = match.group(9)
        if named:
            for part in named.split(","):
                token = part.strip().split(" as ")[-1].strip()
                if token:
                    imports[token] = mod or "export"
        if default:
            imports[default] = mod or "export"
        if export_name:
            imports[export_name] = "module.exports"

    if re.search(r"\.\.\.\w+", cleaned):
        unsupported.append(f"{path}:spread_middleware")
    if re.search(r"\beval\s*\(|new\s+Function\s*\(", cleaned):
        unsupported.append(f"{path}:eval_or_new_function")
    if re.search(r"\.(?:get|post|put|patch|delete|use|all)\s*\(\s*['\"][^'\"]+['\"]\s*,\s*\[", cleaned):
        if re.search(r",\s*\[\s*['\"]", cleaned):
            unsupported.append(f"{path}:array_literal_middleware")

    for match in re.finditer(
        r"(?P<obj>\w+)\.(?P<method>get|post|put|patch|delete|use|all|route)\s*\(",
        cleaned,
        flags=re.IGNORECASE,
    ):
        method = match.group("method").lower()
        obj = match.group("obj")
        start = match.start()
        depth = 0
        end = len(cleaned)
        for idx in range(match.end() - 1, min(len(cleaned), match.end() + 4000)):
            ch = cleaned[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end = idx + 1
                    break
        else:
            unsupported.append(f"{path}:unbalanced_call")
            continue
        arg_region = cleaned[match.end() : end - 1]
        args: list[str] = []
        str_match = _STRING.search(arg_region)
        if method != "route" and method in _HTTP:
            if str_match is None and method != "use":
                unsupported.append(f"{path}:dynamic_route_path")
                continue
            if str_match is not None:
                path_lit = str_match.group("val")
                if "${" in path_lit:
                    unsupported.append(f"{path}:template_path_interpolation")
                    continue
                args.append(path_lit)
        elif method == "route":
            if str_match is None:
                unsupported.append(f"{path}:dynamic_route_path")
                continue
            path_lit = str_match.group("val")
            if "${" in path_lit:
                unsupported.append(f"{path}:template_path_interpolation")
                continue
            args.append(path_lit)
        # Only scan identifiers after the static path literal so path segments
        # like ``/admin`` are never mistaken for middleware names.
        ident_region = arg_region[str_match.end() :] if str_match is not None else arg_region
        for ident in _IDENT.findall(ident_region):
            if ident in {"async", "function", "await", "return", "const", "let", "var"}:
                continue
            args.append(ident)
        calls.append(_Call(object=obj, method=method, args=args, start=start, end=end, path=path))

        if method == "route":
            chain = cleaned[end : end + 200]
            for cm in re.finditer(r"\.(?P<m>get|post|put|patch|delete)\s*\((?P<body>[^)]*)\)", chain, flags=re.I):
                handlers = [
                    ident
                    for ident in _IDENT.findall(cm.group("body"))
                    if ident not in {"async", "function", "await", "return"}
                ]
                calls.append(
                    _Call(
                        object=obj,
                        method=cm.group("m").lower(),
                        args=[args[0], *handlers] if args else handlers,
                        start=end + cm.start(),
                        end=end + cm.end(),
                        path=path,
                    )
                )
    return calls, unsupported, imports


class ExpressAstAuthorizationCompiler:
    """Production Express compiler using an ESTree subset parser."""

    framework = "express"
    source_profile_id = _SOURCE_PROFILE_ID
    parser_id = _PARSER_ID
    parser_digest = _PARSER_DIGEST

    def compile(self, materials: AuthMaterials) -> AuthorizationIR:
        base_index = self._index(materials.base_files)
        head_index = self._index(materials.head_files)
        routes = self._merge_routes(base_index, head_index)
        mounts = sorted(
            {**base_index["mounts"], **head_index["mounts"]}.values(),
            key=lambda item: item.mount_id,
        )
        dependencies = sorted(
            {**base_index["dependencies"], **head_index["dependencies"]}.values(),
            key=lambda item: item.name,
        )
        unsupported = sorted(set(base_index["unsupported"] + head_index["unsupported"]))
        warnings = [
            f"compiled_with_source_profile:{_SOURCE_PROFILE_ID}",
            f"parser:{_PARSER_ID}",
            f"parser_digest:{_PARSER_DIGEST}",
        ]
        if not materials.has_base():
            warnings.append("base materials missing")
        if not materials.has_head():
            warnings.append("head materials missing")
        return AuthorizationIR(
            framework="express",
            subject_repo=materials.repo,
            base_revision=materials.base_revision,
            head_revision=materials.head_revision,
            routes=sorted(routes, key=lambda item: (item.path, ",".join(item.methods), item.route_id)),
            mounts=list(mounts),
            dependencies=list(dependencies),
            unsupported_constructs=unsupported,
            warnings=warnings,
            materials=materials.paths,
        )

    def _index(self, files: dict[str, str]) -> dict[str, Any]:
        mounts: dict[str, AuthMount] = {}
        dependencies: dict[str, AuthDependency] = {}
        route_map: dict[tuple[str, str], dict[str, Any]] = {}
        unsupported: list[str] = []
        routers: set[str] = set()

        for path, source in sorted(files.items()):
            calls, file_unsupported, imports = parse_estree_subset(source, path=path)
            unsupported.extend(file_unsupported)
            for name, mod in imports.items():
                roles = ["admin"] if looks_admin_protected(name) else []
                dependencies[name] = AuthDependency(
                    name=name,
                    kind="middleware",
                    imported_from=mod,
                    role_checks=roles,
                )
            for match in re.finditer(
                r"(?:const|let|var)\s+(\w+)\s*=\s*(?:express\.)?Router\(\)",
                _strip_comments(source),
            ):
                routers.add(match.group(1))

            for call in calls:
                if call.method == "use":
                    prefix = call.args[0] if call.args and call.args[0].startswith("/") else ""
                    target = next((a for a in call.args if a in dependencies or a in routers), None)
                    mounts[f"{path}:use:{target}:{prefix}"] = AuthMount(
                        mount_id=f"{path}:use:{target}:{prefix}",
                        prefix=prefix,
                        included_router=target,
                        middleware=[target] if target else [],
                    )
                    continue
                if call.method not in _HTTP or call.method in {"use", "all"}:
                    continue
                if not call.args:
                    continue
                route_path = call.args[0]
                if not route_path.startswith("/"):
                    unsupported.append(f"{path}:missing_static_path")
                    continue
                middleware = call.args[1:]
                checks: list[AuthCheck] = []
                admin = False
                for name in middleware:
                    roles = list((dependencies.get(name).role_checks if dependencies.get(name) else []) or [])
                    if looks_admin_protected(name):
                        admin = True
                        roles = roles or ["admin"]
                    checks.append(
                        AuthCheck(
                            kind="middleware",
                            expression=name,
                            roles=roles,
                            span=_line_span(source, call.start, call.end, path),
                        )
                    )
                key = (normalize_path(route_path), call.method.upper())
                route_map[key] = {
                    "path": key[0],
                    "method": key[1],
                    "handler": middleware[-1] if middleware else None,
                    "checks": checks,
                    "dependencies": middleware,
                    "admin_only": admin,
                    "support": "supported",
                    "unsupported": [],
                    "span": _line_span(source, call.start, call.end, path),
                }
        return {
            "routes": route_map,
            "mounts": mounts,
            "dependencies": dependencies,
            "unsupported": unsupported,
        }

    def _merge_routes(self, base_index: dict[str, Any], head_index: dict[str, Any]) -> list[AuthRoute]:
        keys = sorted(set(base_index["routes"]) | set(head_index["routes"]))
        routes: list[AuthRoute] = []
        for index, key in enumerate(keys):
            before = base_index["routes"].get(key)
            after = head_index["routes"].get(key)
            path = (after or before)["path"]
            method = (after or before)["method"]
            routes.append(
                AuthRoute(
                    route_id=f"express-ast:{path}:{method}:{index}",
                    methods=[method],
                    path=path,
                    handler=(after or before).get("handler"),
                    checks_before=list((before or {}).get("checks") or []),
                    checks_after=list((after or {}).get("checks") or []),
                    dependencies_before=list((before or {}).get("dependencies") or []),
                    dependencies_after=list((after or {}).get("dependencies") or []),
                    admin_only_before=bool((before or {}).get("admin_only")),
                    admin_only_after=bool((after or {}).get("admin_only")),
                    support=(after or before).get("support", "supported"),
                    unsupported_constructs=list((after or before).get("unsupported") or []),
                    span=(after or before).get("span"),
                )
            )
        return routes
