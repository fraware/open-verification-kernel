"""Extract authorization lane inputs from route-related source changes."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from ovk.core.diff_parser import extract_post_images, is_unified_diff

ROUTE_MARKERS = ("/routes/", "/middleware/", "/auth/", "/controllers/")
ROUTE_PATTERN = re.compile(r'["\'](/[^"\']+)["\']')
ADMIN_PATTERN = re.compile(r"admin|requireAdmin|is_admin|role.*admin", re.IGNORECASE)
GUARD_PATTERN = re.compile(
    r"requireAuth|requireAdmin|authenticate|authorize|middleware|guard|isAdmin|checkRole|@admin",
    re.IGNORECASE,
)


def _is_auth_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    if any(marker in normalized for marker in ROUTE_MARKERS):
        return True
    return "auth" in PurePosixPath(normalized).name or "route" in PurePosixPath(normalized).name


def _routes_from_content(content: str) -> list[dict]:
    routes: list[dict] = []
    seen: set[str] = set()
    for match in ROUTE_PATTERN.finditer(content):
        route_path = match.group(1)
        if route_path in seen:
            continue
        seen.add(route_path)
        line_start = content.rfind("\n", 0, match.start()) + 1
        line_end = content.find("\n", match.end())
        line = content[line_start : line_end if line_end != -1 else len(content)]
        admin_only = bool(ADMIN_PATTERN.search(line)) or route_path.startswith("/admin")
        guarded = bool(GUARD_PATTERN.search(line))
        reachable_after: list[dict] = []
        if admin_only and not guarded:
            reachable_after.append(
                {
                    "role": "user",
                    "via": ["route_added_without_guard", "middleware_not_applied"],
                }
            )
        routes.append(
            {
                "path": route_path,
                "admin_only_before": admin_only,
                "admin_only_after": admin_only,
                "reachable_after": reachable_after,
            }
        )
    return routes


def authorization_inputs_from_diff(diff_text: str) -> list[dict]:
    """Convert auth-related file changes in a unified diff to authorization lane inputs."""
    if not is_unified_diff(diff_text):
        return []

    inputs: list[dict] = []
    for path, content in extract_post_images(diff_text).items():
        if not _is_auth_path(path) or not content.strip():
            continue
        routes = _routes_from_content(content)
        if not routes:
            continue
        inputs.append({"routes": routes})
    return inputs
