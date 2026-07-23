"""GitHub Actions expression helpers."""

from __future__ import annotations

import re

_EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
_SECRET = re.compile(r"secrets\.([A-Za-z0-9_]+)")
_ENV = re.compile(r"envs?\.([A-Za-z0-9_-]+)")


def iter_expressions(text: str) -> list[str]:
    return [match.group(1) for match in _EXPR.finditer(text or "")]


def secret_names(text: str) -> list[str]:
    names: list[str] = []
    for expr in iter_expressions(text):
        names.extend(_SECRET.findall(expr))
    # Also catch literal secrets.X outside expressions in some fixtures.
    names.extend(_SECRET.findall(text or ""))
    return sorted(set(names))


def references_github_token(text: str) -> bool:
    blob = text or ""
    return "secrets.GITHUB_TOKEN" in blob or "github.token" in blob


def references_protected_env(text: str) -> bool:
    return bool(_ENV.search(text or ""))


def contains_untrusted_context(text: str) -> bool:
    blob = (text or "").lower()
    markers = (
        "github.event.pull_request",
        "github.event.issue",
        "github.head_ref",
        "github.event.review",
        "pull_request_target",
    )
    return any(marker in blob for marker in markers)
