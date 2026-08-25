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
    names.extend(_SECRET.findall(text or ""))
    return sorted(set(names))


def references_github_token(text: str) -> bool:
    blob = text or ""
    return "secrets.GITHUB_TOKEN" in blob or "github.token" in blob


def references_protected_env(text: str) -> bool:
    return bool(_ENV.search(text or ""))


def contains_untrusted_context(text: str) -> bool:
    """Detect direct interpolation of attacker-influenced GitHub event data.

    This does not mean an entire event is untrusted code. It identifies values
    that require contextual escaping/data-flow analysis when used by a command or
    privileged action. Checkout lineage is handled separately by trust_flow.
    """
    blob = (text or "").lower()
    markers = (
        "github.event.pull_request",
        "github.event.issue",
        "github.event.comment",
        "github.event.review",
        "github.event.workflow_run",
        "github.head_ref",
        "github.event.inputs",
        "github.event.client_payload",
    )
    return any(marker in blob for marker in markers)
