"""Change-surface detection and template selection.

This module is the first step from fixture-based demos toward repository diff
analysis. It maps changed file paths to OVK domains and candidate intent IDs.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch


@dataclass(frozen=True)
class ChangeSurface:
    """A detected engineering surface affected by a change."""

    domain: str
    reason: str
    files: list[str]
    candidate_intents: list[str]


SURFACE_RULES = [
    {
        "domain": "ci_cd",
        "patterns": [".github/workflows/*", ".github/rulesets/*", "CODEOWNERS", ".verification/*"],
        "intent": "agent-cannot-disable-own-ci-gate",
        "reason": "change touches CI, repository rules, ownership, or OVK configuration",
    },
    {
        "domain": "authorization",
        "patterns": ["*/routes/*", "*/controllers/*", "*/middleware/*", "*/auth/*", "*policy*"],
        "intent": "no-admin-route-bypass",
        "reason": "change touches routes, middleware, authorization, or policy files",
    },
    {
        "domain": "infrastructure",
        "patterns": ["*.tf", "*.tf.json", "*/k8s/*", "*/kubernetes/*", "*deployment*.yml", "*iam*"],
        "intent": "no-public-sensitive-resource",
        "reason": "change touches infrastructure, deployment, IAM, or network configuration",
    },
    {
        "domain": "ci_cd",
        "patterns": [".github/workflows/*"],
        "intent": "no-secrets-in-untrusted-context",
        "reason": "change touches CI workflows that may expose secrets",
    },
    {
        "domain": "deployment",
        "patterns": ["*deployment*.yml", "*deployment*.yaml", "*/deploy/*", "*release*.yml"],
        "intent": "no-skipped-approval-state",
        "reason": "change touches deployment or release state configuration",
    },
]


def _matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch(path, pattern) for pattern in patterns)


def detect_change_surfaces(changed_files: list[str]) -> list[ChangeSurface]:
    """Detect engineering surfaces affected by a list of changed paths."""
    surfaces: list[ChangeSurface] = []
    for rule in SURFACE_RULES:
        matched = [path for path in changed_files if _matches(path, rule["patterns"])]
        if matched:
            surfaces.append(
                ChangeSurface(
                    domain=str(rule["domain"]),
                    reason=str(rule["reason"]),
                    files=matched,
                    candidate_intents=[str(rule["intent"])],
                )
            )
    return surfaces


def infer_candidate_intents(changed_files: list[str]) -> list[str]:
    """Return unique candidate intent IDs for changed paths."""
    intents: list[str] = []
    for surface in detect_change_surfaces(changed_files):
        for intent in surface.candidate_intents:
            if intent not in intents:
                intents.append(intent)
    return intents
