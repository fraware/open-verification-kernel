"""MCP server scaffold for Open Verification Kernel.

This file documents the intended agent-facing tool surface. The first implementation
should wire these handlers to the core kernel functions once the MCP SDK choice is finalized.
"""

from __future__ import annotations

from typing import Any


TOOLS = [
    "ovk.extract_intents",
    "ovk.rank_intents",
    "ovk.list_capabilities",
    "ovk.select_backends",
    "ovk.compile_obligation",
    "ovk.run_verification",
    "ovk.explain_result",
    "ovk.generate_regression_artifact",
    "ovk.create_evidence_bundle",
    "ovk.get_merge_recommendation",
]


def extract_intents(diff: str, repo_context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Placeholder for agent-facing intent extraction."""
    return {"intents": [], "repo_context": repo_context or {}, "diff_length": len(diff)}


def list_capabilities() -> dict[str, Any]:
    """Placeholder for capability discovery."""
    return {"capabilities": []}


def get_merge_recommendation(evidence_bundle: dict[str, Any]) -> dict[str, Any]:
    """Placeholder for MCP-facing merge recommendation."""
    return {
        "merge_recommendation": evidence_bundle.get("decision", {}).get(
            "merge_recommendation", "require_human_review"
        )
    }
