"""Extract CBMC harness inputs from C/C++ source diffs."""

from __future__ import annotations

import re

from ovk.adapters.cbmc.harness_compiler import CBMC_TEMPLATE_IDS
from ovk.core.diff_parser import extract_post_images, is_unified_diff


def _intent_for_path(path: str, content: str) -> str:
    lowered = path.replace("\\", "/").lower()
    if any(token in lowered for token in ("quota", "rate", "limit")):
        return "cbmc-no-integer-overflow-quota"
    if any(token in lowered for token in ("auth", "cache", "session")):
        return "cbmc-no-use-after-free-auth-cache"
    if "memcpy" in content or "strcpy" in content or "strncpy" in content:
        return "cbmc-no-unchecked-buffer-copy"
    return "cbmc-buffer-bounds"


def _findings_from_c(content: str, *, intent_id: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if intent_id == "cbmc-no-integer-overflow-quota" and re.search(r"\+\s*=|\+\+|quota|limit", content):
        findings.append({"kind": "integer_overflow", "summary": "quota or counter arithmetic changed in diff"})
    if intent_id == "cbmc-no-unchecked-buffer-copy" and re.search(r"\b(memcpy|strcpy|strncpy|memmove)\s*\(", content):
        findings.append({"kind": "unchecked_copy", "summary": "memory copy operation introduced or modified in diff"})
    if intent_id == "cbmc-no-use-after-free-auth-cache" and re.search(r"\bfree\s*\(", content):
        findings.append({"kind": "use_after_free", "summary": "free() call introduced or modified in diff"})
    if intent_id == "cbmc-buffer-bounds" and re.search(r"\[[^\]]+\]", content):
        findings.append({"kind": "buffer_access", "summary": "indexed buffer access introduced or modified in diff"})
    return findings


def _violation_hints(content: str, *, intent_id: str) -> dict[str, object]:
    """Infer harness/oracle failure hints from risky patterns in post-image C code."""
    if intent_id == "cbmc-no-use-after-free-auth-cache":
        if re.search(r"free\s*\([^)]+\)\s*;", content) and re.search(r"\*\s*[\w>-]+\s*=", content):
            return {
                "expect_violation": True,
                "failed_assertions": ["use-after-free pattern detected in changed C code"],
            }
    if intent_id == "cbmc-no-integer-overflow-quota":
        if re.search(r"\w+\s*\+\s*\w+", content) and not re.search(
            r"\b(quota|limit|QUOTA|LIMIT)\b",
            content,
            flags=re.IGNORECASE,
        ):
            return {
                "expect_violation": True,
                "failed_assertions": ["unbounded quota arithmetic detected in changed C code"],
            }
    if intent_id == "cbmc-no-unchecked-buffer-copy":
        if re.search(r"\b(memcpy|strcpy|strncpy|memmove)\s*\(", content) and not re.search(
            r"\b(length|size|count)\s*<=|__CPROVER_assume",
            content,
        ):
            return {
                "expect_violation": True,
                "failed_assertions": ["unchecked memory copy without explicit bound in changed C code"],
            }
    return {}


def cbmc_inputs_from_diff(diff_text: str) -> list[dict]:
    """Convert C/C++ file changes in a unified diff to CBMC backend inputs."""
    if not is_unified_diff(diff_text):
        return []

    inputs: list[dict] = []
    for path, content in extract_post_images(diff_text).items():
        if not path.lower().endswith((".c", ".h", ".cpp", ".cc")) or not content.strip():
            continue
        intent_id = _intent_for_path(path, content)
        if intent_id not in CBMC_TEMPLATE_IDS:
            continue
        findings = _findings_from_c(content, intent_id=intent_id)
        payload: dict[str, object] = {
            "intent_id": intent_id,
            "source_path": path,
            "findings": findings,
            "changed_symbols": [item["summary"] for item in findings],
            "source_excerpt": content[:2000],
        }
        payload.update(_violation_hints(content, intent_id=intent_id))
        inputs.append(payload)
    return inputs
