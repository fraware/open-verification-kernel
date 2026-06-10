"""Extract Kani harness inputs from Rust source diffs."""

from __future__ import annotations

import re

from ovk.core.diff_parser import extract_post_images, is_unified_diff


def _findings_from_rust(content: str) -> list[dict]:
    findings: list[dict] = []
    if "unsafe {" in content or "unsafe{" in content:
        findings.append({"kind": "memory_safety", "summary": "unsafe block introduced in diff"})
    if re.search(r"\.unwrap\(\)", content):
        findings.append({"kind": "memory_safety", "summary": "unchecked unwrap introduced in diff"})
    return findings


def kani_inputs_from_diff(diff_text: str) -> list[dict]:
    """Convert Rust file changes in a unified diff to Kani backend inputs."""
    if not is_unified_diff(diff_text):
        return []

    inputs: list[dict] = []
    for path, content in extract_post_images(diff_text).items():
        if not path.lower().endswith(".rs") or not content.strip():
            continue
        findings = _findings_from_rust(content)
        inputs.append(
            {
                "intent_id": "kani-harness-check",
                "source_path": path,
                "findings": findings,
                "unsafe_operations": [item["summary"] for item in findings],
            }
        )
    return inputs
