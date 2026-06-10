"""Unified `ovk check` orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk.core.changed_files import load_changed_files
from ovk.core.compilation_evidence import compilation_failure_evidence
from ovk.core.diff_parser import is_unified_diff
from ovk.core.kernel import KernelResult, execute_kernel
from ovk.core.models import EvidenceBundle

# Re-export for backward-compatible tests and imports.
__all__ = ["CheckResult", "compilation_failure_evidence", "load_diff_or_changed_files", "run_check"]


@dataclass(frozen=True)
class CheckResult:
    """Result of an `ovk check` run."""

    bundle: EvidenceBundle
    plan: dict[str, Any]
    jobs: list[dict[str, Any]]
    markdown: str
    elapsed_ms: float
    ranked_intents: list[dict[str, Any]]
    routing: list[dict[str, Any]]


def _kernel_to_check(result: KernelResult) -> CheckResult:
    return CheckResult(
        bundle=result.bundle,
        plan=result.plan,
        jobs=result.obligations,
        markdown=result.markdown,
        elapsed_ms=result.elapsed_ms,
        ranked_intents=result.ranked_intents,
        routing=result.routing,
    )


def run_check(
    *,
    changed_files: list[str] | None = None,
    diff_text: str | None = None,
    metadata: dict[str, Any] | None = None,
    check_metadata_path: Path | None = None,
    github_event_path: Path | None = None,
    repo: str = "unknown/repo",
    head_sha: str = "unknown",
    base_sha: str | None = None,
    cache_dir: Path | None = None,
    use_cache: bool = True,
    parallel: bool = True,
) -> CheckResult:
    """Infer, compile, route, and evaluate affected lanes for a change."""
    from ovk.core.result_cache import DEFAULT_CACHE_DIR

    result = execute_kernel(
        changed_files=changed_files,
        diff_text=diff_text,
        metadata=metadata,
        check_metadata_path=check_metadata_path,
        github_event_path=github_event_path,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        cache_dir=cache_dir if cache_dir is not None else DEFAULT_CACHE_DIR,
        use_cache=use_cache,
        parallel=parallel,
    )
    return _kernel_to_check(result)


def load_diff_or_changed_files(path: Path | None) -> tuple[list[str], str | None]:
    """Load changed file paths and optional diff text from an input file."""
    if path is None:
        return [], None
    text = path.read_text(encoding="utf-8")
    if is_unified_diff(text):
        return load_changed_files(path), text
    return load_changed_files(path), None
