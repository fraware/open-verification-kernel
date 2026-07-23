"""Load base/head source materials for authorization compilers.

Before/after reconstruction uses both revisions. Compilers must not invent
``before`` protections from head-only post-images.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AuthMaterials:
    """Paired base/head source files keyed by relative path."""

    base_files: dict[str, str] = field(default_factory=dict)
    head_files: dict[str, str] = field(default_factory=dict)
    base_revision: str | None = None
    head_revision: str | None = None
    repo: str | None = None

    @property
    def paths(self) -> list[str]:
        return sorted(set(self.base_files) | set(self.head_files))

    def base_text(self, path: str) -> str:
        return self.base_files.get(path, "")

    def head_text(self, path: str) -> str:
        return self.head_files.get(path, "")

    def has_base(self) -> bool:
        return any(text.strip() for text in self.base_files.values())

    def has_head(self) -> bool:
        return any(text.strip() for text in self.head_files.values())


def load_materials_from_dirs(
    *,
    base_dir: Path | None,
    head_dir: Path | None,
    extensions: tuple[str, ...] = (".py", ".js", ".ts", ".mjs", ".cjs"),
    repo: str | None = None,
    base_revision: str | None = None,
    head_revision: str | None = None,
) -> AuthMaterials:
    """Load text materials from base and head directories."""

    def _load(root: Path | None) -> dict[str, str]:
        if root is None or not root.exists():
            return {}
        files: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in extensions:
                continue
            rel = path.relative_to(root).as_posix()
            files[rel] = path.read_text(encoding="utf-8")
        return files

    return AuthMaterials(
        base_files=_load(base_dir),
        head_files=_load(head_dir),
        base_revision=base_revision,
        head_revision=head_revision,
        repo=repo,
    )


def materials_from_pair(
    *,
    path: str,
    base_source: str | None,
    head_source: str | None,
    repo: str | None = None,
    base_revision: str | None = None,
    head_revision: str | None = None,
) -> AuthMaterials:
    """Build materials for a single logical file path."""
    base_files = {path: base_source} if base_source is not None else {}
    head_files = {path: head_source} if head_source is not None else {}
    return AuthMaterials(
        base_files=base_files,
        head_files=head_files,
        repo=repo,
        base_revision=base_revision,
        head_revision=head_revision,
    )
