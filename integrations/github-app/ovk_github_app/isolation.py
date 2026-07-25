"""Per-installation credentials and data partitions."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ovk_github_app.errors import IsolationError

_SAFE_INSTALLATION = re.compile(r"^[1-9][0-9]*$")


def _require_installation_id(installation_id: int | str) -> str:
    text = str(installation_id).strip()
    if not _SAFE_INSTALLATION.fullmatch(text):
        raise IsolationError(f"invalid installation id: {installation_id!r}")
    return text


@dataclass(frozen=True)
class InstallationPartition:
    """Filesystem layout for one GitHub App installation."""

    installation_id: str
    root: Path

    @property
    def credentials_dir(self) -> Path:
        return self.root / "credentials"

    @property
    def cache_dir(self) -> Path:
        return self.root / "cache"

    @property
    def data_dir(self) -> Path:
        return self.root / "data"

    def ensure(self) -> None:
        for path in (self.root, self.credentials_dir, self.cache_dir, self.data_dir):
            path.mkdir(parents=True, exist_ok=True)


class InstallationStore:
    """Isolate credentials and cached data by installation id.

    Paths are always ``{root}/installations/{installation_id}/...``. Callers must
    never construct sibling paths from untrusted repo names.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.installations_root = self.root / "installations"
        self.installations_root.mkdir(parents=True, exist_ok=True)

    def partition(self, installation_id: int | str) -> InstallationPartition:
        iid = _require_installation_id(installation_id)
        part = InstallationPartition(
            installation_id=iid,
            root=self.installations_root / iid,
        )
        part.ensure()
        return part

    def assert_path_in_partition(self, installation_id: int | str, path: Path) -> Path:
        """Resolve ``path`` and reject escape outside the installation partition."""
        part = self.partition(installation_id)
        resolved = Path(path).resolve()
        root = part.root.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise IsolationError(
                f"path {resolved} escapes installation {part.installation_id} partition"
            ) from exc
        return resolved

    def write_json(self, installation_id: int | str, relative: str, payload: dict[str, Any]) -> Path:
        part = self.partition(installation_id)
        target = (part.data_dir / relative).resolve()
        self.assert_path_in_partition(installation_id, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return target

    def read_json(self, installation_id: int | str, relative: str) -> dict[str, Any] | None:
        part = self.partition(installation_id)
        target = (part.data_dir / relative).resolve()
        self.assert_path_in_partition(installation_id, target)
        if not target.is_file():
            return None
        return json.loads(target.read_text(encoding="utf-8"))

    def delete_installation(self, installation_id: int | str) -> bool:
        """Remove all installation-scoped data. Returns True if anything was deleted."""
        iid = _require_installation_id(installation_id)
        target = (self.installations_root / iid).resolve()
        root = self.installations_root.resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise IsolationError(f"refusing to delete outside installations root: {target}") from exc
        if target == root:
            raise IsolationError("refusing to delete installations root")
        if not target.exists():
            return False
        shutil.rmtree(target)
        return True

    def list_installations(self) -> list[str]:
        if not self.installations_root.is_dir():
            return []
        return sorted(
            path.name
            for path in self.installations_root.iterdir()
            if path.is_dir() and _SAFE_INSTALLATION.fullmatch(path.name)
        )
