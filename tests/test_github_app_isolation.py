"""Installation isolation and uninstall cleanup tests (OVK-PR7)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ovk_github_app.cleanup import handle_installation_deleted
from ovk_github_app.errors import IsolationError
from ovk_github_app.isolation import InstallationStore
from ovk_github_app.tokens import InstallationToken, InstallationTokenProvider


def test_partitions_are_installation_scoped(tmp_path: Path) -> None:
    store = InstallationStore(tmp_path)
    a = store.partition(11)
    b = store.partition(22)
    assert a.root != b.root
    assert a.root.parent == b.root.parent == store.installations_root
    store.write_json(11, "note.json", {"who": "a"})
    store.write_json(22, "note.json", {"who": "b"})
    assert store.read_json(11, "note.json") == {"who": "a"}
    assert store.read_json(22, "note.json") == {"who": "b"}


def test_path_escape_rejected(tmp_path: Path) -> None:
    store = InstallationStore(tmp_path)
    part = store.partition(7)
    escape = (part.root / ".." / "22" / "data" / "x.json").resolve()
    with pytest.raises(IsolationError, match="escapes"):
        store.assert_path_in_partition(7, escape)


def test_invalid_installation_id_rejected(tmp_path: Path) -> None:
    store = InstallationStore(tmp_path)
    with pytest.raises(IsolationError, match="invalid"):
        store.partition("../evil")
    with pytest.raises(IsolationError, match="invalid"):
        store.partition("0")


def test_installation_deleted_removes_partition(tmp_path: Path) -> None:
    store = InstallationStore(tmp_path)
    store.write_json(99, "keep.json", {"x": 1})
    assert (tmp_path / "installations" / "99").is_dir()

    tokens = InstallationTokenProvider(
        app_id=1,
        private_key_pem="unused",
        jwt_builder=lambda **_: "jwt",
        http_post=lambda *_a, **_k: (201, {"token": "ghs_test", "expires_at": 9_999_999_999}),
    )
    # Seed cache without network by injecting directly.
    assert tokens._cache is not None
    tokens._cache[99] = InstallationToken(
        installation_id=99,
        token="ghs_cached",
        expires_at=9_999_999_999,
        permissions={},
    )

    result = handle_installation_deleted(
        {"action": "deleted", "installation": {"id": 99}},
        store=store,
        token_provider=tokens,
    )
    assert result["deleted"] is True
    assert not (tmp_path / "installations" / "99").exists()
    assert 99 not in (tokens._cache or {})
    # Sibling installation untouched.
    store.write_json(100, "ok.json", {"ok": True})
    handle_installation_deleted(
        {"action": "deleted", "installation": {"id": 99}},
        store=store,
        token_provider=tokens,
    )
    assert store.read_json(100, "ok.json") == {"ok": True}
