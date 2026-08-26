"""Tests for fail-closed PyPI publication/recovery state checks."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.check_pypi_distribution_state import (
    compare_pypi_payload,
    local_distribution_files,
)


def _local_dist(tmp_path: Path) -> dict[str, str]:
    wheel = tmp_path / "open_verification_kernel-1.3.0rc1-py3-none-any.whl"
    sdist = tmp_path / "open_verification_kernel-1.3.0rc1.tar.gz"
    wheel.write_bytes(b"wheel-bytes")
    sdist.write_bytes(b"sdist-bytes")
    return {
        wheel.name: hashlib.sha256(wheel.read_bytes()).hexdigest(),
        sdist.name: hashlib.sha256(sdist.read_bytes()).hexdigest(),
    }


def _payload(files: dict[str, str]) -> dict:
    return {
        "info": {"version": "1.3.0rc1"},
        "urls": [
            {"filename": name, "digests": {"sha256": digest}}
            for name, digest in sorted(files.items())
        ],
    }


def test_local_distribution_files_requires_exact_wheel_and_sdist(tmp_path: Path) -> None:
    expected = _local_dist(tmp_path)
    assert local_distribution_files(tmp_path) == expected
    (tmp_path / "extra.whl").write_bytes(b"extra")
    with pytest.raises(ValueError, match="exactly one wheel"):
        local_distribution_files(tmp_path)


def test_exact_existing_pypi_release_is_safe_recovery(tmp_path: Path) -> None:
    local = _local_dist(tmp_path)
    result = compare_pypi_payload(_payload(local), local_files=local)
    assert result["state"] == "exact_match"
    assert result["failures"] == []
    assert result["remote_files"] == local


def test_existing_pypi_digest_substitution_fails_closed(tmp_path: Path) -> None:
    local = _local_dist(tmp_path)
    remote = dict(local)
    first = next(iter(remote))
    remote[first] = "0" * 64
    result = compare_pypi_payload(_payload(remote), local_files=local)
    assert result["state"] == "conflict"
    assert f"PyPI digest mismatch: {first}" in result["failures"]


def test_existing_pypi_missing_or_extra_file_fails_closed(tmp_path: Path) -> None:
    local = _local_dist(tmp_path)
    one_name = next(iter(local))
    missing = {one_name: local[one_name]}
    result = compare_pypi_payload(_payload(missing), local_files=local)
    assert result["state"] == "conflict"
    assert any(item.startswith("missing PyPI file:") for item in result["failures"])

    extra = {**local, "unexpected.whl": "f" * 64}
    result = compare_pypi_payload(_payload(extra), local_files=local)
    assert result["state"] == "conflict"
    assert "unexpected PyPI file: unexpected.whl" in result["failures"]


def test_malformed_remote_digest_fails_closed(tmp_path: Path) -> None:
    local = _local_dist(tmp_path)
    payload = _payload(local)
    payload["urls"][0]["digests"]["sha256"] = "not-a-digest"
    result = compare_pypi_payload(payload, local_files=local)
    assert result["state"] == "conflict"
    assert any("malformed SHA-256" in item for item in result["failures"])
