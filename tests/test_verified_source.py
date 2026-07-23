"""Tests for verified_source_sha resolution."""

from __future__ import annotations

from ovk.core.verified_source import resolve_verified_source_sha


def test_explicit_sha_wins(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "github-sha")
    monkeypatch.setenv("OVK_VERIFIED_SOURCE_SHA", "env-sha")
    assert resolve_verified_source_sha(explicit="explicit-sha") == "explicit-sha"


def test_ovk_env_beats_github(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "github-sha")
    monkeypatch.setenv("OVK_VERIFIED_SOURCE_SHA", "env-sha")
    assert resolve_verified_source_sha() == "env-sha"


def test_github_sha_used_when_no_override(monkeypatch) -> None:
    monkeypatch.delenv("OVK_VERIFIED_SOURCE_SHA", raising=False)
    monkeypatch.setenv("GITHUB_SHA", "github-sha-only")
    assert resolve_verified_source_sha() == "github-sha-only"
