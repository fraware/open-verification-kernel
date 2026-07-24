"""Tests for verified_source_sha / benchmark_source_sha resolution."""

from __future__ import annotations

from ovk.core.verified_source import resolve_benchmark_source_sha, resolve_verified_source_sha


def test_explicit_verified_sha_wins(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "github-sha")
    monkeypatch.setenv("OVK_VERIFIED_SOURCE_SHA", "env-sha")
    assert resolve_verified_source_sha(explicit="explicit-sha") == "explicit-sha"


def test_ovk_env_is_verified(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "github-sha")
    monkeypatch.setenv("OVK_VERIFIED_SOURCE_SHA", "env-sha")
    assert resolve_verified_source_sha() == "env-sha"


def test_github_sha_is_not_verified(monkeypatch) -> None:
    monkeypatch.delenv("OVK_VERIFIED_SOURCE_SHA", raising=False)
    monkeypatch.setenv("GITHUB_SHA", "github-sha-only")
    assert resolve_verified_source_sha() is None


def test_github_sha_is_benchmark_source(monkeypatch) -> None:
    monkeypatch.delenv("OVK_BENCHMARK_SOURCE_SHA", raising=False)
    monkeypatch.setenv("GITHUB_SHA", "github-sha-only")
    assert resolve_benchmark_source_sha() == "github-sha-only"


def test_explicit_benchmark_sha_wins(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "github-sha")
    assert resolve_benchmark_source_sha(explicit="bench-sha") == "bench-sha"
