"""Replay protection tests: timestamp skew + delivery-id dedupe (OVK-PR7)."""

from __future__ import annotations

import pytest

from ovk_github_app.errors import ReplayError
from ovk_github_app.replay import (
    MemoryDeliveryDedupeStore,
    assert_new_delivery,
    assert_timestamp_fresh,
    protect_against_replay,
)


def test_timestamp_within_skew_accepted() -> None:
    now = 1_700_000_000
    assert_timestamp_fresh(now - 10, now=now, max_skew_seconds=300)
    assert_timestamp_fresh(now + 10, now=now, max_skew_seconds=300)


def test_timestamp_outside_skew_rejected() -> None:
    now = 1_700_000_000
    with pytest.raises(ReplayError, match="skew"):
        assert_timestamp_fresh(now - 301, now=now, max_skew_seconds=300)
    with pytest.raises(ReplayError, match="skew"):
        assert_timestamp_fresh(now + 500, now=now, max_skew_seconds=300)


def test_delivery_id_dedupe_rejects_replay() -> None:
    store = MemoryDeliveryDedupeStore()
    assert_new_delivery("delivery-1", store=store, seen_at=100)
    with pytest.raises(ReplayError, match="duplicate"):
        assert_new_delivery("delivery-1", store=store, seen_at=101)


def test_delivery_id_missing_rejected() -> None:
    store = MemoryDeliveryDedupeStore()
    with pytest.raises(ReplayError, match="missing"):
        assert_new_delivery(None, store=store, seen_at=1)
    with pytest.raises(ReplayError, match="missing"):
        assert_new_delivery("  ", store=store, seen_at=1)


def test_protect_against_replay_combines_guards() -> None:
    store = MemoryDeliveryDedupeStore()
    now = 1_700_000_100
    protect_against_replay(
        delivery_id="abc-def",
        timestamp=now - 5,
        store=store,
        now=now,
        max_skew_seconds=300,
    )
    with pytest.raises(ReplayError, match="duplicate"):
        protect_against_replay(
            delivery_id="abc-def",
            timestamp=now - 5,
            store=store,
            now=now,
            max_skew_seconds=300,
        )


def test_protect_against_replay_stale_timestamp_before_dedupe() -> None:
    store = MemoryDeliveryDedupeStore()
    now = 1_700_000_100
    with pytest.raises(ReplayError, match="skew"):
        protect_against_replay(
            delivery_id="never-claimed",
            timestamp=now - 10_000,
            store=store,
            now=now,
            max_skew_seconds=300,
        )
    assert not store.has("never-claimed")


def test_dedupe_ttl_eviction_allows_reclaim() -> None:
    store = MemoryDeliveryDedupeStore(ttl_seconds=60)
    store.try_claim("old", seen_at=100)
    assert store.has("old")
    # Advance past TTL; claim triggers eviction.
    assert store.try_claim("new", seen_at=200)
    assert not store.has("old")
