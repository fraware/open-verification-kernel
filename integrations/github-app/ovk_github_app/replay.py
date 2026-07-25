"""Replay protection: timestamp skew + delivery-id dedupe."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol

from ovk_github_app.errors import ReplayError

DEFAULT_MAX_SKEW_SECONDS = 300
DELIVERY_HEADER = "X-GitHub-Delivery"
TIMESTAMP_HEADER = "X-OVK-Timestamp"


class DeliveryDedupeStore(Protocol):
    """Persistent or in-memory claim store for GitHub delivery IDs."""

    def try_claim(self, delivery_id: str, *, seen_at: int) -> bool:
        """Return True if this delivery_id is newly claimed; False if duplicate."""

    def has(self, delivery_id: str) -> bool:
        """Return True when delivery_id was previously claimed."""


@dataclass
class MemoryDeliveryDedupeStore:
    """Process-local delivery-id store with optional TTL eviction."""

    ttl_seconds: int = 86_400
    _seen: dict[str, int] = field(default_factory=dict)

    def try_claim(self, delivery_id: str, *, seen_at: int) -> bool:
        self._evict(now=seen_at)
        if delivery_id in self._seen:
            return False
        self._seen[delivery_id] = seen_at
        return True

    def has(self, delivery_id: str) -> bool:
        return delivery_id in self._seen

    def _evict(self, *, now: int) -> None:
        if self.ttl_seconds <= 0:
            return
        expired = [key for key, ts in self._seen.items() if now - ts > self.ttl_seconds]
        for key in expired:
            del self._seen[key]


def parse_webhook_timestamp(raw: str | int | None) -> int:
    """Parse a unix-epoch timestamp from header or payload field."""
    if raw is None or raw == "":
        raise ReplayError("missing webhook timestamp")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ReplayError("invalid webhook timestamp") from exc
    return value


def assert_timestamp_fresh(
    timestamp: int,
    *,
    now: int | None = None,
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
) -> None:
    """Reject timestamps outside the allowed clock skew window."""
    if max_skew_seconds < 0:
        raise ReplayError("max_skew_seconds must be non-negative")
    current = int(time.time()) if now is None else int(now)
    if abs(current - int(timestamp)) > int(max_skew_seconds):
        raise ReplayError(
            f"timestamp skew exceeded: ts={timestamp} now={current} max_skew={max_skew_seconds}"
        )


def assert_new_delivery(
    delivery_id: str | None,
    *,
    store: DeliveryDedupeStore,
    seen_at: int | None = None,
) -> None:
    """Claim a GitHub delivery id; reject duplicates and missing ids."""
    if delivery_id is None or not str(delivery_id).strip():
        raise ReplayError("missing X-GitHub-Delivery header")
    claimed_at = int(time.time()) if seen_at is None else int(seen_at)
    if not store.try_claim(str(delivery_id).strip(), seen_at=claimed_at):
        raise ReplayError(f"duplicate delivery id: {delivery_id}")


def protect_against_replay(
    *,
    delivery_id: str | None,
    timestamp: int | str | None,
    store: DeliveryDedupeStore,
    now: int | None = None,
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
) -> int:
    """Apply timestamp skew then delivery-id dedupe; return normalized timestamp."""
    current = int(time.time()) if now is None else int(now)
    ts = parse_webhook_timestamp(timestamp)
    assert_timestamp_fresh(ts, now=current, max_skew_seconds=max_skew_seconds)
    assert_new_delivery(delivery_id, store=store, seen_at=current)
    return ts
